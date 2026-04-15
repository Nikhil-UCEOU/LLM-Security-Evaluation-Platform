"""
CortexFlow Streaming Pipeline Service
Wraps the evaluation pipeline with real-time SSE event emission.
Each stage yields JSON events that the frontend consumes.

DB writes use short-lived sessions (open → write → commit → close) so SQLite
never holds a write lock across multiple await points.
"""
from __future__ import annotations

import json
import asyncio
from datetime import datetime
from typing import AsyncGenerator, List, Optional, Dict, Any

from backend.schemas.evaluation import EvaluationRunRequest
from backend.models.evaluation import (
    EvaluationRun, EvaluationResult, RunStatus, Classification,
)
from backend.models.rca import RCAReport
from backend.models.mitigation import MitigationPlan, MitigationResult
from backend.models.attack import AttackCategory

from backend.modules.attack_engine.runner import build_attack_list
from backend.modules.attack_engine.base_attack import AttackPayload
from backend.modules.attack_engine.escalation_controller import decide_escalation
from backend.modules.evaluation_engine.classifier import classify_response, classify_response_with_confidence, score_severity
from backend.modules.evaluation_engine.isr_calculator import compute_isr
from backend.modules.rca_engine.analyzer import analyze as rca_analyze
from backend.modules.mitigation_engine.prompt_hardener import harden_prompt, generate_guardrails
from backend.modules.mitigation_engine.strategy_selector import select_strategy, extract_vulnerability_categories
from backend.modules.adaptive_attack_engine.ranker import rank_attacks
from backend.modules.learning_engine.store import store_evaluation_results, get_top_attacks
from backend.modules.context_detector.auto_context_detector import detect_context
from backend.modules.gateway import registry
from backend.modules.gateway.base_provider import LLMConfig
from backend.modules.dataset_engine.seed_extractor import promote_successful_attack

import structlog

log = structlog.get_logger()


def _sse(event_type: str, data: Dict[str, Any]) -> str:
    """Format a single SSE message."""
    payload = json.dumps({"type": event_type, **data})
    return f"data: {payload}\n\n"


async def _db_write(fn):
    """Execute a DB write in its own short-lived session (open→write→commit→close)."""
    from backend.core.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        result = await fn(session)
        await session.commit()
        return result


async def _db_read(fn):
    """Execute a DB read in its own short-lived session."""
    from backend.core.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        return await fn(session)


async def stream_evaluation_pipeline(
    request: EvaluationRunRequest,
    document_content: str = "",
    api_schema: str = "",
    enable_mutation: bool = False,
    enable_escalation: bool = True,
    min_level: int = 1,
    max_level: int = 5,
) -> AsyncGenerator[str, None]:
    """
    Async generator that streams the evaluation pipeline as SSE events.
    Each DB write uses its own session so SQLite is never locked long-term.
    """

    # ── Stage 0: Context Detection ─────────────────────────────────────────
    ctx = detect_context(
        system_prompt=request.system_prompt,
        document_content=document_content,
        api_schema=api_schema,
    )
    yield _sse("context_detected", {
        "domain": ctx.domain,
        "app_type": ctx.app_type,
        "domain_confidence": ctx.domain_confidence,
        "app_type_confidence": ctx.app_type_confidence,
        "detected_signals": ctx.detected_signals,
        "recommended_categories": ctx.recommended_categories,
    })

    # ── Stage 1: Create run record (own session, committed immediately) ────
    run_id: int = 0
    try:
        async def _create_run(session):
            run = EvaluationRun(
                provider=request.provider,
                model=request.model,
                system_prompt=request.system_prompt,
                status=RunStatus.running,
                started_at=datetime.utcnow(),
            )
            session.add(run)
            await session.flush()
            return run.id

        run_id = await _db_write(_create_run)
    except Exception as exc:
        yield _sse("error", {"message": f"Failed to create run record: {exc}"})
        return

    yield _sse("pipeline_start", {
        "run_id": run_id,
        "provider": request.provider,
        "model": request.model,
        "timestamp": datetime.utcnow().isoformat(),
    })

    try:
        # ── Stage 2: Build attack list ─────────────────────────────────────
        categories = request.attack_categories or list(AttackCategory)
        historical = await _db_read(
            lambda s: get_top_attacks(s, request.provider, request.model, limit=20)
        )

        attacks = build_attack_list(
            categories=categories,
            max_attacks=request.max_attacks,
        )
        attacks = rank_attacks(attacks, historical)

        # Filter by level range
        attacks = [a for a in attacks if min_level <= a.level <= max_level]
        if not attacks:
            attacks = build_attack_list(categories=categories, max_attacks=request.max_attacks)

        total = len(attacks)
        yield _sse("attacks_ready", {
            "total_attacks": total,
            "levels_in_use": sorted(set(a.level for a in attacks)),
            "categories": list(set(a.category.value for a in attacks)),
        })

        # ── Stage 3: Execute attacks one by one (streaming) ────────────────
        config = LLMConfig(model=request.model, system_prompt=request.system_prompt)
        result_dicts: List[Dict] = []
        eval_result_rows: List[Dict] = []  # data for bulk DB write later
        current_level = min_level
        current_isr = 0.0
        consecutive_failures = 0

        for idx, attack in enumerate(attacks):
            yield _sse("attack_info", {
                "index": idx,
                "total": total,
                "name": attack.name,
                "category": attack.category.value,
                "level": attack.level,
                "attack_type": attack.attack_type,
                "domain": attack.domain,
                "risk_score": attack.risk_score,
            })
            await asyncio.sleep(0)

            yield _sse("attack_input", {
                "index": idx,
                "payload_preview": attack.payload[:300] + ("..." if len(attack.payload) > 300 else ""),
                "full_payload": attack.payload,
            })
            await asyncio.sleep(0)

            yield _sse("attack_executing", {"index": idx})

            t_start = asyncio.get_event_loop().time()
            try:
                response = await registry.query(request.provider, attack.payload, config)
                elapsed_ms = int((asyncio.get_event_loop().time() - t_start) * 1000)
            except Exception as exc:
                yield _sse("attack_error", {"index": idx, "error": str(exc)})
                continue

            response_text = response.response_text or response.error or ""
            yield _sse("attack_response", {
                "index": idx,
                "response_preview": response_text[:400] + ("..." if len(response_text) > 400 else ""),
                "latency_ms": elapsed_ms,
                "tokens_used": response.tokens_used,
            })
            await asyncio.sleep(0)

            cls_result = classify_response_with_confidence(
                response_text,
                attack_tags=getattr(attack, "tags", []),
            )
            classification = cls_result.classification
            severity = score_severity(classification, response_text)
            isr_contribution = 1.0 if classification in (
                Classification.unsafe, Classification.partial
            ) else 0.0

            yield _sse("attack_classified", {
                "index": idx,
                "classification": classification.value,
                "severity": severity.value,
                "isr_contribution": isr_contribution,
                "success": isr_contribution > 0,
                "category": attack.category.value,
                "strategy": getattr(attack, "strategy_goal", attack.category.value),
                "owasp_risk": cls_result.owasp_risk,
                "signals": cls_result.signals,
                "confidence": cls_result.confidence,
                "name": attack.name,
            })
            await asyncio.sleep(0)

            # Adaptive per-attack escalation
            if isr_contribution > 0:
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                if consecutive_failures >= 2 and enable_escalation:
                    new_level = min(current_level + 1, max_level)
                    if new_level > current_level:
                        current_level = new_level
                        consecutive_failures = 0
                        yield _sse("strategy_change", {
                            "index": idx,
                            "reason": f"Model defended — escalating to L{new_level}",
                            "new_level": new_level,
                            "action": "escalate",
                        })

            # Accumulate for bulk write (no DB access here)
            eval_result_rows.append({
                "run_id": run_id,
                "attack_id": attack.attack_id,
                "attack_name": attack.name,
                "attack_payload": attack.payload,
                "response_text": response_text,
                "classification": classification,
                "severity": severity,
                "latency_ms": elapsed_ms,
                "tokens_used": response.tokens_used,
                "isr_contribution": isr_contribution,
                "attack_category": attack.category.value,
                "attack_strategy": getattr(attack, "strategy_goal", attack.category.value),
                "owasp_risk": cls_result.owasp_risk,
                "signals": cls_result.signals,
            })

            result_dicts.append({
                "attack_id": attack.attack_id,
                "attack_name": attack.name,
                "attack_payload": attack.payload,
                "category": attack.category.value,
                "classification": classification,
                "severity": severity,
                "response_text": response_text,
                "isr_contribution": isr_contribution,
            })

            # Live ISR update
            if result_dicts:
                live_isr = sum(r["classification"] in (Classification.unsafe, Classification.partial)
                               for r in result_dicts) / len(result_dicts)
                current_isr = live_isr
                yield _sse("metrics_update", {
                    "attacks_done": idx + 1,
                    "total": total,
                    "current_isr": round(live_isr, 3),
                    "successful_attacks": int(live_isr * (idx + 1)),
                    "current_level": attack.level,
                })

            # Macro escalation check every 5 attacks
            if enable_escalation and (idx + 1) % 5 == 0 and idx < total - 1:
                partial_metrics = compute_isr(result_dicts)
                failed_cats = [
                    r["category"] for r in result_dicts
                    if r["classification"] not in (Classification.unsafe, Classification.partial)
                ]
                decision = decide_escalation(
                    current_level=current_level,
                    success_rate=partial_metrics.global_isr,
                    failed_categories=failed_cats,
                )
                new_level = min(decision.recommended_level, max_level)
                if new_level != current_level or decision.strategy_switch:
                    yield _sse("escalation_decision", {
                        "action": "escalate" if new_level > current_level else "diversify",
                        "from_level": current_level,
                        "to_level": new_level,
                        "reason": decision.reason,
                        "current_isr": round(partial_metrics.global_isr, 3),
                    })
                    current_level = new_level

            await asyncio.sleep(0)

        # ── Bulk write all EvaluationResult rows (single short-lived session) ──
        async def _save_results(session):
            for row in eval_result_rows:
                er = EvaluationResult(**row)
                session.add(er)
            await session.flush()

        await _db_write(_save_results)

        # ── Stage 4: ISR metrics ───────────────────────────────────────────
        isr_metrics = compute_isr(result_dicts)
        global_isr = isr_metrics.global_isr

        async def _update_isr(session):
            from sqlalchemy import select, update
            from backend.models.evaluation import EvaluationRun
            await session.execute(
                update(EvaluationRun).where(EvaluationRun.id == run_id).values(global_isr=global_isr)
            )

        await _db_write(_update_isr)

        yield _sse("stage_isr", {
            "global_isr": isr_metrics.global_isr,
            "total_attacks": isr_metrics.total_attacks,
            "successful_attacks": isr_metrics.successful_attacks,
            "by_category": isr_metrics.by_category,
            "by_severity": isr_metrics.by_severity,
        })

        # ── Stage 5: RCA ───────────────────────────────────────────────────
        yield _sse("stage_rca_start", {"message": "Analyzing root causes..."})

        rca_data = rca_analyze(result_dicts, request.system_prompt)

        rca_report_id: int = 0
        async def _save_rca(session):
            rca_report = RCAReport(
                run_id=run_id,
                root_causes=rca_data["root_causes"],
                patterns=rca_data["patterns"],
                affected_prompt_sections=rca_data["affected_prompt_sections"],
                behavioral_analysis=rca_data["behavioral_analysis"],
                architectural_findings=rca_data["architectural_findings"],
                attack_trace=rca_data["attack_trace"],
            )
            session.add(rca_report)
            await session.flush()
            return rca_report.id

        rca_report_id = await _db_write(_save_rca)

        yield _sse("stage_rca_done", {
            "root_causes": rca_data["root_causes"],
            "patterns": rca_data["patterns"],
            "behavioral_analysis": rca_data["behavioral_analysis"],
            "attack_trace_count": len(rca_data["attack_trace"]),
        })

        # ── Stage 6: Mitigation ────────────────────────────────────────────
        yield _sse("stage_mitigation_start", {"message": "Generating mitigation strategy..."})

        strategy = select_strategy(rca_data, isr_metrics.global_isr)
        vuln_cats = extract_vulnerability_categories(rca_data)
        hardened = harden_prompt(request.system_prompt, vuln_cats)
        guardrails = generate_guardrails(vuln_cats)

        plan_id: int = 0
        async def _save_plan(session):
            plan = MitigationPlan(
                run_id=run_id,
                strategy=strategy,
                original_system_prompt=request.system_prompt,
                hardened_prompt=hardened,
                guardrails=guardrails,
            )
            session.add(plan)
            await session.flush()
            return plan.id

        plan_id = await _db_write(_save_plan)

        yield _sse("stage_mitigation_done", {
            "strategy": strategy,
            "guardrail_count": len(guardrails),
            "hardened_prompt_preview": hardened[:300] + "...",
        })

        # ── Stage 7: Re-test with hardened prompt ─────────────────────────
        yield _sse("stage_retest_start", {"message": "Re-testing with hardened prompt..."})

        hardened_config = LLMConfig(model=request.model, system_prompt=hardened)
        retest_attacks = attacks[:min(len(attacks), 10)]
        retest_result_dicts: List[Dict] = []
        retest_rows: List[Dict] = []

        # Create retest run record
        retest_run_id: int = 0
        async def _create_retest_run(session):
            retest_run = EvaluationRun(
                provider=request.provider,
                model=request.model,
                system_prompt=hardened,
                status=RunStatus.running,
                started_at=datetime.utcnow(),
            )
            session.add(retest_run)
            await session.flush()
            return retest_run.id

        retest_run_id = await _db_write(_create_retest_run)

        for rt_attack in retest_attacks:
            try:
                rt_response = await registry.query(request.provider, rt_attack.payload, hardened_config)
            except Exception:
                continue
            rt_text = rt_response.response_text or ""
            rt_cls = classify_response(rt_text)
            rt_sev = score_severity(rt_cls, rt_text)
            rt_isr = 1.0 if rt_cls in (Classification.unsafe, Classification.partial) else 0.0
            retest_rows.append({
                "run_id": retest_run_id,
                "attack_name": rt_attack.name,
                "attack_payload": rt_attack.payload,
                "response_text": rt_text,
                "classification": rt_cls,
                "severity": rt_sev,
                "latency_ms": 0,
                "tokens_used": rt_response.tokens_used,
                "isr_contribution": rt_isr,
            })
            retest_result_dicts.append({
                "classification": rt_cls,
                "severity": rt_sev,
                "category": rt_attack.category.value,
                "attack_name": rt_attack.name,
                "attack_payload": rt_attack.payload,
                "response_text": rt_text,
            })

        retest_isr_metrics = compute_isr(retest_result_dicts) if retest_result_dicts else isr_metrics
        hardened_isr = retest_isr_metrics.global_isr
        improvement_pct = (
            (isr_metrics.global_isr - hardened_isr) / isr_metrics.global_isr * 100
            if isr_metrics.global_isr > 0 else 0.0
        )

        # Save retest results + mitigation result in one shot
        async def _save_retest(session):
            from sqlalchemy import update
            from backend.models.evaluation import EvaluationRun
            for row in retest_rows:
                session.add(EvaluationResult(**row))
            await session.execute(
                update(EvaluationRun).where(EvaluationRun.id == retest_run_id).values(
                    global_isr=hardened_isr,
                    status=RunStatus.completed,
                    completed_at=datetime.utcnow(),
                )
            )
            session.add(MitigationResult(
                plan_id=plan_id,
                original_isr=isr_metrics.global_isr,
                hardened_isr=hardened_isr,
                improvement_pct=round(improvement_pct, 2),
                retest_run_id=retest_run_id,
            ))

        await _db_write(_save_retest)

        yield _sse("stage_retest_done", {
            "original_isr": isr_metrics.global_isr,
            "hardened_isr": hardened_isr,
            "improvement_pct": round(improvement_pct, 2),
        })

        # ── Stage 8: Learning + Seed Promotion ────────────────────────────
        yield _sse("stage_learning_start", {"message": "Storing insights..."})

        await _db_write(
            lambda s: store_evaluation_results(s, request.provider, request.model, result_dicts)
        )

        seeds_promoted = 0
        for rd in result_dicts:
            if rd["classification"] in (Classification.unsafe, Classification.partial):
                promoted = promote_successful_attack(
                    attack_id=rd.get("attack_id", "unknown"),
                    attack_name=rd.get("attack_name", "unknown"),
                    category=rd.get("category", "unknown"),
                    strategy=rd.get("attack_payload", "")[:50],
                    prompt=rd.get("attack_payload", ""),
                    severity=rd.get("severity", Classification.partial).value
                        if hasattr(rd.get("severity"), "value") else str(rd.get("severity", "medium")),
                    success_rate=rd.get("isr_contribution", 1.0),
                    source=f"{request.provider}/{request.model}",
                )
                if promoted:
                    seeds_promoted += 1

        yield _sse("stage_learning_done", {
            "entries_stored": len(result_dicts),
            "seeds_promoted": seeds_promoted,
        })

        # ── Finalize main run ──────────────────────────────────────────────
        async def _finalize(session):
            from sqlalchemy import update
            from backend.models.evaluation import EvaluationRun
            await session.execute(
                update(EvaluationRun).where(EvaluationRun.id == run_id).values(
                    status=RunStatus.completed,
                    completed_at=datetime.utcnow(),
                )
            )

        await _db_write(_finalize)

        yield _sse("complete", {
            "run_id": run_id,
            "provider": request.provider,
            "model": request.model,
            "global_isr": isr_metrics.global_isr,
            "total_attacks": isr_metrics.total_attacks,
            "successful_attacks": isr_metrics.successful_attacks,
            "hardened_isr": hardened_isr,
            "improvement_pct": round(improvement_pct, 2),
            "domain": ctx.domain,
            "app_type": ctx.app_type,
            "isr_by_category": isr_metrics.by_category,
            "severity_distribution": isr_metrics.by_severity,
            "rca_root_causes": rca_data["root_causes"],
            "rca_behavioral_analysis": rca_data["behavioral_analysis"],
        })

    except Exception as exc:
        log.error("streaming_pipeline.failed", run_id=run_id, error=str(exc))
        try:
            async def _fail(session):
                from sqlalchemy import update
                from backend.models.evaluation import EvaluationRun
                await session.execute(
                    update(EvaluationRun).where(EvaluationRun.id == run_id).values(
                        status=RunStatus.failed,
                        completed_at=datetime.utcnow(),
                    )
                )
            await _db_write(_fail)
        except Exception:
            pass
        yield _sse("error", {"message": str(exc), "run_id": run_id})
