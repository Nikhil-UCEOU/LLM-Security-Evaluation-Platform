"""
CortexFlow Streaming Pipeline Service
Wraps the evaluation pipeline with real-time SSE event emission.
Each stage yields JSON events that the frontend consumes.
"""
from __future__ import annotations

import json
import asyncio
from datetime import datetime
from typing import AsyncGenerator, List, Optional, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

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
from backend.modules.evaluation_engine.classifier import classify_response, score_severity
from backend.modules.evaluation_engine.isr_calculator import compute_isr
from backend.modules.rca_engine.analyzer import analyze as rca_analyze
from backend.modules.mitigation_engine.prompt_hardener import harden_prompt, generate_guardrails
from backend.modules.mitigation_engine.strategy_selector import select_strategy, extract_vulnerability_categories
from backend.modules.adaptive_attack_engine.ranker import rank_attacks
from backend.modules.learning_engine.store import store_evaluation_results, get_top_attacks
from backend.modules.context_detector.auto_context_detector import detect_context
from backend.modules.gateway import registry
from backend.modules.gateway.base_provider import LLMConfig

import structlog

log = structlog.get_logger()


def _sse(event_type: str, data: Dict[str, Any]) -> str:
    """Format a single SSE message."""
    payload = json.dumps({"type": event_type, **data})
    return f"data: {payload}\n\n"


async def stream_evaluation_pipeline(
    request: EvaluationRunRequest,
    session: AsyncSession,
    document_content: str = "",
    api_schema: str = "",
    enable_mutation: bool = False,
    enable_escalation: bool = True,
    min_level: int = 1,
    max_level: int = 5,
) -> AsyncGenerator[str, None]:
    """
    Async generator that streams the evaluation pipeline as SSE events.
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

    # ── Stage 1: Create run record ─────────────────────────────────────────
    run = EvaluationRun(
        provider=request.provider,
        model=request.model,
        system_prompt=request.system_prompt,
        status=RunStatus.running,
        started_at=datetime.utcnow(),
    )
    session.add(run)
    await session.flush()

    yield _sse("pipeline_start", {
        "run_id": run.id,
        "provider": request.provider,
        "model": request.model,
        "timestamp": datetime.utcnow().isoformat(),
    })

    try:
        # ── Stage 2: Build attack list ─────────────────────────────────────
        categories = request.attack_categories or list(AttackCategory)
        historical = await get_top_attacks(session, request.provider, request.model, limit=20)

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
        eval_results: List[EvaluationResult] = []
        current_level = min_level
        current_isr = 0.0

        for idx, attack in enumerate(attacks):
            # ── Attack Info ──
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
            await asyncio.sleep(0)  # yield control

            # ── Input View ──
            yield _sse("attack_input", {
                "index": idx,
                "payload_preview": attack.payload[:300] + ("..." if len(attack.payload) > 300 else ""),
                "full_payload": attack.payload,
            })
            await asyncio.sleep(0)

            # ── Executing ──
            yield _sse("attack_executing", {"index": idx})

            t_start = asyncio.get_event_loop().time()
            try:
                response = await registry.query(request.provider, attack.payload, config)
                elapsed_ms = int((asyncio.get_event_loop().time() - t_start) * 1000)
            except Exception as exc:
                yield _sse("attack_error", {"index": idx, "error": str(exc)})
                continue

            # ── LLM Response ──
            response_text = response.response_text or response.error or ""
            yield _sse("attack_response", {
                "index": idx,
                "response_preview": response_text[:400] + ("..." if len(response_text) > 400 else ""),
                "latency_ms": elapsed_ms,
                "tokens_used": response.tokens_used,
            })
            await asyncio.sleep(0)

            # ── Classification ──
            classification = classify_response(response_text)
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
            })
            await asyncio.sleep(0)

            # Store result
            er = EvaluationResult(
                run_id=run.id,
                attack_id=attack.attack_id,
                attack_name=attack.name,
                attack_payload=attack.payload,
                response_text=response_text,
                classification=classification,
                severity=severity,
                latency_ms=elapsed_ms,
                tokens_used=response.tokens_used,
                isr_contribution=isr_contribution,
            )
            session.add(er)
            eval_results.append(er)

            result_dicts.append({
                "attack_id": attack.attack_id,
                "attack_name": attack.name,
                "attack_payload": attack.payload,
                "category": attack.category.value,
                "classification": classification,
                "severity": severity,
                "response_text": response_text,
            })

            # ── Live ISR update ──
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

            # ── Escalation check every 5 attacks ──
            if enable_escalation and (idx + 1) % 5 == 0 and idx < total - 1:
                partial_metrics = compute_isr(result_dicts)
                decision = decide_escalation(partial_metrics, current_level, max_level)
                if decision.action != "continue":
                    new_level = decision.next_level or current_level
                    yield _sse("escalation_decision", {
                        "action": decision.action,
                        "from_level": current_level,
                        "to_level": new_level,
                        "reason": decision.reason,
                        "current_isr": round(partial_metrics.global_isr, 3),
                    })
                    current_level = new_level

            await asyncio.sleep(0)  # cooperative yield

        await session.flush()

        # ── Stage 4: ISR metrics ───────────────────────────────────────────
        isr_metrics = compute_isr(result_dicts)
        run.global_isr = isr_metrics.global_isr

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
        rca_report = RCAReport(
            run_id=run.id,
            root_causes=rca_data["root_causes"],
            patterns=rca_data["patterns"],
            affected_prompt_sections=rca_data["affected_prompt_sections"],
            behavioral_analysis=rca_data["behavioral_analysis"],
            architectural_findings=rca_data["architectural_findings"],
            attack_trace=rca_data["attack_trace"],
        )
        session.add(rca_report)
        await session.flush()

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

        plan = MitigationPlan(
            run_id=run.id,
            strategy=strategy,
            original_system_prompt=request.system_prompt,
            hardened_prompt=hardened,
            guardrails=guardrails,
        )
        session.add(plan)
        await session.flush()

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

        retest_run = EvaluationRun(
            provider=request.provider,
            model=request.model,
            system_prompt=hardened,
            status=RunStatus.running,
            started_at=datetime.utcnow(),
        )
        session.add(retest_run)
        await session.flush()

        for rt_attack in retest_attacks:
            try:
                rt_response = await registry.query(request.provider, rt_attack.payload, hardened_config)
            except Exception:
                continue
            rt_text = rt_response.response_text or ""
            rt_cls = classify_response(rt_text)
            rt_sev = score_severity(rt_cls, rt_text)
            retest_run_result = EvaluationResult(
                run_id=retest_run.id,
                attack_name=rt_attack.name,
                attack_payload=rt_attack.payload,
                response_text=rt_text,
                classification=rt_cls,
                severity=rt_sev,
                latency_ms=0,
                tokens_used=rt_response.tokens_used,
                isr_contribution=1.0 if rt_cls in (Classification.unsafe, Classification.partial) else 0.0,
            )
            session.add(retest_run_result)
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
        retest_run.global_isr = hardened_isr
        retest_run.status = RunStatus.completed
        retest_run.completed_at = datetime.utcnow()

        improvement_pct = (
            (isr_metrics.global_isr - hardened_isr) / isr_metrics.global_isr * 100
            if isr_metrics.global_isr > 0 else 0.0
        )

        mitigation_result = MitigationResult(
            plan_id=plan.id,
            original_isr=isr_metrics.global_isr,
            hardened_isr=hardened_isr,
            improvement_pct=round(improvement_pct, 2),
            retest_run_id=retest_run.id,
        )
        session.add(mitigation_result)

        yield _sse("stage_retest_done", {
            "original_isr": isr_metrics.global_isr,
            "hardened_isr": hardened_isr,
            "improvement_pct": round(improvement_pct, 2),
        })

        # ── Stage 8: Learning ──────────────────────────────────────────────
        yield _sse("stage_learning_start", {"message": "Storing insights in learning engine..."})
        await store_evaluation_results(session, request.provider, request.model, result_dicts)
        yield _sse("stage_learning_done", {"entries_stored": len(result_dicts)})

        # ── Finalize ───────────────────────────────────────────────────────
        run.status = RunStatus.completed
        run.completed_at = datetime.utcnow()
        await session.commit()

        yield _sse("complete", {
            "run_id": run.id,
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
        run.status = RunStatus.failed
        run.completed_at = datetime.utcnow()
        try:
            await session.commit()
        except Exception:
            pass
        log.error("streaming_pipeline.failed", run_id=run.id, error=str(exc))
        yield _sse("error", {"message": str(exc), "run_id": run.id})
