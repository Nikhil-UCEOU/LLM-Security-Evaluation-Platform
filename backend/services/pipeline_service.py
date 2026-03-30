"""
CortexFlow Pipeline Service
Orchestrates the full evaluation pipeline:
Attack → LLM → Evaluation → RCA → Mitigation → Re-test → Store → Learn
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession

from backend.schemas.evaluation import EvaluationRunRequest
from backend.models.evaluation import (
    EvaluationRun, EvaluationResult, RunStatus, Classification,
)
from backend.models.rca import RCAReport
from backend.models.mitigation import MitigationPlan, MitigationResult
from backend.models.attack import AttackTemplate, AttackCategory

from backend.modules.attack_engine.runner import run_attacks, build_attack_list
from backend.modules.attack_engine.base_attack import AttackPayload
from backend.modules.evaluation_engine.classifier import classify_response, score_severity
from backend.modules.evaluation_engine.isr_calculator import compute_isr
from backend.modules.rca_engine.analyzer import analyze as rca_analyze
from backend.modules.mitigation_engine.prompt_hardener import harden_prompt, generate_guardrails
from backend.modules.mitigation_engine.strategy_selector import select_strategy, extract_vulnerability_categories
from backend.modules.adaptive_attack_engine.generator import generate_adaptive_attacks
from backend.modules.adaptive_attack_engine.ranker import rank_attacks
from backend.modules.learning_engine.store import store_evaluation_results, get_top_attacks
from backend.core.exceptions import PipelineError

import structlog

log = structlog.get_logger()


async def run_evaluation_pipeline(
    request: EvaluationRunRequest,
    session: AsyncSession,
) -> Dict[str, Any]:
    """
    Full evaluation pipeline. Returns a comprehensive report dict.
    """
    # --- Stage 1: Create evaluation run record ---
    run = EvaluationRun(
        provider=request.provider,
        model=request.model,
        system_prompt=request.system_prompt,
        status=RunStatus.running,
        started_at=datetime.utcnow(),
    )
    session.add(run)
    await session.flush()
    log.info("pipeline.start", run_id=run.id, provider=request.provider, model=request.model)

    try:
        # --- Stage 2: Build attack list ---
        categories = request.attack_categories or list(AttackCategory)
        historical = await get_top_attacks(session, request.provider, request.model, limit=20)

        adaptive_attacks: List[AttackPayload] = []
        if request.include_adaptive:
            log.info("pipeline.adaptive_generation", run_id=run.id)
            successful_history = [h for h in historical if h["success_rate"] > 0.3]
            adaptive_attacks = await generate_adaptive_attacks(
                count=5,
                successful_attacks=successful_history,
                target_categories=[c.value for c in categories],
            )

        attacks = build_attack_list(
            categories=categories,
            max_attacks=request.max_attacks,
            extra_attacks=adaptive_attacks,
        )
        attacks = rank_attacks(attacks, historical)
        log.info("pipeline.attacks_built", run_id=run.id, count=len(attacks))

        # --- Stage 3: Execute attacks via LLM Gateway ---
        log.info("pipeline.executing_attacks", run_id=run.id)
        attack_results = await run_attacks(
            provider=request.provider,
            model=request.model,
            system_prompt=request.system_prompt,
            attacks=attacks,
        )

        # --- Stage 4: Evaluate responses ---
        eval_result_records = []
        result_dicts = []

        for ar in attack_results:
            classification = classify_response(ar.response.response_text)
            severity = score_severity(classification, ar.response.response_text)
            isr_contribution = 1.0 if classification in (Classification.unsafe, Classification.partial) else 0.0

            # Find attack_id from DB if it exists
            attack_id_db = ar.payload.attack_id

            result = EvaluationResult(
                run_id=run.id,
                attack_id=attack_id_db,
                attack_name=ar.payload.name,
                attack_payload=ar.payload.payload,
                response_text=ar.response.response_text or ar.response.error or "",
                classification=classification,
                severity=severity,
                latency_ms=ar.response.latency_ms,
                tokens_used=ar.response.tokens_used,
                isr_contribution=isr_contribution,
            )
            session.add(result)
            eval_result_records.append(result)

            result_dicts.append({
                "attack_id": attack_id_db,
                "attack_name": ar.payload.name,
                "attack_payload": ar.payload.payload,
                "category": ar.payload.category.value,
                "classification": classification,
                "severity": severity,
                "response_text": ar.response.response_text or "",
            })

        await session.flush()

        # Compute ISR
        isr_metrics = compute_isr(result_dicts)
        run.global_isr = isr_metrics.global_isr
        log.info("pipeline.evaluation_done", run_id=run.id, isr=isr_metrics.global_isr)

        # --- Stage 5: RCA ---
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
        log.info("pipeline.rca_done", run_id=run.id)

        # --- Stage 6: Mitigation ---
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

        # --- Stage 7: Re-test with hardened prompt ---
        hardened_isr = isr_metrics.global_isr
        retest_run_id = None

        retest_request = EvaluationRunRequest(
            provider=request.provider,
            model=request.model,
            system_prompt=hardened,
            attack_categories=request.attack_categories,
            include_adaptive=False,
            max_attacks=min(request.max_attacks, 10),
        )
        retest_run = EvaluationRun(
            provider=request.provider,
            model=request.model,
            system_prompt=hardened,
            status=RunStatus.running,
            started_at=datetime.utcnow(),
        )
        session.add(retest_run)
        await session.flush()

        retest_attack_results = await run_attacks(
            provider=request.provider,
            model=request.model,
            system_prompt=hardened,
            attacks=attacks[:min(len(attacks), 10)],
        )

        retest_result_dicts = []
        for ar in retest_attack_results:
            cls = classify_response(ar.response.response_text)
            sev = score_severity(cls, ar.response.response_text)
            res = EvaluationResult(
                run_id=retest_run.id,
                attack_name=ar.payload.name,
                attack_payload=ar.payload.payload,
                response_text=ar.response.response_text or ar.response.error or "",
                classification=cls,
                severity=sev,
                latency_ms=ar.response.latency_ms,
                tokens_used=ar.response.tokens_used,
                isr_contribution=1.0 if cls in (Classification.unsafe, Classification.partial) else 0.0,
            )
            session.add(res)
            retest_result_dicts.append({
                "classification": cls,
                "severity": sev,
                "category": ar.payload.category.value,
                "attack_name": ar.payload.name,
                "attack_payload": ar.payload.payload,
                "response_text": ar.response.response_text or "",
            })

        retest_isr = compute_isr(retest_result_dicts)
        hardened_isr = retest_isr.global_isr
        retest_run.global_isr = hardened_isr
        retest_run.status = RunStatus.completed
        retest_run.completed_at = datetime.utcnow()
        retest_run_id = retest_run.id

        improvement_pct = (
            (isr_metrics.global_isr - hardened_isr) / isr_metrics.global_isr * 100
            if isr_metrics.global_isr > 0 else 0.0
        )

        mitigation_result = MitigationResult(
            plan_id=plan.id,
            original_isr=isr_metrics.global_isr,
            hardened_isr=hardened_isr,
            improvement_pct=round(improvement_pct, 2),
            retest_run_id=retest_run_id,
        )
        session.add(mitigation_result)
        log.info("pipeline.mitigation_done", run_id=run.id, original_isr=isr_metrics.global_isr, hardened_isr=hardened_isr)

        # --- Stage 8: Learning ---
        await store_evaluation_results(session, request.provider, request.model, result_dicts)

        # --- Finalize ---
        run.status = RunStatus.completed
        run.completed_at = datetime.utcnow()
        await session.commit()
        log.info("pipeline.complete", run_id=run.id)

        return {
            "run_id": run.id,
            "status": "completed",
            "provider": request.provider,
            "model": request.model,
            "global_isr": isr_metrics.global_isr,
            "isr_by_category": isr_metrics.by_category,
            "total_attacks": isr_metrics.total_attacks,
            "successful_attacks": isr_metrics.successful_attacks,
            "severity_distribution": isr_metrics.by_severity,
            "rca_summary": {
                "root_causes": len(rca_data["root_causes"]),
                "patterns": len(rca_data["patterns"]),
                "behavioral_analysis": rca_data["behavioral_analysis"],
            },
            "mitigation": {
                "strategy": strategy,
                "original_isr": isr_metrics.global_isr,
                "hardened_isr": hardened_isr,
                "improvement_pct": improvement_pct,
            },
        }

    except Exception as e:
        run.status = RunStatus.failed
        run.completed_at = datetime.utcnow()
        await session.commit()
        log.error("pipeline.failed", run_id=run.id, error=str(e))
        raise PipelineError("pipeline", str(e))
