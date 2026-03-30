"""Report generation service — aggregates all pipeline data into a structured report."""
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.models.evaluation import EvaluationRun, EvaluationResult
from backend.models.rca import RCAReport
from backend.models.mitigation import MitigationPlan, MitigationResult


async def generate_report(run_id: int, session: AsyncSession) -> Dict[str, Any]:
    """Generate a full structured report for a completed evaluation run."""
    # Load run with results
    stmt = (
        select(EvaluationRun)
        .where(EvaluationRun.id == run_id)
        .options(selectinload(EvaluationRun.results))
    )
    run = (await session.execute(stmt)).scalar_one_or_none()
    if not run:
        return {"error": f"Run {run_id} not found"}

    # Load RCA
    rca = (await session.execute(
        select(RCAReport).where(RCAReport.run_id == run_id)
    )).scalar_one_or_none()

    # Load mitigation
    plan = (await session.execute(
        select(MitigationPlan).where(MitigationPlan.run_id == run_id)
    )).scalar_one_or_none()

    mitigation_result = None
    if plan:
        mitigation_result = (await session.execute(
            select(MitigationResult).where(MitigationResult.plan_id == plan.id)
        )).scalar_one_or_none()

    # Aggregate severity distribution
    severity_dist: Dict[str, int] = {}
    unsafe_results = []
    for r in run.results:
        sev = r.severity.value
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
        if r.isr_contribution > 0:
            unsafe_results.append({
                "attack_name": r.attack_name,
                "classification": r.classification.value,
                "severity": r.severity.value,
                "payload_excerpt": r.attack_payload[:100],
                "response_excerpt": r.response_text[:100],
            })

    return {
        "report_type": "CortexFlow Security Evaluation Report",
        "run_id": run_id,
        "model_performance": {
            "provider": run.provider,
            "model": run.model,
            "global_isr": run.global_isr,
            "total_attacks": len(run.results),
            "status": run.status.value,
            "evaluated_at": run.completed_at.isoformat() if run.completed_at else None,
        },
        "vulnerabilities": unsafe_results,
        "severity_distribution": severity_dist,
        "root_causes": rca.root_causes if rca else [],
        "patterns": rca.patterns if rca else [],
        "behavioral_analysis": rca.behavioral_analysis if rca else "",
        "architectural_findings": rca.architectural_findings if rca else "",
        "mitigation": {
            "strategy": plan.strategy if plan else None,
            "hardened_prompt": plan.hardened_prompt if plan else None,
            "guardrails": plan.guardrails if plan else [],
            "original_isr": mitigation_result.original_isr if mitigation_result else None,
            "hardened_isr": mitigation_result.hardened_isr if mitigation_result else None,
            "improvement_pct": mitigation_result.improvement_pct if mitigation_result else None,
        },
    }
