"""
Mitigation Intelligence Engine (MIE) — API Routes
/mitigation/plan     → Generate mitigation plan from evaluation run
/mitigation/apply    → Apply mitigations and return hardened config
/mitigation/retest   → Re-run subset of attacks with hardened prompt
/mitigation/report   → Full before/after comparison report with MES
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from backend.api.deps import get_db, verify_api_key
from backend.models.evaluation import EvaluationRun, EvaluationResult
from backend.mitigation_service.failure_classifier import classify_failures
from backend.mitigation_service.mitigation_planner import plan_mitigations
from backend.mitigation_service.comparison_engine import compare_before_after

router = APIRouter(prefix="/mitigation", tags=["Mitigation Intelligence Engine"])


class PlanRequest(BaseModel):
    run_id: int = Field(description="Evaluation run ID to analyze")
    provider: str = "openai"
    model: str = "gpt-4o-mini"


class ApplyRequest(BaseModel):
    run_id: int
    selected_technique_ids: Optional[List[str]] = None  # None = apply all recommended


class RetestRequest(BaseModel):
    run_id: int
    hardened_prompt: str
    max_attacks: int = Field(default=10, ge=1, le=50)


@router.post("/plan")
async def get_mitigation_plan(
    body: PlanRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Analyze an evaluation run and generate a full mitigation plan.
    Returns failure modes, prioritized techniques, hardened prompt, and guardrails.
    """
    # Load run + results
    stmt = (
        select(EvaluationRun)
        .where(EvaluationRun.id == body.run_id)
        .options(selectinload(EvaluationRun.results))
    )
    run = (await db.execute(stmt)).scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")

    # Build result dicts
    result_dicts = [
        {
            "attack_name": r.attack_name,
            "attack_payload": r.attack_payload,
            "response_text": r.response_text,
            "classification": r.classification.value,
            "severity": r.severity.value,
            "category": r.attack_name.split("_")[0] if "_" in r.attack_name else "prompt_injection",
        }
        for r in run.results
    ]

    plan = plan_mitigations(
        result_dicts=result_dicts,
        original_system_prompt=run.system_prompt,
        global_isr=run.global_isr or 0.0,
        provider=body.provider,
        model=body.model,
    )

    return {
        "plan_id": plan.plan_id,
        "run_id": body.run_id,
        "original_isr": plan.original_isr,
        "total_failures": plan.total_failures,
        "failure_modes_detected": plan.failure_modes_detected,
        "steps": [
            {
                "priority": s.priority,
                "technique_id": s.technique_id,
                "technique_name": s.technique_name,
                "layer": s.layer,
                "description": s.description,
                "implementation": s.implementation,
                "prompt_instruction": s.prompt_instruction,
                "guardrail_rule": s.guardrail_rule,
                "estimated_effectiveness": s.estimated_effectiveness,
                "complexity": s.complexity,
                "addresses_failures": s.addresses_failures,
            }
            for s in plan.steps
        ],
        "hardened_prompt": plan.hardened_prompt,
        "guardrails": plan.guardrails,
        "estimated_residual_isr": plan.estimated_residual_isr,
        "estimated_mes": plan.estimated_mes,
        "confidence": plan.confidence,
        "priority_recommendation": plan.priority_recommendation,
    }


@router.post("/apply")
async def apply_mitigations(
    body: ApplyRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Apply selected (or all) mitigations from the plan and return
    the hardened system prompt + active guardrail configuration.
    """
    stmt = (
        select(EvaluationRun)
        .where(EvaluationRun.id == body.run_id)
        .options(selectinload(EvaluationRun.results))
    )
    run = (await db.execute(stmt)).scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")

    result_dicts = [
        {
            "attack_name": r.attack_name,
            "attack_payload": r.attack_payload,
            "response_text": r.response_text,
            "classification": r.classification.value,
            "severity": r.severity.value,
            "category": r.attack_name.split("_")[0] if "_" in r.attack_name else "prompt_injection",
        }
        for r in run.results
    ]

    plan = plan_mitigations(
        result_dicts=result_dicts,
        original_system_prompt=run.system_prompt,
        global_isr=run.global_isr or 0.0,
    )

    # Filter by selected technique IDs if provided
    active_steps = plan.steps
    if body.selected_technique_ids:
        active_steps = [s for s in plan.steps if s.technique_id in body.selected_technique_ids]

    return {
        "run_id": body.run_id,
        "hardened_prompt": plan.hardened_prompt,
        "active_techniques": [s.technique_id for s in active_steps],
        "guardrails": [g for g in plan.guardrails if any(s.technique_id == g["id"] for s in active_steps)],
        "estimated_mes": plan.estimated_mes,
        "message": f"Applied {len(active_steps)} mitigation techniques.",
    }


@router.post("/report")
async def mitigation_report(
    body: PlanRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Full before/after comparison report.
    Computes MES, DLS, IDI changes.
    """
    # Load original run
    stmt = (
        select(EvaluationRun)
        .where(EvaluationRun.id == body.run_id)
        .options(selectinload(EvaluationRun.results))
    )
    run = (await db.execute(stmt)).scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")

    original_results = [
        {
            "response_text": r.response_text,
            "classification": r.classification.value,
            "severity": r.severity.value,
        }
        for r in run.results
    ]

    # For now, hardened results use the same data (re-test not yet completed)
    # In production this would compare against a re-test run
    plan = plan_mitigations(
        result_dicts=original_results,
        original_system_prompt=run.system_prompt,
        global_isr=run.global_isr or 0.0,
    )

    comparison = compare_before_after(
        original_results=original_results,
        hardened_results=original_results,  # placeholder until retest
        original_isr=run.global_isr or 0.0,
        hardened_isr=plan.estimated_residual_isr,
    )

    return {
        "run_id": body.run_id,
        "original_isr": comparison.original_isr,
        "hardened_isr": comparison.hardened_isr,
        "isr_delta": comparison.isr_delta,
        "isr_improvement_pct": comparison.isr_improvement_pct,
        "original_dls": comparison.original_dls,
        "hardened_dls": comparison.hardened_dls,
        "dls_delta": comparison.dls_delta,
        "original_idi": comparison.original_idi,
        "hardened_idi": comparison.hardened_idi,
        "idi_delta": comparison.idi_delta,
        "mes": comparison.mes,
        "grade": comparison.grade,
        "summary": comparison.summary,
        "failure_modes_detected": plan.failure_modes_detected,
        "priority_recommendation": plan.priority_recommendation,
        "mitigation_steps_count": len(plan.steps),
    }
