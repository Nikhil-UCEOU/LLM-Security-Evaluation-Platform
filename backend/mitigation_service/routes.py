"""
Mitigation Intelligence Engine v2 — API Routes
Core:
  /mitigation/plan             → Generate mitigation plan
  /mitigation/apply            → Apply mitigations
  /mitigation/report           → Before/after comparison report

MIE v2 (Research-grade):
  /mitigation/adversarial-test → Re-attack against hardened system
  /mitigation/generalize       → Test across models and domains
  /mitigation/tradeoff         → Security vs quality trade-off analysis
  /mitigation/optimize         → Find best strategy combination
  /mitigation/adaptive-plan    → Domain/risk-aware mitigation plan
  /mitigation/runtime-check    → Real-time input inspection
  /mitigation/explain          → Explain mitigation decision
  /mitigation/compliance       → Map to business compliance frameworks
  /mitigation/defense-plan     → Build layered defense architecture
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

# MIE v2 engines
from backend.mitigation_service.adversarial_retester import run_adversarial_retest
from backend.mitigation_service.generalization_engine import run_generalization_test
from backend.mitigation_service.tradeoff_analyzer import analyze_tradeoffs
from backend.mitigation_service.mitigation_optimizer import optimize_mitigation
from backend.mitigation_service.adaptive_engine import build_adaptive_plan
from backend.mitigation_service.runtime_guard import inspect_input, batch_inspect
from backend.mitigation_service.explanation_engine import explain_mitigation, explain_attack_success
from backend.mitigation_service.compliance_mapper import map_compliance
from backend.mitigation_service.defense_planner import build_defense_architecture

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


# ── MIE v2 endpoints ──────────────────────────────────────────────────────────

class AdversarialTestRequest(BaseModel):
    run_id: int
    max_generations: int = Field(default=3, ge=1, le=6)
    variants_per_attack: int = Field(default=4, ge=1, le=10)


class GeneralizeRequest(BaseModel):
    run_id: int
    test_models: Optional[List[str]] = None
    test_domains: Optional[List[str]] = None
    pass_threshold: float = Field(default=0.25, ge=0.0, le=1.0)


class TradeoffRequest(BaseModel):
    run_id: int


class OptimizeRequest(BaseModel):
    run_id: int
    optimization_target: str = Field(default="balanced", pattern="^(balanced|security_first|quality_first)$")


class AdaptivePlanRequest(BaseModel):
    domain: str = "general"
    risk_level: str = Field(default="high", pattern="^(critical|high|medium|low)$")
    system_prompt: str = "You are a helpful assistant."
    failure_modes: Optional[List[str]] = None


class RuntimeCheckRequest(BaseModel):
    input: str = Field(description="User input to inspect")
    strictness: str = Field(default="moderate", pattern="^(strict|moderate|permissive)$")
    domain: str = "general"


class RuntimeBatchRequest(BaseModel):
    inputs: List[str] = Field(description="Batch of inputs to inspect", max_length=50)
    strictness: str = "moderate"
    domain: str = "general"


class ExplainRequest(BaseModel):
    run_id: int
    failure_mode: Optional[str] = None  # if None, use the dominant failure mode


class ComplianceRequest(BaseModel):
    run_id: int
    domain: str = "general"


class DefensePlanRequest(BaseModel):
    run_id: int


def _load_run_sync_helper(run_id: int):
    """Helper — loaded async in endpoint."""
    pass


async def _get_plan_from_run(run_id: int, db: AsyncSession) -> tuple:
    """Load run + build plan, used by multiple v2 endpoints."""
    stmt = (select(EvaluationRun).where(EvaluationRun.id == run_id)
            .options(selectinload(EvaluationRun.results)))
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
    return run, plan, result_dicts


@router.post("/adversarial-test")
async def adversarial_test(
    body: AdversarialTestRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Re-attack the hardened system with adaptively generated bypass attacks."""
    run, plan, result_dicts = await _get_plan_from_run(body.run_id, db)
    original_attacks = [r["attack_payload"] for r in result_dicts if r["attack_payload"]]
    result = run_adversarial_retest(
        original_attacks=original_attacks,
        hardened_prompt=plan.hardened_prompt,
        applied_techniques=[s.technique_id for s in plan.steps],
        max_generations=body.max_generations,
        variants_per_attack=body.variants_per_attack,
    )
    return result.to_dict()


@router.post("/generalize")
async def generalize(
    body: GeneralizeRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Test mitigation effectiveness across multiple models and domains."""
    run, plan, _ = await _get_plan_from_run(body.run_id, db)
    result = run_generalization_test(
        original_isr=run.global_isr or 0.0,
        applied_techniques=[s.technique_id for s in plan.steps],
        test_models=body.test_models,
        test_domains=body.test_domains,
        pass_threshold=body.pass_threshold,
    )
    return result.to_dict()


@router.post("/tradeoff")
async def tradeoff(
    body: TradeoffRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Analyze security vs quality vs latency trade-offs for applied mitigations."""
    run, plan, _ = await _get_plan_from_run(body.run_id, db)
    steps_dicts = [
        {
            "technique_id": s.technique_id,
            "technique_name": s.technique_name,
            "layer": s.layer,
            "complexity": s.complexity,
            "estimated_effectiveness": s.estimated_effectiveness,
        }
        for s in plan.steps
    ]
    result = analyze_tradeoffs(
        mitigation_steps=steps_dicts,
        original_isr=run.global_isr or 0.0,
        estimated_residual_isr=plan.estimated_residual_isr,
    )
    return result.to_dict()


@router.post("/optimize")
async def optimize(
    body: OptimizeRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Find the optimal mitigation strategy combination."""
    run, plan, _ = await _get_plan_from_run(body.run_id, db)
    result = optimize_mitigation(
        original_isr=run.global_isr or 0.0,
        failure_modes=plan.failure_modes_detected,
        optimization_target=body.optimization_target,
    )
    return result.to_dict()


@router.post("/adaptive-plan")
def adaptive_plan(
    body: AdaptivePlanRequest,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Build a domain- and risk-aware mitigation plan."""
    result = build_adaptive_plan(
        domain=body.domain,
        risk_level=body.risk_level,
        original_prompt=body.system_prompt,
        failure_modes=body.failure_modes,
    )
    return result.to_dict()


@router.post("/runtime-check")
def runtime_check(
    body: RuntimeCheckRequest,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Inspect a user input in real-time and return block/modify/allow decision."""
    result = inspect_input(
        user_input=body.input,
        strictness=body.strictness,
        domain=body.domain,
    )
    return result.to_dict()


@router.post("/runtime-check/batch")
def runtime_check_batch(
    body: RuntimeBatchRequest,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Inspect multiple inputs in batch."""
    results = batch_inspect(body.inputs, strictness=body.strictness, domain=body.domain)
    blocked = sum(1 for r in results if r.decision.value == "block")
    modified = sum(1 for r in results if r.decision.value == "modify")
    return {
        "total": len(results),
        "blocked": blocked,
        "modified": modified,
        "allowed": len(results) - blocked - modified,
        "results": [r.to_dict() for r in results],
    }


@router.post("/explain")
async def explain(
    body: ExplainRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Explain why a mitigation was applied and what it protects against."""
    run, plan, _ = await _get_plan_from_run(body.run_id, db)
    fm = body.failure_mode or (plan.failure_modes_detected[0] if plan.failure_modes_detected else "direct_override")
    result = explain_mitigation(
        failure_mode=fm,
        applied_techniques=[s.technique_id for s in plan.steps],
        isr_before=run.global_isr or 0.0,
        isr_after=plan.estimated_residual_isr,
    )
    # Also explain top attacks
    attack_explanations = []
    seen_cats: set = set()
    from backend.mitigation_service.failure_classifier import FAILURE_MODES
    for rd in []:  # skipped — not needed in explain
        pass
    for cat in ["jailbreak", "prompt_injection", "rag", "tool_misuse"]:
        if cat not in seen_cats:
            ae = explain_attack_success("", cat)
            attack_explanations.append(ae.to_dict())
            seen_cats.add(cat)

    return {
        **result.to_dict(),
        "attack_category_explanations": attack_explanations,
    }


@router.post("/compliance")
async def compliance(
    body: ComplianceRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Map detected vulnerabilities to compliance frameworks (GDPR, HIPAA, PCI-DSS, etc.)."""
    run, plan, _ = await _get_plan_from_run(body.run_id, db)
    result = map_compliance(
        failure_modes=plan.failure_modes_detected,
        domain=body.domain,
    )
    return result.to_dict()


@router.post("/defense-plan")
async def defense_plan(
    body: DefensePlanRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Build a layered defense-in-depth architecture from applied techniques."""
    run, plan, _ = await _get_plan_from_run(body.run_id, db)
    result = build_defense_architecture(
        applied_techniques=[s.technique_id for s in plan.steps],
        failure_modes=plan.failure_modes_detected,
    )
    return result.to_dict()
