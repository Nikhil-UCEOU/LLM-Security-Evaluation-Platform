from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from backend.api.deps import get_db, verify_api_key
from backend.schemas.evaluation import EvaluationRunRequest, EvaluationRunOut, EvaluationSummary
from backend.models.evaluation import EvaluationRun
from backend.services.pipeline_service import run_evaluation_pipeline
from backend.services.report_service import generate_report
from backend.modules.evaluation_engine.analysis_engine import analyze_evaluation

router = APIRouter(prefix="/evaluations", tags=["Evaluation Engine"])


class DirectAnalysisRequest(BaseModel):
    """Request body for direct analysis without DB lookup."""
    attack_results: List[Dict[str, Any]]
    global_isr: float = 0.0
    run_id: str = "direct"


@router.post("/run")
async def run_evaluation(
    request: EvaluationRunRequest,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    """
    Trigger the full CortexFlow evaluation pipeline:
    Attack → LLM → Evaluate → RCA → Mitigate → Re-test → Learn
    """
    result = await run_evaluation_pipeline(request, db)
    return result


@router.get("/", response_model=List[EvaluationSummary])
async def list_evaluations(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> List[EvaluationSummary]:
    """List recent evaluation runs."""
    stmt = (
        select(EvaluationRun)
        .order_by(desc(EvaluationRun.started_at))
        .limit(limit)
        .options(selectinload(EvaluationRun.results))
    )
    runs = (await db.execute(stmt)).scalars().all()

    summaries = []
    for run in runs:
        unsafe_count = sum(1 for r in run.results if r.isr_contribution > 0)
        critical_count = sum(1 for r in run.results if r.severity.value == "critical")
        summaries.append(EvaluationSummary(
            run_id=run.id,
            provider=run.provider,
            model=run.model,
            status=run.status,
            global_isr=run.global_isr,
            total_attacks=len(run.results),
            unsafe_count=unsafe_count,
            critical_count=critical_count,
            started_at=run.started_at,
            completed_at=run.completed_at,
        ))
    return summaries


@router.get("/{run_id}", response_model=EvaluationRunOut)
async def get_evaluation(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> EvaluationRunOut:
    """Get a full evaluation run with all results."""
    stmt = (
        select(EvaluationRun)
        .where(EvaluationRun.id == run_id)
        .options(selectinload(EvaluationRun.results))
    )
    run = (await db.execute(stmt)).scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")
    return run


@router.get("/{run_id}/report")
async def get_report(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    """Generate and return a full structured report for an evaluation run."""
    return await generate_report(run_id, db)


@router.get("/{run_id}/analysis")
async def get_evaluation_analysis(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Deep analysis of WHY failures occurred in an evaluation run.
    Returns:
    - Failure factors (which attack techniques succeeded and why)
    - OWASP risk breakdown
    - Model vulnerability profile
    - Priority mitigation recommendations
    - Human-readable key findings
    """
    stmt = (
        select(EvaluationRun)
        .where(EvaluationRun.id == run_id)
        .options(selectinload(EvaluationRun.results))
    )
    run = (await db.execute(stmt)).scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found")

    # Build attack results from DB records
    attack_results = []
    for r in run.results:
        attack_results.append({
            "classification": r.classification.value if r.classification else "safe",
            "severity": r.severity.value if r.severity else "none",
            "category": r.attack_category or "unknown",
            "strategy": r.attack_strategy or "unknown",
            "owasp_risk": getattr(r, "owasp_risk", "LLM01") or "LLM01",
            "signals": getattr(r, "signals", []) or [],
            "attack_name": r.attack_name or "Unknown",
        })

    analysis = analyze_evaluation(
        run_id=str(run_id),
        attack_results=attack_results,
        global_isr=float(run.global_isr or 0),
    )

    return analysis.to_dict()


@router.post("/analyze")
async def analyze_direct(
    req: DirectAnalysisRequest,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Analyze attack results directly (without DB lookup).
    Use this when you have evaluation results from the pipeline
    and want immediate analysis.
    """
    if not req.attack_results:
        raise HTTPException(400, "No attack results provided")

    total = len(req.attack_results)
    successful = sum(
        1 for r in req.attack_results
        if r.get("classification") in ("unsafe", "partial")
    )
    isr = req.global_isr if req.global_isr > 0 else (successful / total if total > 0 else 0.0)

    analysis = analyze_evaluation(
        run_id=req.run_id,
        attack_results=req.attack_results,
        global_isr=isr,
    )

    return analysis.to_dict()
