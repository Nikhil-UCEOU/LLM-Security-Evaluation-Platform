from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from typing import List

from backend.api.deps import get_db, verify_api_key
from backend.schemas.evaluation import EvaluationRunRequest, EvaluationRunOut, EvaluationSummary
from backend.models.evaluation import EvaluationRun
from backend.services.pipeline_service import run_evaluation_pipeline
from backend.services.report_service import generate_report

router = APIRouter(prefix="/evaluations", tags=["Evaluation Engine"])


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
