from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.api.deps import get_db, verify_api_key
from backend.schemas.mitigation import MitigationRequest, MitigationReport, MitigationPlanOut, MitigationResultOut
from backend.models.mitigation import MitigationPlan, MitigationResult

router = APIRouter(prefix="/mitigations", tags=["Mitigation Engine"])


@router.get("/{run_id}", response_model=MitigationReport)
async def get_mitigation(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> MitigationReport:
    """Get the mitigation plan and result for an evaluation run."""
    plan = (await db.execute(
        select(MitigationPlan).where(MitigationPlan.run_id == run_id)
    )).scalar_one_or_none()

    if not plan:
        raise HTTPException(status_code=404, detail="No mitigation plan found for this run")

    result = (await db.execute(
        select(MitigationResult).where(MitigationResult.plan_id == plan.id)
    )).scalar_one_or_none()

    return MitigationReport(
        plan=MitigationPlanOut.model_validate(plan),
        result=MitigationResultOut.model_validate(result) if result else None,
    )
