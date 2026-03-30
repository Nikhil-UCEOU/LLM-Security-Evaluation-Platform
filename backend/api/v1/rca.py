from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.api.deps import get_db, verify_api_key
from backend.schemas.rca import RCAReportOut
from backend.models.rca import RCAReport

router = APIRouter(prefix="/rca", tags=["RCA Engine"])


@router.get("/{run_id}", response_model=RCAReportOut)
async def get_rca_report(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> RCAReportOut:
    """Get the Root Cause Analysis report for an evaluation run."""
    report = (await db.execute(
        select(RCAReport).where(RCAReport.run_id == run_id)
    )).scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail="RCA report not found for this run")
    return report
