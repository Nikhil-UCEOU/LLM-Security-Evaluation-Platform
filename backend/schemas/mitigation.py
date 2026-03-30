from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class MitigationRequest(BaseModel):
    run_id: int = Field(..., description="Evaluation run to mitigate")
    strategy: str = Field(default="auto", description="auto | prompt_hardening | guardrails | combined")
    run_retest: bool = Field(default=True, description="Re-run attacks after mitigation")


class MitigationPlanOut(BaseModel):
    id: int
    run_id: int
    strategy: str
    original_system_prompt: str
    hardened_prompt: str
    guardrails: List[Dict[str, Any]]
    created_at: datetime

    model_config = {"from_attributes": True}


class MitigationResultOut(BaseModel):
    id: int
    plan_id: int
    original_isr: float
    hardened_isr: float
    improvement_pct: float
    retest_run_id: Optional[int]
    created_at: datetime

    model_config = {"from_attributes": True}


class MitigationReport(BaseModel):
    plan: MitigationPlanOut
    result: Optional[MitigationResultOut]
