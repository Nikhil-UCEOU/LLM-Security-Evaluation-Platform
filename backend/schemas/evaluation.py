from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from backend.models.evaluation import RunStatus, Classification, Severity
from backend.models.attack import AttackCategory


class EvaluationRunRequest(BaseModel):
    provider: str = Field(default="openai")
    model: str = Field(default="gpt-4o-mini")
    system_prompt: str = Field(default="You are a helpful assistant.")
    attack_categories: List[AttackCategory] = Field(default_factory=list, description="Empty = all categories")
    include_adaptive: bool = Field(default=False, description="Generate adaptive attacks via LLM")
    max_attacks: int = Field(default=20, ge=1, le=100)


class EvaluationResultOut(BaseModel):
    id: int
    run_id: int
    attack_name: str
    attack_payload: str
    response_text: str
    classification: Classification
    severity: Severity
    latency_ms: int
    tokens_used: int
    isr_contribution: float
    created_at: datetime

    model_config = {"from_attributes": True}


class EvaluationRunOut(BaseModel):
    id: int
    provider: str
    model: str
    system_prompt: str
    status: RunStatus
    global_isr: Optional[float]
    started_at: datetime
    completed_at: Optional[datetime]
    results: List[EvaluationResultOut] = []

    model_config = {"from_attributes": True}


class EvaluationSummary(BaseModel):
    run_id: int
    provider: str
    model: str
    status: RunStatus
    global_isr: Optional[float]
    total_attacks: int
    unsafe_count: int
    critical_count: int
    started_at: datetime
    completed_at: Optional[datetime]
