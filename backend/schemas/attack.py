from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from backend.models.attack import AttackSource, AttackCategory, AttackType, AttackDomain


class AttackTemplateCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    category: AttackCategory
    attack_type: AttackType = AttackType.prompt
    level: int = Field(default=1, ge=1, le=5)
    domain: AttackDomain = AttackDomain.general
    description: str = ""
    payload_template: str = Field(..., min_length=1)
    source: AttackSource = AttackSource.manual

    # Strategy fields
    strategy_goal: str = ""
    strategy_method: str = ""
    strategy_vulnerability: str = ""
    strategy_steps: List[str] = Field(default_factory=list)

    # Metrics
    risk_score: float = Field(default=0.5, ge=0.0, le=1.0)


class AttackTemplateUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[AttackCategory] = None
    attack_type: Optional[AttackType] = None
    level: Optional[int] = Field(default=None, ge=1, le=5)
    domain: Optional[AttackDomain] = None
    description: Optional[str] = None
    payload_template: Optional[str] = None
    is_active: Optional[bool] = None
    strategy_goal: Optional[str] = None
    strategy_method: Optional[str] = None
    strategy_vulnerability: Optional[str] = None
    strategy_steps: Optional[List[str]] = None
    risk_score: Optional[float] = None


class AttackTemplateOut(BaseModel):
    id: int
    name: str
    category: AttackCategory
    attack_type: AttackType
    level: int
    domain: AttackDomain
    description: str
    payload_template: str
    source: AttackSource
    is_active: bool
    strategy_goal: str
    strategy_method: str
    strategy_vulnerability: str
    strategy_steps: List[str]
    success_rate: float
    risk_score: float
    mutation_count: int
    parent_id: Optional[int]
    created_at: datetime

    model_config = {"from_attributes": True}


class AttackPayloadSchema(BaseModel):
    attack_id: Optional[int] = None
    name: str
    category: AttackCategory
    payload: str
    level: int = 1
    attack_type: str = "prompt"
    domain: str = "general"
    risk_score: float = 0.5


class StrategyPlanRequest(BaseModel):
    goal: str = Field(..., description="Attack goal")
    method: str = Field(..., description="Attack method/strategy")
    target_vulnerability: str = Field(..., description="Vulnerability being exploited")
    domain: str = Field(default="general")
    steps: List[str] = Field(default_factory=list)
