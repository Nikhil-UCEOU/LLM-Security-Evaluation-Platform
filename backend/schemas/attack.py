from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from backend.models.attack import AttackSource, AttackCategory


class AttackTemplateCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    category: AttackCategory
    description: str = ""
    payload_template: str = Field(..., min_length=1)
    source: AttackSource = AttackSource.manual


class AttackTemplateUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[AttackCategory] = None
    description: Optional[str] = None
    payload_template: Optional[str] = None
    is_active: Optional[bool] = None


class AttackTemplateOut(BaseModel):
    id: int
    name: str
    category: AttackCategory
    description: str
    payload_template: str
    source: AttackSource
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AttackPayload(BaseModel):
    attack_id: Optional[int] = None
    name: str
    category: AttackCategory
    payload: str
