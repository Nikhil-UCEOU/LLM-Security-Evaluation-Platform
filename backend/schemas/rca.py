from pydantic import BaseModel
from typing import List, Dict, Any
from datetime import datetime


class RCARootCause(BaseModel):
    category: str
    description: str
    affected_attacks: List[str]
    severity: str


class RCAReportOut(BaseModel):
    id: int
    run_id: int
    root_causes: List[RCARootCause]
    patterns: List[Dict[str, Any]]
    affected_prompt_sections: List[str]
    behavioral_analysis: str
    architectural_findings: str
    attack_trace: List[Dict[str, Any]]
    generated_at: datetime

    model_config = {"from_attributes": True}
