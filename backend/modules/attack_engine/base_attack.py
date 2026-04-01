from dataclasses import dataclass, field
from typing import Optional, List
from backend.models.attack import AttackCategory


@dataclass
class AttackPayload:
    attack_id: Optional[int]
    name: str
    category: AttackCategory
    payload: str
    description: str = ""
    level: int = 1
    attack_type: str = "prompt"
    domain: str = "general"
    risk_score: float = 0.5
    strategy_goal: str = ""
    strategy_method: str = ""
    strategy_vulnerability: str = ""
    strategy_steps: List[str] = field(default_factory=list)
