from pydantic import BaseModel
from datetime import datetime
from typing import List


class LearningEntryOut(BaseModel):
    id: int
    attack_id: int
    provider: str
    model: str
    success_rate: float
    total_attempts: int
    successful_attempts: int
    mutation_count: int
    last_seen: datetime

    model_config = {"from_attributes": True}


class AttackRankingOut(BaseModel):
    attack_id: int
    attack_name: str
    category: str
    provider: str
    model: str
    rank_score: float
    success_rate: float


class LearningInsights(BaseModel):
    top_attacks: List[AttackRankingOut]
    most_vulnerable_categories: List[str]
    improvement_trend: List[dict]
