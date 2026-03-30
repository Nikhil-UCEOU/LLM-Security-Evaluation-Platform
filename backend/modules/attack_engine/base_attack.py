from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from backend.models.attack import AttackCategory


@dataclass
class AttackPayload:
    attack_id: Optional[int]
    name: str
    category: AttackCategory
    payload: str
    description: str = ""
