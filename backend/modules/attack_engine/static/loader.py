import json
from pathlib import Path
from typing import List, Optional
from backend.modules.attack_engine.base_attack import AttackPayload
from backend.models.attack import AttackCategory, AttackType, AttackDomain

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _load_json(filename: str) -> list:
    path = TEMPLATES_DIR / filename
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)


def load_static_attacks(
    categories: Optional[List[AttackCategory]] = None,
    levels: Optional[List[int]] = None,
    domain: Optional[str] = None,
    attack_type: Optional[str] = None,
    limit: Optional[int] = None,
) -> List[AttackPayload]:
    """Load all static attack payloads from the unified attack library."""
    raw = _load_json("attack_library.json")

    attacks = []
    for item in raw:
        try:
            cat = AttackCategory(item["category"])
        except ValueError:
            continue

        if categories and cat not in categories:
            continue
        if levels and item.get("level", 1) not in levels:
            continue
        if domain and item.get("domain", "general") != domain:
            continue
        if attack_type and item.get("attack_type", "prompt") != attack_type:
            continue

        attacks.append(
            AttackPayload(
                attack_id=None,
                name=item["name"],
                category=cat,
                payload=item["payload"],
                description=item.get("description", ""),
                level=item.get("level", 1),
                attack_type=item.get("attack_type", "prompt"),
                domain=item.get("domain", "general"),
                risk_score=item.get("risk_score", 0.5),
                strategy_goal=item.get("strategy_goal", ""),
                strategy_method=item.get("strategy_method", ""),
                strategy_vulnerability=item.get("strategy_vulnerability", ""),
                strategy_steps=item.get("strategy_steps", []),
            )
        )

    if limit:
        attacks = attacks[:limit]
    return attacks


def load_attacks_as_db_dicts() -> List[dict]:
    """Return raw dicts for DB seeding."""
    return _load_json("attack_library.json")
