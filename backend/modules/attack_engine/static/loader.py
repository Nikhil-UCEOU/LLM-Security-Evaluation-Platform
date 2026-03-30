import json
from pathlib import Path
from typing import List, Optional
from backend.modules.attack_engine.base_attack import AttackPayload
from backend.models.attack import AttackCategory

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _load_json(filename: str) -> list:
    path = TEMPLATES_DIR / filename
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)


def load_static_attacks(
    categories: Optional[List[AttackCategory]] = None,
    limit: Optional[int] = None,
) -> List[AttackPayload]:
    """Load all static attack payloads from JSON libraries."""
    raw = _load_json("injection_library.json") + _load_json("jailbreak_library.json")

    attacks = []
    for item in raw:
        try:
            cat = AttackCategory(item["category"])
        except ValueError:
            continue
        if categories and cat not in categories:
            continue
        attacks.append(
            AttackPayload(
                attack_id=None,
                name=item["name"],
                category=cat,
                payload=item["payload"],
                description=item.get("description", ""),
            )
        )

    if limit:
        attacks = attacks[:limit]
    return attacks
