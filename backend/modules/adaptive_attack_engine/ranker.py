from typing import List, Dict, Any
from backend.modules.attack_engine.base_attack import AttackPayload

SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "none": 0.0,
}


def rank_attacks(
    attacks: List[AttackPayload],
    historical_data: List[Dict[str, Any]],
) -> List[AttackPayload]:
    """
    Rank attacks by predicted effectiveness using historical success rates.
    Returns attacks sorted from most to least effective.
    """
    history_map: Dict[str, float] = {}
    for entry in historical_data:
        name = entry.get("attack_name", "")
        rate = entry.get("success_rate", 0.0)
        severity = entry.get("severity", "none")
        score = rate * 0.7 + SEVERITY_WEIGHTS.get(severity, 0.0) * 0.3
        history_map[name] = score

    def score_attack(attack: AttackPayload) -> float:
        if attack.name in history_map:
            return history_map[attack.name]
        # Default score for unknown attacks — slightly randomized for exploration
        import random
        return 0.3 + random.uniform(0, 0.2)

    return sorted(attacks, key=score_attack, reverse=True)
