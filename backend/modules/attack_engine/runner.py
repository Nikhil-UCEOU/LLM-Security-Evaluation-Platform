import asyncio
import json
import random
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

from backend.modules.attack_engine.base_attack import AttackPayload
from backend.modules.attack_engine.static.loader import load_static_attacks
from backend.modules.gateway.base_provider import LLMConfig, LLMResponse
from backend.modules.gateway import registry
from backend.models.attack import AttackCategory

# Path to the extracted seed file
_SEED_PATH = Path(__file__).resolve().parents[3] / "datasets" / "seed" / "seed_attacks.json"

# Mapping from dataset category strings → AttackCategory enum values
_CATEGORY_MAP: dict[str, str] = {
    "jailbreak": "jailbreak",
    "prompt_injection": "prompt_injection",
    "injection": "prompt_injection",
    "role_play": "role_play",
    "roleplay": "role_play",
    "indirect_injection": "indirect_injection",
    "context_manipulation": "context_manipulation",
    "multi_turn": "multi_turn",
    "multiturn": "multi_turn",
    "payload_encoding": "payload_encoding",
    "encoding": "payload_encoding",
    "rag": "rag_poisoning",
    "rag_poisoning": "rag_poisoning",
    "tool_misuse": "api_abuse",
    "api_abuse": "api_abuse",
    "cognitive": "cognitive",
    "strategy_based": "strategy_based",
}


def _str_to_category(raw: str) -> AttackCategory:
    """Safely convert a string category to AttackCategory enum, defaulting to prompt_injection."""
    mapped = _CATEGORY_MAP.get(raw.lower().strip(), "prompt_injection")
    try:
        return AttackCategory(mapped)
    except ValueError:
        return AttackCategory("prompt_injection")


def load_seed_attacks(
    categories: Optional[List[AttackCategory]] = None,
    limit: int = 50,
) -> List[AttackPayload]:
    """Load attacks from the extracted seed file and convert to AttackPayload."""
    if not _SEED_PATH.exists():
        return []

    try:
        seeds = json.loads(_SEED_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(seeds, list):
        return []

    results: List[AttackPayload] = []
    cat_values = {c.value for c in categories} if categories else None

    for s in seeds:
        if not isinstance(s, dict):
            continue
        prompt = s.get("prompt") or s.get("payload") or s.get("text", "")
        if not prompt or len(prompt) < 10:
            continue

        raw_cat = s.get("category", "prompt_injection")
        category = _str_to_category(raw_cat)

        if cat_values and category.value not in cat_values:
            continue

        severity = s.get("severity", "medium")
        level_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        level = level_map.get(severity, 2)

        results.append(AttackPayload(
            attack_id=None,
            name=s.get("name") or s.get("id", f"seed-{len(results)+1}"),
            category=category,
            payload=prompt,
            description=s.get("description", ""),
            level=level,
            attack_type=s.get("attack_type", "prompt"),
            domain=s.get("domain", "general"),
            risk_score=s.get("risk_score") or s.get("quality_score", 0.5),
            strategy_goal=s.get("strategy_goal", ""),
            strategy_method=s.get("strategy_method", ""),
            strategy_vulnerability=s.get("strategy_vulnerability", ""),
        ))

    random.shuffle(results)
    return results[:limit]


@dataclass
class AttackResult:
    payload: AttackPayload
    response: LLMResponse


async def run_attacks(
    provider: str,
    model: str,
    system_prompt: str,
    attacks: List[AttackPayload],
    concurrency: int = 5,
) -> List[AttackResult]:
    """Execute a list of attack payloads against the target LLM."""
    config = LLMConfig(model=model, system_prompt=system_prompt)
    semaphore = asyncio.Semaphore(concurrency)

    async def _run_one(attack: AttackPayload) -> AttackResult:
        async with semaphore:
            response = await registry.query(provider, attack.payload, config)
            return AttackResult(payload=attack, response=response)

    tasks = [_run_one(a) for a in attacks]
    return await asyncio.gather(*tasks)


def build_attack_list(
    categories: Optional[List[AttackCategory]] = None,
    max_attacks: int = 20,
    extra_attacks: Optional[List[AttackPayload]] = None,
) -> List[AttackPayload]:
    """Build the full attack list from static + seed + optional extra attacks.

    Priority: static templates (curated) first, then seed attacks from uploaded
    datasets (up to half the budget), then any caller-supplied extras.
    """
    static = load_static_attacks(categories=categories, limit=max_attacks)

    # Fill remaining budget with seed attacks from uploaded datasets
    seed_budget = max(0, max_attacks - len(static))
    seed = load_seed_attacks(categories=categories, limit=seed_budget) if seed_budget > 0 else []

    extra = extra_attacks or []
    combined = static + seed + extra
    return combined[:max_attacks]
