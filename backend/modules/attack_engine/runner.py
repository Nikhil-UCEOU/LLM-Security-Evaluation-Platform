import asyncio
from typing import List, Optional
from dataclasses import dataclass

from backend.modules.attack_engine.base_attack import AttackPayload
from backend.modules.attack_engine.static.loader import load_static_attacks
from backend.modules.gateway.base_provider import LLMConfig, LLMResponse
from backend.modules.gateway import registry
from backend.models.attack import AttackCategory


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
    """Build the full attack list from static + optional extra attacks."""
    static = load_static_attacks(categories=categories, limit=max_attacks)
    extra = extra_attacks or []
    combined = static + extra
    return combined[:max_attacks]
