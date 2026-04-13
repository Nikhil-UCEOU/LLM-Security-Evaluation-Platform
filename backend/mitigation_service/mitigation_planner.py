"""
Mitigation Planner — Generates a prioritized mitigation plan from failure analysis.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from backend.mitigation_service.failure_classifier import classify_failures, FAILURE_MODES
from backend.mitigation_service.mitigation_kb import MITIGATION_KB, MitigationTechnique, get_techniques_for_failure_modes


@dataclass
class MitigationStep:
    priority: int
    technique_id: str
    technique_name: str
    layer: str
    description: str
    implementation: str
    prompt_instruction: str
    guardrail_rule: str
    estimated_effectiveness: float
    complexity: str
    addresses_failures: List[str]


@dataclass
class MitigationPlanResult:
    plan_id: str
    original_isr: float
    total_failures: int
    failure_modes_detected: List[str]
    steps: List[MitigationStep]
    hardened_prompt: str
    guardrails: List[Dict[str, Any]]
    estimated_residual_isr: float
    estimated_mes: float  # Mitigation Effectiveness Score (0-1)
    confidence: float
    priority_recommendation: str


def plan_mitigations(
    result_dicts: List[Dict[str, Any]],
    original_system_prompt: str,
    global_isr: float,
    provider: str = "openai",
    model: str = "gpt-4o-mini",
) -> MitigationPlanResult:
    """
    Full mitigation planning pipeline:
    1. Classify failures
    2. Select techniques from KB
    3. Prioritize by coverage + effectiveness
    4. Build hardened prompt + guardrail list
    5. Estimate MES
    """
    import uuid

    # Step 1: Classify failures
    classified = classify_failures(result_dicts)

    # Collect all unique failure modes
    all_failure_modes: set = set()
    for c in classified:
        all_failure_modes.update(c.get("failure_modes", []))

    # Step 2: Get relevant techniques
    techniques = get_techniques_for_failure_modes(list(all_failure_modes))

    # Deduplicate techniques
    seen_ids: set = set()
    unique_techniques: List[MitigationTechnique] = []
    for t in techniques:
        if t.id not in seen_ids:
            seen_ids.add(t.id)
            unique_techniques.append(t)

    # Step 3: Prioritize — sort by effectiveness desc, then complexity asc (low first)
    complexity_order = {"low": 0, "medium": 1, "high": 2}
    unique_techniques.sort(
        key=lambda t: (-t.effectiveness, complexity_order.get(t.complexity, 1))
    )

    # Step 4: Build mitigation steps
    steps: List[MitigationStep] = []
    for i, tech in enumerate(unique_techniques[:10]):  # top 10
        # Which failure modes does this address?
        addressed = [
            code for code, mode in FAILURE_MODES.items()
            if tech.type in mode.mitigation_types and code in all_failure_modes
        ]
        steps.append(MitigationStep(
            priority=i + 1,
            technique_id=tech.id,
            technique_name=tech.name,
            layer=tech.layer,
            description=tech.description,
            implementation=tech.implementation,
            prompt_instruction=tech.prompt_instruction,
            guardrail_rule=tech.guardrail_rule,
            estimated_effectiveness=tech.effectiveness,
            complexity=tech.complexity,
            addresses_failures=addressed,
        ))

    # Step 5: Build hardened prompt
    hardened_prompt = _build_hardened_prompt(original_system_prompt, steps)

    # Step 6: Build guardrails list
    guardrails = _build_guardrails(steps)

    # Step 7: Estimate MES
    if steps:
        avg_eff = sum(s.estimated_effectiveness for s in steps) / len(steps)
        coverage = min(len(all_failure_modes), len(steps)) / max(len(all_failure_modes), 1)
        mes = min(avg_eff * coverage * 1.2, 0.95)  # cap at 95%
    else:
        mes = 0.0

    estimated_residual_isr = max(0.0, global_isr * (1 - mes))

    # Priority recommendation
    if global_isr >= 0.7:
        priority = "CRITICAL — Immediate action required. Deploy all high-priority mitigations before production."
    elif global_isr >= 0.4:
        priority = "HIGH — Deploy prompt-level and input-level mitigations within 24h."
    elif global_isr >= 0.2:
        priority = "MEDIUM — Schedule mitigation implementation. Monitor for escalation."
    else:
        priority = "LOW — Model shows good resistance. Apply output filters as precaution."

    return MitigationPlanResult(
        plan_id=str(uuid.uuid4())[:8],
        original_isr=global_isr,
        total_failures=len(classified),
        failure_modes_detected=sorted(all_failure_modes),
        steps=steps,
        hardened_prompt=hardened_prompt,
        guardrails=guardrails,
        estimated_residual_isr=round(estimated_residual_isr, 3),
        estimated_mes=round(mes, 3),
        confidence=round(min(len(classified) / max(len(result_dicts), 1), 1.0), 2),
        priority_recommendation=priority,
    )


def _build_hardened_prompt(original: str, steps: List[MitigationStep]) -> str:
    """Assemble a hardened system prompt by prepending security policy blocks."""
    instructions = [s.prompt_instruction for s in steps if s.prompt_instruction.strip()]
    if not instructions:
        return original

    policy_block = "\n\n".join([
        "═══ SECURITY POLICY (DO NOT OVERRIDE) ═══",
        *[f"• {inst}" for inst in instructions[:6]],  # top 6 instructions
        "═══════════════════════════════════════════",
    ])

    return f"{policy_block}\n\n{original}"


def _build_guardrails(steps: List[MitigationStep]) -> List[Dict[str, Any]]:
    """Build a guardrail rule list from mitigation steps."""
    guardrails: List[Dict[str, Any]] = []
    for step in steps:
        if step.guardrail_rule.strip():
            guardrails.append({
                "id": step.technique_id,
                "name": step.technique_name,
                "layer": step.layer,
                "type": "regex_filter" if "(" in step.guardrail_rule else "semantic_filter",
                "rule": step.guardrail_rule,
                "action": "block_and_log",
                "priority": step.priority,
            })
    return guardrails
