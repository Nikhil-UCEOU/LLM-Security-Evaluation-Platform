"""
Defense-in-Depth Planner — Combines multiple mitigations into a layered
defense architecture. Each layer acts as an independent control that must
be bypassed before the next, creating a compound barrier.

Layers: Input → Prompt → Context → Model → Output → Tool → Monitoring
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from backend.mitigation_service.mitigation_kb import MITIGATION_KB


# ── Layer definitions ────────────────────────────────────────────────────────

DEFENSE_LAYERS: Dict[str, Dict[str, Any]] = {
    "L1_input":        {"order": 1, "name": "Input Validation Layer",     "position": "pre-model",  "techniques": ["MIT-004", "MIT-005"]},
    "L2_prompt":       {"order": 2, "name": "System Prompt Layer",        "position": "pre-model",  "techniques": ["MIT-001", "MIT-002", "MIT-003"]},
    "L3_context":      {"order": 3, "name": "Context Isolation Layer",    "position": "pre-model",  "techniques": ["MIT-006", "MIT-007", "MIT-008"]},
    "L4_model":        {"order": 4, "name": "Model Behavior Layer",       "position": "at-model",   "techniques": ["MIT-015", "MIT-011"]},
    "L5_output":       {"order": 5, "name": "Output Filtering Layer",     "position": "post-model", "techniques": ["MIT-009", "MIT-010"]},
    "L6_tool":         {"order": 6, "name": "Tool Restriction Layer",     "position": "post-model", "techniques": ["MIT-012", "MIT-013", "MIT-014"]},
    "L7_monitoring":   {"order": 7, "name": "Monitoring & Alerting Layer","position": "continuous", "techniques": ["MIT-016", "MIT-017", "MIT-018"]},
}


@dataclass
class LayerConfig:
    layer_id: str
    layer_name: str
    order: int
    position: str
    active_techniques: List[str]
    bypass_probability: float   # probability an attacker can bypass this layer
    coverage_score: float       # 0-1 how well this layer is configured

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_id": self.layer_id,
            "layer_name": self.layer_name,
            "order": self.order,
            "position": self.position,
            "active_techniques": self.active_techniques,
            "bypass_probability": round(self.bypass_probability, 3),
            "coverage_score": round(self.coverage_score, 3),
        }


@dataclass
class DefenseArchitecture:
    layers: List[LayerConfig]
    compound_bypass_probability: float   # probability of bypassing ALL layers
    overall_coverage: float              # weighted average coverage
    weakest_layer: str
    strongest_layer: str
    missing_layers: List[str]
    architecture_grade: str              # A-F
    recommendation: str
    attack_resistance: Dict[str, float]  # attack_type → resistance score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layers": [l.to_dict() for l in self.layers],
            "compound_bypass_probability": round(self.compound_bypass_probability, 4),
            "overall_coverage": round(self.overall_coverage, 3),
            "weakest_layer": self.weakest_layer,
            "strongest_layer": self.strongest_layer,
            "missing_layers": self.missing_layers,
            "architecture_grade": self.architecture_grade,
            "recommendation": self.recommendation,
            "attack_resistance": {k: round(v, 3) for k, v in self.attack_resistance.items()},
        }


def build_defense_architecture(
    applied_techniques: List[str],
    failure_modes: List[str],
) -> DefenseArchitecture:
    """
    Build a layered defense architecture from applied techniques.
    """
    layer_configs: List[LayerConfig] = []
    active_set = set(applied_techniques)

    for layer_id, layer_def in DEFENSE_LAYERS.items():
        layer_techniques = [t for t in layer_def["techniques"] if t in active_set]
        total_layer_tech = len(layer_def["techniques"])
        coverage = len(layer_techniques) / max(1, total_layer_tech)

        # Bypass probability decreases with coverage
        bypass_prob = max(0.02, 1.0 - coverage * 0.85)

        # Add noise based on failure modes
        if any(fm in ("direct_override", "role_confusion") for fm in failure_modes):
            if layer_id in ("L2_prompt",):
                bypass_prob = min(1.0, bypass_prob * 1.3)  # prompt layer harder to defend

        layer_configs.append(LayerConfig(
            layer_id=layer_id,
            layer_name=layer_def["name"],
            order=layer_def["order"],
            position=layer_def["position"],
            active_techniques=layer_techniques,
            bypass_probability=round(bypass_prob, 3),
            coverage_score=round(coverage, 3),
        ))

    layer_configs.sort(key=lambda l: l.order)

    # Compound bypass: multiply all bypass probs (like series locks)
    compound_bypass = 1.0
    for lc in layer_configs:
        compound_bypass *= lc.bypass_probability

    overall_coverage = sum(l.coverage_score for l in layer_configs) / len(layer_configs)

    # Find weakest/strongest
    weakest = min(layer_configs, key=lambda l: l.coverage_score)
    strongest = max(layer_configs, key=lambda l: l.coverage_score)

    # Missing layers (no techniques active)
    missing = [l.layer_name for l in layer_configs if not l.active_techniques]

    # Architecture grade
    if overall_coverage >= 0.80:
        grade = "A"
    elif overall_coverage >= 0.65:
        grade = "B"
    elif overall_coverage >= 0.45:
        grade = "C"
    elif overall_coverage >= 0.25:
        grade = "D"
    else:
        grade = "F"

    # Per-attack-type resistance
    attack_resistance = {
        "jailbreak":          min(1.0, layer_configs[1].coverage_score * 0.8 + layer_configs[3].coverage_score * 0.2),
        "prompt_injection":   min(1.0, layer_configs[0].coverage_score * 0.6 + layer_configs[1].coverage_score * 0.4),
        "rag_poisoning":      min(1.0, layer_configs[2].coverage_score * 0.7 + layer_configs[4].coverage_score * 0.3),
        "tool_misuse":        min(1.0, layer_configs[5].coverage_score * 0.8 + layer_configs[6].coverage_score * 0.2),
        "data_leakage":       min(1.0, layer_configs[4].coverage_score * 0.7 + layer_configs[6].coverage_score * 0.3),
        "multi_turn_drift":   min(1.0, layer_configs[2].coverage_score * 0.5 + layer_configs[6].coverage_score * 0.5),
    }

    recommendation = (
        "Defense-in-depth architecture is strong — all layers have active techniques. Monitor for evolving bypass strategies."
        if not missing
        else f"Gaps detected in: {', '.join(missing[:3])}. Add techniques to these layers to close attack vectors."
        if len(missing) <= 3
        else "Major architecture gaps — more than half of defense layers are unprotected. Implement a minimum baseline across all layers."
    )

    return DefenseArchitecture(
        layers=layer_configs,
        compound_bypass_probability=round(compound_bypass, 4),
        overall_coverage=round(overall_coverage, 3),
        weakest_layer=weakest.layer_name,
        strongest_layer=strongest.layer_name,
        missing_layers=missing,
        architecture_grade=grade,
        recommendation=recommendation,
        attack_resistance=attack_resistance,
    )
