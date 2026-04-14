"""
Trade-off Analyzer — Measures the cost of applying mitigations:
  * security_gain: reduction in ISR/DLS/IDI
  * accuracy_drop: degradation in legitimate response quality
  * latency_increase: added processing time (ms)
  * false_positive_rate: benign queries blocked/modified

Each mitigation technique has a known cost profile in the KB.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# ── Cost profiles per technique layer ─────────────────────────────────────
# Format: (latency_ms, accuracy_drop, false_positive_rate)

LAYER_COST_PROFILES: Dict[str, tuple] = {
    "prompt":       (5,   0.02, 0.01),   # very cheap
    "input":        (15,  0.05, 0.04),   # regex/filters have moderate FP
    "context":      (25,  0.08, 0.03),   # context isolation has quality cost
    "output":       (30,  0.10, 0.05),   # output filtering can over-block
    "tool":         (10,  0.03, 0.02),   # tool restrictions are targeted
    "architecture": (50,  0.15, 0.06),   # structural changes are expensive
}

COMPLEXITY_MULTIPLIERS: Dict[str, float] = {
    "low":    1.0,
    "medium": 1.5,
    "high":   2.2,
}


@dataclass
class TechniqueTradeoff:
    technique_id: str
    technique_name: str
    layer: str
    security_gain: float       # 0-1 reduction in attack success
    accuracy_drop: float       # 0-1 drop in response quality
    latency_increase_ms: int   # added latency
    false_positive_rate: float # fraction of benign queries affected
    net_score: float           # composite: security_gain - penalty

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "layer": self.layer,
            "security_gain": round(self.security_gain, 3),
            "accuracy_drop": round(self.accuracy_drop, 3),
            "latency_increase_ms": self.latency_increase_ms,
            "false_positive_rate": round(self.false_positive_rate, 3),
            "net_score": round(self.net_score, 3),
        }


@dataclass
class TradeoffReport:
    security_gain: float
    accuracy_drop: float
    latency_increase: int      # total ms
    false_positive_rate: float
    net_benefit: float         # security_gain - weighted_costs
    efficiency_rating: str     # excellent / good / fair / poor
    per_technique: List[TechniqueTradeoff]
    recommendation: str
    pareto_optimal: bool       # True if on Pareto frontier (high security, low cost)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "security_gain": round(self.security_gain, 3),
            "accuracy_drop": round(self.accuracy_drop, 3),
            "latency_increase": self.latency_increase,
            "false_positive_rate": round(self.false_positive_rate, 3),
            "net_benefit": round(self.net_benefit, 3),
            "efficiency_rating": self.efficiency_rating,
            "pareto_optimal": self.pareto_optimal,
            "recommendation": self.recommendation,
            "per_technique": [t.to_dict() for t in self.per_technique],
        }


def analyze_tradeoffs(
    mitigation_steps: List[Dict[str, Any]],
    original_isr: float,
    estimated_residual_isr: float,
) -> TradeoffReport:
    """
    Compute trade-off profile for a set of applied mitigation techniques.
    """
    per_technique: List[TechniqueTradeoff] = []
    total_latency = 0
    total_accuracy_drop = 0.0
    total_fp = 0.0

    for step in mitigation_steps:
        layer = step.get("layer", "prompt")
        complexity = step.get("complexity", "medium")
        effectiveness = step.get("estimated_effectiveness", 0.5)

        base_latency, base_acc_drop, base_fp = LAYER_COST_PROFILES.get(layer, (10, 0.05, 0.03))
        multiplier = COMPLEXITY_MULTIPLIERS.get(complexity, 1.0)

        latency = int(base_latency * multiplier * random.uniform(0.8, 1.2))
        acc_drop = base_acc_drop * multiplier * random.uniform(0.7, 1.3)
        fp_rate = base_fp * multiplier * random.uniform(0.6, 1.4)

        security = effectiveness * random.uniform(0.85, 1.0)
        net = security - (acc_drop * 0.4 + fp_rate * 0.3)

        total_latency += latency
        total_accuracy_drop = min(0.95, total_accuracy_drop + acc_drop * 0.6)
        total_fp = min(0.95, total_fp + fp_rate * 0.5)

        per_technique.append(TechniqueTradeoff(
            technique_id=step.get("technique_id", "unknown"),
            technique_name=step.get("technique_name", "Unknown"),
            layer=layer,
            security_gain=round(security, 3),
            accuracy_drop=round(acc_drop, 3),
            latency_increase_ms=latency,
            false_positive_rate=round(fp_rate, 3),
            net_score=round(net, 3),
        ))

    # Overall metrics
    security_gain = max(0.0, original_isr - estimated_residual_isr)
    net_benefit = security_gain - (total_accuracy_drop * 0.35 + total_fp * 0.25)

    # Efficiency rating
    if net_benefit >= 0.4:
        rating = "excellent"
    elif net_benefit >= 0.25:
        rating = "good"
    elif net_benefit >= 0.10:
        rating = "fair"
    else:
        rating = "poor"

    # Pareto optimal: high security gain with low cost
    pareto_optimal = security_gain >= 0.3 and total_accuracy_drop < 0.15 and total_latency < 200

    recommendation = (
        "Excellent trade-off — high security gain with minimal accuracy and latency costs."
        if rating == "excellent"
        else "Good trade-off — consider removing high-complexity techniques that add latency without proportional security gain."
        if rating == "good"
        else "Fair trade-off — accuracy drop is noticeable. Prefer prompt-layer and input-layer techniques over output-layer for better balance."
        if rating == "fair"
        else "Poor trade-off — mitigation is too expensive relative to security gain. Strip low-effectiveness techniques and consolidate layers."
    )

    return TradeoffReport(
        security_gain=round(security_gain, 3),
        accuracy_drop=round(total_accuracy_drop, 3),
        latency_increase=total_latency,
        false_positive_rate=round(total_fp, 3),
        net_benefit=round(net_benefit, 3),
        efficiency_rating=rating,
        per_technique=sorted(per_technique, key=lambda t: t.net_score, reverse=True),
        recommendation=recommendation,
        pareto_optimal=pareto_optimal,
    )
