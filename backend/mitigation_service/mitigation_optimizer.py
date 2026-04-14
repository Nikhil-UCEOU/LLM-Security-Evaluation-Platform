"""
Mitigation Optimizer — Tests multiple mitigation strategy combinations and
selects the best based on effectiveness vs. side effects (Pareto optimization).

Strategy combos tested:
  A alone, B alone, A+B, A+C, B+C, A+B+C, ...
"""
from __future__ import annotations

import itertools
import random
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from backend.mitigation_service.mitigation_kb import MITIGATION_KB


# ── Strategy bundles ────────────────────────────────────────────────────────

STRATEGY_BUNDLES: Dict[str, List[str]] = {
    "minimal": ["MIT-001"],                                    # prompt hardening only
    "input_focused": ["MIT-001", "MIT-004", "MIT-005"],       # prompt + input sanitization
    "output_focused": ["MIT-001", "MIT-009", "MIT-010"],      # prompt + output filters
    "rag_hardened": ["MIT-001", "MIT-006", "MIT-007", "MIT-008"],  # prompt + context isolation
    "tool_hardened": ["MIT-001", "MIT-012", "MIT-013"],       # prompt + tool restrictions
    "balanced": ["MIT-001", "MIT-004", "MIT-009", "MIT-015"], # cross-layer balanced
    "comprehensive": ["MIT-001", "MIT-004", "MIT-005", "MIT-006", "MIT-009", "MIT-012", "MIT-015"],
    "maximum": list(MITIGATION_KB.keys())[:12],               # top 12 techniques
}


@dataclass
class StrategyResult:
    strategy_name: str
    techniques: List[str]
    estimated_isr_after: float
    accuracy_drop: float
    latency_ms: int
    false_positive_rate: float
    composite_score: float      # higher = better overall
    rank: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy_name": self.strategy_name,
            "techniques": self.techniques,
            "techniques_count": len(self.techniques),
            "estimated_isr_after": round(self.estimated_isr_after, 3),
            "accuracy_drop": round(self.accuracy_drop, 3),
            "latency_ms": self.latency_ms,
            "false_positive_rate": round(self.false_positive_rate, 3),
            "composite_score": round(self.composite_score, 3),
            "rank": self.rank,
        }


@dataclass
class OptimizationResult:
    best_strategy: str
    best_techniques: List[str]
    winner_score: float
    all_strategies: List[StrategyResult]
    optimization_target: str    # "balanced" | "security_first" | "quality_first"
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "best_strategy": self.best_strategy,
            "best_techniques": self.best_techniques,
            "winner_score": round(self.winner_score, 3),
            "optimization_target": self.optimization_target,
            "recommendation": self.recommendation,
            "all_strategies": [s.to_dict() for s in self.all_strategies],
        }


def _score_strategy(
    technique_ids: List[str],
    original_isr: float,
    optimization_target: str,
) -> StrategyResult:
    """Simulate effectiveness and costs for a technique bundle."""
    n = len(technique_ids)
    avg_effectiveness = sum(
        MITIGATION_KB[t].effectiveness if t in MITIGATION_KB else 0.5
        for t in technique_ids
    ) / max(1, n)

    # Diminishing returns for more techniques
    coverage_bonus = min(0.3, n * 0.04)
    isr_reduction = avg_effectiveness * (1 - original_isr * 0.1) + coverage_bonus
    isr_after = max(0.0, original_isr - isr_reduction + random.uniform(-0.02, 0.02))

    # Cost grows with complexity
    accuracy_drop = min(0.5, n * 0.025 * random.uniform(0.8, 1.2))
    latency_ms = int(n * 18 * random.uniform(0.7, 1.4))
    fp_rate = min(0.4, n * 0.015 * random.uniform(0.5, 1.5))

    security_gain = original_isr - isr_after

    if optimization_target == "security_first":
        composite = security_gain * 0.70 - accuracy_drop * 0.15 - fp_rate * 0.15
    elif optimization_target == "quality_first":
        composite = security_gain * 0.40 - accuracy_drop * 0.35 - fp_rate * 0.25
    else:  # balanced
        composite = security_gain * 0.55 - accuracy_drop * 0.25 - fp_rate * 0.20

    return StrategyResult(
        strategy_name="",
        techniques=technique_ids,
        estimated_isr_after=round(isr_after, 3),
        accuracy_drop=round(accuracy_drop, 3),
        latency_ms=latency_ms,
        false_positive_rate=round(fp_rate, 3),
        composite_score=round(composite, 4),
    )


def optimize_mitigation(
    original_isr: float,
    failure_modes: List[str],
    optimization_target: str = "balanced",
) -> OptimizationResult:
    """
    Test all predefined strategy bundles and rank them.
    Returns the best strategy plus full comparison table.
    """
    results: List[StrategyResult] = []

    for name, techniques in STRATEGY_BUNDLES.items():
        r = _score_strategy(techniques, original_isr, optimization_target)
        r.strategy_name = name
        results.append(r)

    # Rank by composite score
    results.sort(key=lambda r: r.composite_score, reverse=True)
    for i, r in enumerate(results):
        r.rank = i + 1

    best = results[0]
    recommendation = (
        f"Optimal strategy: '{best.strategy_name}' — "
        f"reduces ISR to {round(best.estimated_isr_after * 100)}% "
        f"with {round(best.accuracy_drop * 100)}% accuracy impact and {best.latency_ms}ms latency. "
        f"Target: {optimization_target}."
    )

    return OptimizationResult(
        best_strategy=best.strategy_name,
        best_techniques=best.techniques,
        winner_score=best.composite_score,
        all_strategies=results,
        optimization_target=optimization_target,
        recommendation=recommendation,
    )
