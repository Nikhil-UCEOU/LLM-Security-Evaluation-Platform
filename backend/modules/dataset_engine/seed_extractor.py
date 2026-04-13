"""
Seed Extractor — Selects high-quality, diverse seeds from datasets.
Rules:
  - Remove duplicates (hash-based)
  - Cluster by strategy type
  - Select top 50-100 diverse seeds
  - Output to datasets/seed/seed_attacks.json
  - NEVER feeds raw dataset into attack engine
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict

from backend.modules.dataset_engine.dataset_loader import (
    NormalizedAttack, load_all_datasets, DATASETS_ROOT
)

SEED_OUTPUT_PATH = DATASETS_ROOT / "seed" / "seed_attacks.json"


# ── Deduplication ──────────────────────────────────────────────────────────

def _prompt_hash(prompt: str) -> str:
    """Short hash of lowercased, stripped prompt."""
    normalized = " ".join(prompt.lower().split())
    return hashlib.md5(normalized.encode()).hexdigest()[:12]


def deduplicate(attacks: List[NormalizedAttack]) -> List[NormalizedAttack]:
    """Remove near-duplicate prompts based on content hash."""
    seen: set = set()
    unique: List[NormalizedAttack] = []
    for a in attacks:
        h = _prompt_hash(a.prompt)
        if h not in seen:
            seen.add(h)
            unique.append(a)
    return unique


# ── Quality scoring ────────────────────────────────────────────────────────

def _score_attack(attack: NormalizedAttack) -> float:
    """
    Score an attack for seed quality (0-1).
    Factors: length, strategy diversity, severity, tag richness.
    """
    score = 0.0

    # Prompt length — too short = weak, too long = noisy
    prompt_len = len(attack.prompt)
    if 50 <= prompt_len <= 500:
        score += 0.30
    elif 30 <= prompt_len < 50 or 500 < prompt_len <= 800:
        score += 0.15

    # Strategy specified
    if attack.strategy and attack.strategy != "unknown":
        score += 0.25

    # Severity weight
    sev_map = {"critical": 0.30, "high": 0.25, "medium": 0.15, "low": 0.05}
    score += sev_map.get(attack.severity, 0.10)

    # Tag richness
    score += min(len(attack.tags) * 0.05, 0.15)

    return round(min(score, 1.0), 3)


# ── Diversity clustering ───────────────────────────────────────────────────

def _cluster_by_strategy(
    attacks: List[NormalizedAttack],
) -> Dict[str, List[NormalizedAttack]]:
    """Group attacks by (category, strategy) for diverse selection."""
    clusters: Dict[str, List[NormalizedAttack]] = {}
    for a in attacks:
        key = f"{a.category}::{a.strategy}"
        clusters.setdefault(key, []).append(a)
    return clusters


def _select_diverse(
    clusters: Dict[str, List[NormalizedAttack]],
    target_n: int = 75,
) -> List[NormalizedAttack]:
    """
    Round-robin selection across strategy clusters to maximize diversity.
    Within each cluster, pick by quality score descending.
    """
    # Sort each cluster by quality score
    sorted_clusters = {
        k: sorted(v, key=_score_attack, reverse=True)
        for k, v in clusters.items()
    }
    cluster_lists = list(sorted_clusters.values())
    selected: List[NormalizedAttack] = []
    i = 0
    while len(selected) < target_n and any(cluster_lists):
        bucket = cluster_lists[i % len(cluster_lists)]
        if bucket:
            candidate = bucket.pop(0)
            selected.append(candidate)
        i += 1
        # Remove empty clusters
        cluster_lists = [c for c in cluster_lists if c]
    return selected


# ── Public API ─────────────────────────────────────────────────────────────

def extract_seeds(
    categories: Optional[List[str]] = None,
    target_n: int = 75,
    min_quality: float = 0.3,
) -> List[Dict[str, Any]]:
    """
    Full pipeline: load → deduplicate → quality filter → cluster → select diverse seeds.
    Returns list of seed dicts.
    """
    all_data = load_all_datasets(categories=categories)
    all_attacks: List[NormalizedAttack] = []
    for attacks in all_data.values():
        all_attacks.extend(attacks)

    # Deduplicate
    unique = deduplicate(all_attacks)

    # Quality filter
    quality_filtered = [a for a in unique if _score_attack(a) >= min_quality]
    if not quality_filtered:
        quality_filtered = unique  # fallback: use all if nothing passes threshold

    # Cluster + diverse selection
    clusters = _cluster_by_strategy(quality_filtered)
    seeds = _select_diverse(clusters, target_n=target_n)

    # Annotate with quality score
    result = []
    for s in seeds:
        d = s.to_dict()
        d["quality_score"] = _score_attack(s)
        result.append(d)

    return result


def save_seeds(seeds: List[Dict[str, Any]]) -> str:
    """Persist seeds to datasets/seed/seed_attacks.json."""
    SEED_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SEED_OUTPUT_PATH.write_text(
        json.dumps(seeds, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(SEED_OUTPUT_PATH)


def load_seeds() -> List[Dict[str, Any]]:
    """Load previously saved seeds from disk."""
    if not SEED_OUTPUT_PATH.exists():
        return []
    return json.loads(SEED_OUTPUT_PATH.read_text(encoding="utf-8"))


def run_seed_pipeline(
    categories: Optional[List[str]] = None,
    target_n: int = 75,
    force_refresh: bool = False,
) -> List[Dict[str, Any]]:
    """
    Run seed extraction pipeline.
    Uses cached seeds unless force_refresh=True.
    """
    if not force_refresh and SEED_OUTPUT_PATH.exists():
        return load_seeds()
    seeds = extract_seeds(categories=categories, target_n=target_n)
    save_seeds(seeds)
    return seeds
