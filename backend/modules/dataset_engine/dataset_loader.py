"""
Dataset Loader — Parses multiple dataset formats and normalizes into a unified schema.
Supports: JSON arrays, JSONL, CSV, plain text (one prompt per line).
Does NOT feed directly into the attack engine — output is seeds/benchmark only.
"""
from __future__ import annotations

import json
import csv
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path

# ── Base datasets directory ────────────────────────────────────────────────

DATASETS_ROOT = Path(__file__).resolve().parents[3] / "datasets"


@dataclass
class NormalizedAttack:
    """Unified schema for any attack loaded from any dataset format."""
    id: str
    prompt: str
    category: str          # prompt_injection | jailbreak | rag_poisoning | api_abuse
    strategy: str          # attack sub-type
    source: str            # dataset name
    severity: str          # critical | high | medium | low
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "category": self.category,
            "strategy": self.strategy,
            "source": self.source,
            "severity": self.severity,
            "tags": self.tags,
            "metadata": self.metadata,
        }


# ── Format parsers ─────────────────────────────────────────────────────────

def _parse_json_array(data: list, source: str) -> List[NormalizedAttack]:
    results = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        prompt = item.get("prompt") or item.get("text") or item.get("attack") or item.get("input", "")
        if not prompt:
            continue
        results.append(NormalizedAttack(
            id=item.get("id", f"{source.upper()}-{i+1:03d}"),
            prompt=prompt,
            category=item.get("category", "prompt_injection"),
            strategy=item.get("strategy", "unknown"),
            source=item.get("source", source),
            severity=item.get("severity", "medium"),
            tags=item.get("tags", []),
            metadata={k: v for k, v in item.items()
                      if k not in ("id", "prompt", "category", "strategy", "source", "severity", "tags")},
        ))
    return results


def _parse_jsonl(text: str, source: str) -> List[NormalizedAttack]:
    results = []
    for i, line in enumerate(text.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            results.extend(_parse_json_array([item], source))
        except json.JSONDecodeError:
            pass
    return results


def _parse_csv(text: str, source: str) -> List[NormalizedAttack]:
    results = []
    reader = csv.DictReader(text.splitlines())
    for i, row in enumerate(reader):
        prompt = row.get("prompt") or row.get("text") or row.get("attack", "")
        if not prompt:
            continue
        results.append(NormalizedAttack(
            id=f"{source.upper()}-{i+1:03d}",
            prompt=prompt,
            category=row.get("category", "prompt_injection"),
            strategy=row.get("strategy", "unknown"),
            source=source,
            severity=row.get("severity", "medium"),
            tags=[t.strip() for t in row.get("tags", "").split(",") if t.strip()],
            metadata={k: v for k, v in row.items()
                      if k not in ("prompt", "category", "strategy", "severity", "tags")},
        ))
    return results


def _parse_text(text: str, source: str, category: str = "prompt_injection") -> List[NormalizedAttack]:
    results = []
    for i, line in enumerate(text.strip().splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        results.append(NormalizedAttack(
            id=f"{source.upper()}-{i+1:03d}",
            prompt=line,
            category=category,
            strategy="unknown",
            source=source,
            severity="medium",
        ))
    return results


# ── Main loader ────────────────────────────────────────────────────────────

def load_dataset_file(path: str, source: Optional[str] = None) -> List[NormalizedAttack]:
    """Load a single dataset file. Auto-detects format from extension."""
    p = Path(path)
    if not p.exists():
        return []

    src = source or p.parent.name
    raw = p.read_text(encoding="utf-8")

    if p.suffix == ".json":
        data = json.loads(raw)
        if isinstance(data, list):
            return _parse_json_array(data, src)
        elif isinstance(data, dict) and "attacks" in data:
            return _parse_json_array(data["attacks"], src)
        return []
    elif p.suffix in (".jsonl", ".ndjson"):
        return _parse_jsonl(raw, src)
    elif p.suffix == ".csv":
        return _parse_csv(raw, src)
    elif p.suffix == ".txt":
        return _parse_text(raw, src)
    return []


def load_category(category: str) -> List[NormalizedAttack]:
    """Load all dataset files in a category folder."""
    cat_dir = DATASETS_ROOT / category
    if not cat_dir.exists():
        return []
    results = []
    for f in cat_dir.iterdir():
        if f.suffix in (".json", ".jsonl", ".csv", ".txt"):
            results.extend(load_dataset_file(str(f), source=category))
    return results


def load_all_datasets(
    categories: Optional[List[str]] = None,
) -> Dict[str, List[NormalizedAttack]]:
    """Load all datasets, optionally filtered by category names."""
    available_cats = [
        d.name for d in DATASETS_ROOT.iterdir()
        if d.is_dir() and d.name not in ("seed", "benchmark")
    ]
    if categories:
        available_cats = [c for c in available_cats if c in categories]

    return {cat: load_category(cat) for cat in available_cats}


def get_available_datasets() -> List[Dict[str, Any]]:
    """Return metadata about available datasets (for UI dropdown)."""
    result = []
    for d in sorted(DATASETS_ROOT.iterdir()):
        if not d.is_dir() or d.name in ("seed", "benchmark"):
            continue
        files = list(d.glob("*.json")) + list(d.glob("*.jsonl")) + list(d.glob("*.csv"))
        attacks = load_category(d.name)
        result.append({
            "name": d.name,
            "label": d.name.replace("_", " ").title(),
            "files": len(files),
            "total_attacks": len(attacks),
            "categories": list({a.category for a in attacks}),
            "severities": {
                sev: sum(1 for a in attacks if a.severity == sev)
                for sev in ("critical", "high", "medium", "low")
            },
        })
    return result
