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

# ── Version management ─────────────────────────────────────────────────────

def get_dataset_versions() -> list:
    """Return all available dataset version directories, sorted newest first."""
    versions = []
    for d in DATASETS_ROOT.iterdir():
        if d.is_dir() and d.name.startswith("v") and d.name[1:].replace(".", "").isdigit():
            versions.append(d.name)
    return sorted(versions, reverse=True)


def get_versioned_category_path(category: str, version: Optional[str] = None) -> Path:
    """
    Resolve the path for a category.
    If version is given (e.g. 'v1'), looks in datasets/v1/<category>.
    If None, tries the latest version first, then falls back to flat layout.
    """
    if version:
        p = DATASETS_ROOT / version / category
        if p.exists():
            return p
    # Try latest versioned folder
    for ver in get_dataset_versions():
        p = DATASETS_ROOT / ver / category
        if p.exists():
            return p
    # Fallback: flat legacy layout
    return DATASETS_ROOT / category


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


def load_category(category: str, version: Optional[str] = None) -> List[NormalizedAttack]:
    """Load all dataset files in a category folder (version-aware)."""
    cat_dir = get_versioned_category_path(category, version)
    if not cat_dir.exists():
        return []
    results = []
    for f in cat_dir.iterdir():
        if f.suffix in (".json", ".jsonl", ".csv", ".txt"):
            results.extend(load_dataset_file(str(f), source=category))
    return results


def load_all_datasets(
    categories: Optional[List[str]] = None,
    version: Optional[str] = None,
) -> Dict[str, List[NormalizedAttack]]:
    """Load all datasets, optionally filtered by category names."""
    # Collect categories from flat layout + versioned layout
    flat_cats = [
        d.name for d in DATASETS_ROOT.iterdir()
        if d.is_dir() and d.name not in ("seed", "benchmark") and not d.name.startswith("v")
    ]
    versioned_cats: list = []
    active_ver = version or (get_dataset_versions()[0] if get_dataset_versions() else None)
    if active_ver:
        ver_dir = DATASETS_ROOT / active_ver
        if ver_dir.exists():
            versioned_cats = [d.name for d in ver_dir.iterdir() if d.is_dir()]

    all_cats = list({*flat_cats, *versioned_cats})
    if categories:
        all_cats = [c for c in all_cats if c in categories]

    return {cat: load_category(cat, version=version) for cat in sorted(all_cats)}


def get_available_datasets(version: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return metadata about available datasets (for UI dropdown), version-aware."""
    import json as _json

    # Determine active version
    versions = get_dataset_versions()
    active_ver = version or (versions[0] if versions else None)

    # Load version metadata if available
    ver_meta: Dict[str, Any] = {}
    if active_ver:
        meta_path = DATASETS_ROOT / active_ver / "metadata.json"
        if meta_path.exists():
            try:
                ver_meta = _json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                pass

    # Gather category dirs
    cat_dirs: Dict[str, Path] = {}
    for d in sorted(DATASETS_ROOT.iterdir()):
        if not d.is_dir() or d.name in ("seed", "benchmark") or d.name.startswith("v"):
            continue
        cat_dirs[d.name] = d
    if active_ver:
        ver_root = DATASETS_ROOT / active_ver
        if ver_root.exists():
            for d in sorted(ver_root.iterdir()):
                if d.is_dir() and d.name not in ("seed", "benchmark") and not d.name.startswith("v"):
                    cat_dirs[d.name] = d  # versioned takes precedence

    result = []
    for name, cat_dir in sorted(cat_dirs.items()):
        files = list(cat_dir.glob("*.json")) + list(cat_dir.glob("*.jsonl")) + list(cat_dir.glob("*.csv"))
        attacks = load_category(name, version=version)
        cat_meta = ver_meta.get("categories", {}).get(name, {})
        result.append({
            "name": name,
            "label": name.replace("_", " ").title(),
            "files": len(files),
            "total_attacks": len(attacks),
            "categories": list({a.category for a in attacks}),
            "severities": {
                sev: sum(1 for a in attacks if a.severity == sev)
                for sev in ("critical", "high", "medium", "low")
            },
            "description": cat_meta.get("description", ""),
            "version": active_ver or "flat",
        })
    return result


def get_version_info() -> Dict[str, Any]:
    """Return information about all dataset versions."""
    import json as _json
    versions = get_dataset_versions()
    info: List[Dict[str, Any]] = []
    for ver in versions:
        meta_path = DATASETS_ROOT / ver / "metadata.json"
        meta: Dict[str, Any] = {"version": ver}
        if meta_path.exists():
            try:
                meta.update(_json.loads(meta_path.read_text(encoding="utf-8")))
            except Exception:
                pass
        info.append(meta)
    return {"versions": versions, "latest": versions[0] if versions else None, "details": info}
