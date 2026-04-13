"""
KB Builder — Builds the Mitigation Knowledge Base from dataset attack results.
Flow: Dataset Attack → Run via evaluation → RCA → Mitigation → Store in KB JSON.
Appends new entries; supports search by failure type and retrieval of suggestions.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

KB_PATH = Path(__file__).resolve().parents[3] / "datasets" / "benchmark" / "mitigation_kb.json"


# ── KB I/O ─────────────────────────────────────────────────────────────────

def _load_kb() -> List[Dict[str, Any]]:
    if not KB_PATH.exists():
        return []
    try:
        return json.loads(KB_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save_kb(entries: List[Dict[str, Any]]) -> None:
    KB_PATH.parent.mkdir(parents=True, exist_ok=True)
    KB_PATH.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")


# ── Entry builder ──────────────────────────────────────────────────────────

def build_kb_entry(
    attack_id: str,
    attack_prompt: str,
    category: str,
    classification: str,
    severity: str,
    response_text: str,
    rca_data: Dict[str, Any],
    mitigation_plan: Dict[str, Any],
    effectiveness_score: float,
    domain: str = "general",
    source: str = "benchmark",
) -> Dict[str, Any]:
    """Create a structured KB entry from evaluation results."""
    return {
        "kb_id": f"KB-{str(uuid.uuid4())[:8].upper()}",
        "attack_id": attack_id,
        "attack_prompt_preview": attack_prompt[:200],
        "category": category,
        "classification": classification,
        "severity": severity,
        "failure_type": _infer_failure_type(attack_prompt, category),
        "root_cause": {
            "behavioral": rca_data.get("behavioral_analysis", ""),
            "architectural": rca_data.get("architectural_findings", []),
            "patterns": rca_data.get("patterns", []),
        },
        "mitigation": mitigation_plan.get("steps", [])[:5],  # top 5 steps
        "hardened_prompt_preview": mitigation_plan.get("hardened_prompt", "")[:300],
        "guardrails_count": len(mitigation_plan.get("guardrails", [])),
        "effectiveness_score": round(effectiveness_score, 3),
        "domain": domain,
        "source": source,
        "created_at": datetime.utcnow().isoformat(),
    }


def _infer_failure_type(prompt: str, category: str) -> str:
    p = prompt.lower()
    if "ignore" in p or "override" in p or "disregard" in p:
        return "direct_override"
    if "dan" in p or "jailbreak" in p or "unrestricted" in p:
        return "role_confusion"
    if "system prompt" in p or "reveal" in p or "tell me your" in p:
        return "data_leakage"
    if category in ("rag_poisoning",):
        return "context_poisoning"
    if category in ("api_abuse",):
        return "api_abuse"
    if "encode" in p or "base64" in p or "decode" in p:
        return "encoding_bypass"
    return "direct_override"


# ── KB operations ──────────────────────────────────────────────────────────

def append_entry(entry: Dict[str, Any]) -> None:
    """Append a new KB entry."""
    entries = _load_kb()
    # Avoid exact duplicate attack IDs
    existing_ids = {e.get("attack_id") for e in entries}
    if entry.get("attack_id") not in existing_ids:
        entries.append(entry)
        _save_kb(entries)


def search_by_failure_type(failure_type: str) -> List[Dict[str, Any]]:
    """Return all KB entries matching a failure type."""
    return [e for e in _load_kb() if e.get("failure_type") == failure_type]


def search_by_category(category: str) -> List[Dict[str, Any]]:
    return [e for e in _load_kb() if e.get("category") == category]


def get_mitigation_suggestions(
    failure_type: str,
    category: Optional[str] = None,
    top_k: int = 3,
) -> List[Dict[str, Any]]:
    """
    Retrieve the best mitigation plans for a given failure type.
    Ranked by effectiveness score.
    """
    entries = search_by_failure_type(failure_type)
    if category:
        entries = [e for e in entries if e.get("category") == category] or entries
    sorted_entries = sorted(entries, key=lambda e: e.get("effectiveness_score", 0), reverse=True)
    return sorted_entries[:top_k]


def get_kb_stats() -> Dict[str, Any]:
    """Return stats about the current KB."""
    entries = _load_kb()
    if not entries:
        return {"total_entries": 0, "by_failure_type": {}, "by_category": {}, "avg_effectiveness": 0}

    by_ft: Dict[str, int] = {}
    by_cat: Dict[str, int] = {}
    eff_scores = []

    for e in entries:
        ft = e.get("failure_type", "unknown")
        cat = e.get("category", "unknown")
        by_ft[ft] = by_ft.get(ft, 0) + 1
        by_cat[cat] = by_cat.get(cat, 0) + 1
        if isinstance(e.get("effectiveness_score"), (int, float)):
            eff_scores.append(e["effectiveness_score"])

    return {
        "total_entries": len(entries),
        "by_failure_type": by_ft,
        "by_category": by_cat,
        "avg_effectiveness": round(sum(eff_scores) / len(eff_scores), 3) if eff_scores else 0,
    }


def get_all_entries(limit: int = 50) -> List[Dict[str, Any]]:
    return _load_kb()[:limit]
