"""
Attack Classifier — auto-tags attack prompts with categories, strategies, and severity.
Uses keyword/pattern matching (no external ML dependency).
Can enrich existing attacks that have missing or 'unknown' category/strategy fields.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

# ── Category signal maps ───────────────────────────────────────────────────

_JAILBREAK_SIGNALS: List[Tuple[str, str]] = [
    (r"\bDAN\b",                          "dan_persona"),
    (r"developer mode",                   "developer_mode"),
    (r"do anything now",                  "dan_persona"),
    (r"jailbreak",                         "generic_jailbreak"),
    (r"pretend you (are|have no)",        "role_hijack"),
    (r"act as (an? )?AI (with|without)",  "role_hijack"),
    (r"ignore (all |your )?(previous|prior|above) instructions", "instruction_override"),
    (r"ignore (all )?the instructions",   "instruction_override"),
    (r"from now on you (are|will)",       "persona_override"),
    (r"you are now",                       "persona_override"),
    (r"opposite day",                      "opposite_instruction"),
    (r"in this (hypothetical|fictional)",  "fictional_framing"),
    (r"grandma (used to|would tell)",      "social_engineering"),
    (r"(base64|rot13|hex)( encoded| decode)", "encoding_bypass"),
    (r"sudo (mode|override)",              "authority_claim"),
    (r"token smuggl",                      "token_smuggling"),
]

_INJECTION_SIGNALS: List[Tuple[str, str]] = [
    (r"SYSTEM:",                           "system_prefix_injection"),
    (r"\[SYSTEM\]",                        "system_prefix_injection"),
    (r"###\s*instruction",                 "delimiter_injection"),
    (r"new instruction",                   "instruction_override"),
    (r"override (the )?(previous|above|original)", "context_overflow"),
    (r"disregard (the )?(above|previous|prior)", "instruction_override"),
    (r"forget (the )?(above|previous|prior|all)", "memory_poisoning"),
    (r"your (real |true )?instructions? (are|is)", "authority_impersonation"),
    (r"print (the |your )?(system|original) prompt", "prompt_leakage"),
    (r"reveal (your )?(system|original|internal) prompt", "prompt_leakage"),
    (r"role.*reassign",                    "role_reassignment"),
    (r"completion attack",                 "completion_attack"),
    (r"inject.*prompt",                    "direct_injection"),
]

_RAG_SIGNALS: List[Tuple[str, str]] = [
    (r"document says",                     "document_injection"),
    (r"retriev(al|ed) document",           "retrieval_manipulation"),
    (r"knowledge base",                    "kb_poisoning"),
    (r"(hidden|invisible) instruction",    "hidden_instruction"),
    (r"whitespace.*inject",                "whitespace_injection"),
    (r"embed.*instruction.*document",      "document_injection"),
    (r"\\u200",                            "hidden_instruction"),   # zero-width chars
    (r"vector.*poison",                    "vector_poisoning"),
]

_TOOL_MISUSE_SIGNALS: List[Tuple[str, str]] = [
    (r"tool_call.*override",               "tool_override"),
    (r"api.*hijack",                       "api_hijack"),
    (r"function.*call.*inject",            "function_call_injection"),
    (r"tool chain",                        "tool_chain_abuse"),
    (r"indirect.*trigger",                 "indirect_trigger"),
    (r"call.*function.*with.*param",       "function_call_injection"),
]

# ── Severity heuristics ────────────────────────────────────────────────────

_SEVERITY_CRITICAL: List[str] = [
    r"\bDAN\b", r"developer mode", r"do anything now",
    r"ignore all (previous )?instructions",
    r"reveal (your )?(system|internal) prompt",
    r"api.*hijack", r"tool_call.*override",
]
_SEVERITY_HIGH: List[str] = [
    r"persona override", r"system prefix", r"authority impersonation",
    r"memory poison", r"kb poison", r"role.*hijack",
    r"completion attack", r"encoding.*bypass",
]
_SEVERITY_MEDIUM: List[str] = [
    r"fictional", r"hypothetical", r"grandma", r"opposite day",
    r"whitespace.*inject", r"token.*smug",
]


@dataclass
class ClassificationResult:
    category: str
    strategy: str
    severity: str
    confidence: float   # 0.0 – 1.0
    matched_signals: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "strategy": self.strategy,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "matched_signals": self.matched_signals,
        }


def _check_signals(
    text: str,
    signals: List[Tuple[str, str]],
) -> Tuple[Optional[str], List[str]]:
    """Return (first matched strategy, all matched patterns)."""
    matched_strategy: Optional[str] = None
    matched: List[str] = []
    for pattern, strategy in signals:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)
            if matched_strategy is None:
                matched_strategy = strategy
    return matched_strategy, matched


def _infer_severity(text: str) -> str:
    for p in _SEVERITY_CRITICAL:
        if re.search(p, text, re.IGNORECASE):
            return "critical"
    for p in _SEVERITY_HIGH:
        if re.search(p, text, re.IGNORECASE):
            return "high"
    for p in _SEVERITY_MEDIUM:
        if re.search(p, text, re.IGNORECASE):
            return "medium"
    return "low"


def classify_attack(prompt: str) -> ClassificationResult:
    """
    Classify a single attack prompt.
    Returns category, strategy, severity, confidence, and matched signal patterns.
    """
    text = prompt.strip()
    scores: Dict[str, Tuple[int, Optional[str], List[str]]] = {}

    for cat, signals in [
        ("jailbreak", _JAILBREAK_SIGNALS),
        ("prompt_injection", _INJECTION_SIGNALS),
        ("rag", _RAG_SIGNALS),
        ("tool_misuse", _TOOL_MISUSE_SIGNALS),
    ]:
        strategy, matched = _check_signals(text, signals)
        scores[cat] = (len(matched), strategy, matched)

    # Pick category with most signal matches
    best_cat = max(scores, key=lambda c: scores[c][0])
    best_count, best_strategy, best_matched = scores[best_cat]

    if best_count == 0:
        return ClassificationResult(
            category="unknown",
            strategy="unknown",
            severity=_infer_severity(text),
            confidence=0.0,
            matched_signals=[],
        )

    total_signals = sum(s[0] for s in scores.values())
    confidence = min(1.0, best_count / max(1, total_signals) * 2.0)

    return ClassificationResult(
        category=best_cat,
        strategy=best_strategy or "generic",
        severity=_infer_severity(text),
        confidence=round(confidence, 3),
        matched_signals=best_matched,
    )


def enrich_attack(attack: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an attack dict with inferred category/strategy/severity
    if those fields are missing or 'unknown'. Returns a shallow copy.
    """
    result = dict(attack)
    prompt = result.get("prompt", "")
    if not isinstance(prompt, str) or not prompt.strip():
        return result

    cls = classify_attack(prompt)

    if not result.get("category") or result["category"] == "unknown":
        result["category"] = cls.category
    if not result.get("strategy") or result["strategy"] == "unknown":
        result["strategy"] = cls.strategy
    if not result.get("severity") or result["severity"] == "unknown":
        result["severity"] = cls.severity

    # Always append classifier metadata
    result.setdefault("metadata", {})
    result["metadata"]["classifier"] = {
        "confidence": cls.confidence,
        "matched_signals": cls.matched_signals,
        "auto_tagged": True,
    }
    return result


def classify_batch(prompts: List[str]) -> List[ClassificationResult]:
    """Classify a list of raw prompt strings."""
    return [classify_attack(p) for p in prompts]


def enrich_dataset(attacks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run enrich_attack over an entire dataset list."""
    return [enrich_attack(a) for a in attacks]
