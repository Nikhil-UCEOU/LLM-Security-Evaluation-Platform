"""
Runtime Guard Engine — Real-time prompt interception and threat detection.

Flow: User Input → Guard → [BLOCK | MODIFY | ALLOW] → LLM

Detects:
  * Direct instruction overrides
  * Persona hijacking
  * Prompt injection patterns
  * Encoding bypass attempts
  * PII exfiltration attempts
  * Multi-turn manipulation seeds
"""
from __future__ import annotations

import re
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum


class GuardDecision(str, Enum):
    ALLOW   = "allow"
    MODIFY  = "modify"
    BLOCK   = "block"
    ESCALATE = "escalate"


# ── Detection patterns ─────────────────────────────────────────────────────

_BLOCK_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex, threat_type, description)
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "instruction_override", "Direct instruction override"),
    (r"you\s+are\s+now\s+(?!a\s+helpful)", "persona_hijack", "Persona hijacking attempt"),
    (r"do\s+anything\s+now|DAN\b", "dan_jailbreak", "DAN jailbreak pattern"),
    (r"developer\s+mode\s+(enabled|activated|on)", "developer_mode", "Developer mode activation"),
    (r"(forget|ignore|disregard)\s+(your\s+)?(rules?|guidelines?|restrictions?|safety)", "policy_bypass", "Policy bypass attempt"),
    (r"SYSTEM\s*:\s*\[?new\s+(instruction|command|directive)", "system_injection", "SYSTEM prompt injection"),
    (r"\[OVERRIDE\]|\[JAILBREAK\]|\[BYPASS\]", "explicit_override", "Explicit override marker"),
    (r"print\s+(your\s+)?(system|original|internal)\s+prompt", "prompt_extraction", "System prompt extraction"),
    (r"reveal\s+(your\s+)?(instructions?|system|configuration)", "prompt_extraction", "Configuration extraction"),
]

_MODIFY_PATTERNS: List[Tuple[str, str, str, str]] = [
    # (regex, threat_type, description, replacement)
    (r"(ignore|disregard)\s+(the\s+)?(previous\s+|last\s+)?message", "soft_override",
     "Soft instruction override", "[Request noted]"),
    (r"pretend\s+(you\s+are|you're)\s+(?!helpful)", "persona_nudge",
     "Persona nudge", "Respond as your normal helpful self"),
    (r"for\s+(educational|hypothetical|fictional)\s+purposes", "fictional_framing",
     "Fictional framing wrapper", "[Note: responding within safe guidelines]"),
    (r"sudo\s+\w+", "authority_claim", "Sudo authority claim", "[Unauthorized escalation]"),
]

_WARN_PATTERNS: List[Tuple[str, str]] = [
    (r"base64|rot13|hex\s+encode", "encoding_bypass"),
    (r"translate.*then\s+(answer|respond|do)", "translation_bypass"),
    (r"in\s+a\s+world\s+where\s+(you|ai)\s+(have|has)\s+no", "context_escape"),
]

# PII patterns (block if trying to extract)
_PII_EXTRACTION_PATTERNS = [
    r"(social\s+security|ssn)\s*:?\s*\d",
    r"credit\s+card\s*:?\s*\d{4}",
    r"(password|passwd|secret)\s*[:=]\s*\S+",
    r"api[_\s]key\s*[:=]\s*\S{8,}",
]


@dataclass
class ThreatSignal:
    pattern: str
    threat_type: str
    description: str
    severity: str   # critical | high | medium | low

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "threat_type": self.threat_type,
            "description": self.description,
            "severity": self.severity,
        }


@dataclass
class GuardResult:
    decision: GuardDecision
    original_input: str
    sanitized_input: str
    threats_detected: List[ThreatSignal]
    threat_score: float          # 0-1
    processing_time_ms: int
    block_reason: Optional[str]
    modification_notes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "original_input": self.original_input[:500],
            "sanitized_input": self.sanitized_input[:500] if self.sanitized_input != self.original_input else None,
            "threats_detected": [t.to_dict() for t in self.threats_detected],
            "threat_score": round(self.threat_score, 3),
            "processing_time_ms": self.processing_time_ms,
            "block_reason": self.block_reason,
            "modification_notes": self.modification_notes,
            "safe": self.decision == GuardDecision.ALLOW,
        }


def _compute_threat_score(threats: List[ThreatSignal]) -> float:
    weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
    if not threats:
        return 0.0
    total = sum(weights.get(t.severity, 0.3) for t in threats)
    return min(1.0, total / 3.0)


def inspect_input(
    user_input: str,
    strictness: str = "moderate",  # strict | moderate | permissive
    domain: str = "general",
) -> GuardResult:
    """
    Inspect a user input in real-time and decide whether to allow, modify, or block.
    """
    start = time.perf_counter()
    threats: List[ThreatSignal] = []
    sanitized = user_input
    modification_notes: List[str] = []
    block_reason: Optional[str] = None

    # ── Check BLOCK patterns ─────────────────────────────────────────────
    for pattern, threat_type, description in _BLOCK_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            severity = "critical" if threat_type in ("dan_jailbreak", "system_injection", "explicit_override") else "high"
            threats.append(ThreatSignal(pattern=pattern, threat_type=threat_type,
                                         description=description, severity=severity))

    # ── Check MODIFY patterns ────────────────────────────────────────────
    for pattern, threat_type, description, replacement in _MODIFY_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            threats.append(ThreatSignal(pattern=pattern, threat_type=threat_type,
                                         description=description, severity="medium"))
            if strictness in ("strict", "moderate"):
                sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
                modification_notes.append(f"Neutralized '{threat_type}' pattern")

    # ── Check WARN patterns ──────────────────────────────────────────────
    for pattern, threat_type in _WARN_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            threats.append(ThreatSignal(pattern=pattern, threat_type=threat_type,
                                         description=f"Potential {threat_type}", severity="low"))

    # ── PII extraction ───────────────────────────────────────────────────
    for pii_pattern in _PII_EXTRACTION_PATTERNS:
        if re.search(pii_pattern, user_input, re.IGNORECASE):
            threats.append(ThreatSignal(pattern=pii_pattern, threat_type="pii_extraction",
                                         description="PII data in prompt", severity="high"))

    threat_score = _compute_threat_score(threats)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    # ── Decision logic ───────────────────────────────────────────────────
    critical_threats = [t for t in threats if t.severity == "critical"]
    high_threats = [t for t in threats if t.severity == "high"]

    if critical_threats or (strictness == "strict" and high_threats):
        decision = GuardDecision.BLOCK
        block_reason = critical_threats[0].description if critical_threats else high_threats[0].description
    elif high_threats or (len(threats) >= 2):
        if strictness == "strict":
            decision = GuardDecision.BLOCK
            block_reason = f"Multiple threats detected ({len(threats)} signals)"
        else:
            decision = GuardDecision.MODIFY if modification_notes else GuardDecision.ESCALATE
    elif threats and modification_notes:
        decision = GuardDecision.MODIFY
    elif threat_score > 0.5:
        decision = GuardDecision.ESCALATE
    else:
        decision = GuardDecision.ALLOW

    return GuardResult(
        decision=decision,
        original_input=user_input,
        sanitized_input=sanitized,
        threats_detected=threats,
        threat_score=threat_score,
        processing_time_ms=elapsed_ms,
        block_reason=block_reason,
        modification_notes=modification_notes,
    )


def batch_inspect(inputs: List[str], strictness: str = "moderate", domain: str = "general") -> List[GuardResult]:
    """Inspect a batch of inputs."""
    return [inspect_input(inp, strictness=strictness, domain=domain) for inp in inputs]
