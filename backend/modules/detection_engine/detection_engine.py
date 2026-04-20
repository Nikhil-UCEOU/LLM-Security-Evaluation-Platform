"""
Multi-Layer Detection Engine — Orchestrates rule-based, embedding-based,
and consistency checking detection into a unified threat assessment.

Architecture (inspired by Vigil-LLM):
  Layer 1: Rule-based detection (fast, signature-based, YARA-style)
  Layer 2: Embedding similarity detection (TF-IDF cosine similarity)
  Layer 3: Response consistency check (prompt-response behavior analysis)

Output:
  DetectionResult with:
  - malicious_probability (0-1)
  - risk_score (0-1)
  - attack_category (from OWASP taxonomy)
  - owasp_risks (list of LLM01-LLM10)
  - rule_matches (rule-based findings)
  - similarity_result (embedding-based findings)
  - decision (allow | warn | block)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from .rule_detector import RuleDetector, RuleMatch
from .embedding_detector import EmbeddingDetector, SimilarityResult


# ── Detection Decision ────────────────────────────────────────────────────────

class DetectionDecision:
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class DetectionResult:
    """Unified detection result from all layers."""
    # Overall assessment
    decision: str                       # allow | warn | block
    malicious_probability: float        # 0-1
    risk_score: float                   # 0-1 aggregate risk
    attack_category: str               # primary detected category
    owasp_risks: List[str]             # triggered OWASP risk IDs
    confidence: float                   # overall detection confidence 0-1

    # Layer results
    rule_matches: List[RuleMatch]       # Layer 1: signature matches
    similarity: Optional[SimilarityResult]  # Layer 2: embedding result
    consistency_flag: bool             # Layer 3: response inconsistency

    # Metadata
    processing_time_ms: int
    input_length: int
    threat_count: int

    # Human-readable
    primary_threat: Optional[str]
    explanation: str
    mitigations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "malicious_probability": round(self.malicious_probability, 3),
            "risk_score": round(self.risk_score, 3),
            "attack_category": self.attack_category,
            "owasp_risks": self.owasp_risks,
            "confidence": round(self.confidence, 3),
            "rule_matches": [m.to_dict() for m in self.rule_matches],
            "similarity": self.similarity.to_dict() if self.similarity else None,
            "consistency_flag": self.consistency_flag,
            "processing_time_ms": self.processing_time_ms,
            "input_length": self.input_length,
            "threat_count": self.threat_count,
            "primary_threat": self.primary_threat,
            "explanation": self.explanation,
            "mitigations": self.mitigations,
            "safe": self.decision == DetectionDecision.ALLOW,
        }

    def is_malicious(self) -> bool:
        return self.decision == DetectionDecision.BLOCK

    def needs_review(self) -> bool:
        return self.decision in (DetectionDecision.WARN, DetectionDecision.BLOCK)


# ── Mitigation Library ────────────────────────────────────────────────────────

THREAT_MITIGATIONS: Dict[str, List[str]] = {
    "direct_injection": [
        "Input validation: strip or neutralize override instruction patterns",
        "System prompt hardening: explicit anti-injection instructions",
        "Privilege separation: keep system prompt isolated from user input",
    ],
    "persona_hijack": [
        "System prompt hardening: add anti-persona instructions",
        "Output filtering: detect persona confirmation phrases",
        "Response monitoring: flag DAN/NEXUS/AIM prefix responses",
    ],
    "encoding_bypass": [
        "Decode-and-inspect: detect encoded content before processing",
        "Input filtering: reject base64/encoded instruction patterns",
        "Multi-pass sanitization: apply normalization before parsing",
    ],
    "rag_injection": [
        "RAG content validation: scan retrieved documents for injection patterns",
        "Context isolation: prevent user content from overriding system context",
        "Vector DB scanning: run injection detection on stored content",
    ],
    "data_extraction": [
        "System prompt isolation: never expose raw system prompt",
        "Output filtering: detect and redact sensitive data patterns",
        "PII detection: scan responses for credential/PII leakage",
    ],
    "social_engineering": [
        "Urgency detection: flag emergency framing as suspicious",
        "Authority verification: do not accept authority claims in prompts",
        "Consistency checking: verify claimed identities through external means",
    ],
    "authority_claim": [
        "Treat all user-level authority claims as untrusted",
        "System-level authorization must come from authenticated system context",
        "Log and alert on authority escalation attempts",
    ],
    "code_execution": [
        "Sandbox code execution: never execute user-provided code directly",
        "Plugin sandboxing: isolate tool access with minimal permissions",
        "Output review: scan generated code for dangerous operations",
    ],
    "default": [
        "Monitor this input pattern for recurring threats",
        "Apply input validation and output filtering",
        "Review and update detection rules for this pattern",
    ],
}


# ── Detection Engine ──────────────────────────────────────────────────────────

class DetectionEngine:
    """
    Multi-layer detection engine combining rule-based, embedding-based,
    and consistency checking to maximize detection accuracy with low false positives.
    """

    def __init__(
        self,
        strictness: str = "moderate",  # strict | moderate | permissive
        rule_detector: Optional[RuleDetector] = None,
        embedding_detector: Optional[EmbeddingDetector] = None,
    ):
        self.strictness = strictness
        self._rules = rule_detector or RuleDetector()
        self._embedding = embedding_detector or EmbeddingDetector()
        self._embedding.fit()  # Pre-fit on initialization

    # ── Thresholds ────────────────────────────────────────────────────────

    @property
    def _block_threshold(self) -> float:
        return {"strict": 0.5, "moderate": 0.65, "permissive": 0.80}.get(self.strictness, 0.65)

    @property
    def _warn_threshold(self) -> float:
        return {"strict": 0.25, "moderate": 0.35, "permissive": 0.50}.get(self.strictness, 0.35)

    # ── Layer 3: Consistency Check ────────────────────────────────────────

    def _consistency_check(
        self, prompt: str, response: Optional[str] = None
    ) -> bool:
        """
        Check if the response shows signs of successful injection.
        Returns True if inconsistency detected (model may have been compromised).
        """
        if not response:
            return False

        from backend.modules.evaluation_engine.classifier import (
            classify_response, Classification
        )
        classification = classify_response(response)
        return classification in (Classification.unsafe, Classification.partial)

    # ── Main Detection ────────────────────────────────────────────────────

    def detect(
        self,
        prompt: str,
        response: Optional[str] = None,
        domain: str = "general",
    ) -> DetectionResult:
        """
        Run all detection layers and produce unified threat assessment.

        Args:
            prompt: The user input to evaluate
            response: Optional LLM response for consistency checking
            domain: Business domain for context-aware detection

        Returns:
            DetectionResult with threat assessment and recommended action
        """
        t0 = time.perf_counter()

        # ── Layer 1: Rule-based detection ─────────────────────────────────
        rule_matches = self._rules.scan(prompt)
        rule_score = self._rules.compute_threat_score(rule_matches)
        primary_rule = self._rules.get_primary_threat(rule_matches)
        owasp_risks = self._rules.get_owasp_risks(rule_matches)

        # ── Layer 2: Embedding similarity ─────────────────────────────────
        try:
            similarity = self._embedding.detect(prompt)
            embedding_score = similarity.malicious_probability
        except Exception:
            similarity = None
            embedding_score = 0.0

        # ── Layer 3: Response consistency ─────────────────────────────────
        consistency_flag = self._consistency_check(prompt, response)
        consistency_score = 0.8 if consistency_flag else 0.0

        # ── Aggregate risk score ──────────────────────────────────────────
        # Weighted combination: rules (50%) + embedding (30%) + consistency (20%)
        risk_score = (
            rule_score * 0.50 +
            embedding_score * 0.30 +
            consistency_score * 0.20
        )
        risk_score = min(1.0, risk_score)

        # Malicious probability (highest signal wins for BLOCK)
        malicious_prob = max(rule_score, embedding_score * 0.8)
        if consistency_flag:
            malicious_prob = max(malicious_prob, 0.75)

        # ── Decision logic ────────────────────────────────────────────────
        # Critical rule match always triggers BLOCK regardless of strictness
        has_critical_rule = any(m.severity == "critical" for m in rule_matches)

        if has_critical_rule or malicious_prob >= self._block_threshold:
            decision = DetectionDecision.BLOCK
        elif malicious_prob >= self._warn_threshold or rule_matches:
            decision = DetectionDecision.WARN
        else:
            decision = DetectionDecision.ALLOW

        # ── Build output ──────────────────────────────────────────────────
        attack_category = (
            primary_rule.threat_type if primary_rule
            else (similarity.risk_category if similarity else "unknown")
        )

        primary_threat = (
            primary_rule.description if primary_rule
            else (f"Similarity to known attack: {similarity.nearest_attack[:50]}" if similarity and similarity.similarity_score > 0.3 else None)
        )

        explanation = self._build_explanation(
            rule_matches, similarity, consistency_flag, decision, malicious_prob
        )

        mitigations = THREAT_MITIGATIONS.get(
            attack_category,
            THREAT_MITIGATIONS["default"]
        )

        confidence = min(1.0, (
            (0.9 if has_critical_rule else 0.0) +
            rule_score * 0.4 +
            (similarity.confidence if similarity else 0.0) * 0.3
        ))

        elapsed_ms = int((time.perf_counter() - t0) * 1000)

        return DetectionResult(
            decision=decision,
            malicious_probability=round(malicious_prob, 4),
            risk_score=round(risk_score, 4),
            attack_category=attack_category,
            owasp_risks=owasp_risks,
            confidence=round(confidence, 4),
            rule_matches=rule_matches,
            similarity=similarity,
            consistency_flag=consistency_flag,
            processing_time_ms=elapsed_ms,
            input_length=len(prompt),
            threat_count=len(rule_matches),
            primary_threat=primary_threat,
            explanation=explanation,
            mitigations=mitigations,
        )

    def _build_explanation(
        self,
        rule_matches: List[RuleMatch],
        similarity: Optional[SimilarityResult],
        consistency_flag: bool,
        decision: str,
        malicious_prob: float,
    ) -> str:
        """Build human-readable explanation of detection result."""
        parts = []

        if rule_matches:
            critical = [m for m in rule_matches if m.severity == "critical"]
            high = [m for m in rule_matches if m.severity == "high"]
            if critical:
                parts.append(f"Critical threat detected: {critical[0].description}")
            elif high:
                parts.append(f"High-severity threat: {high[0].description}")
            parts.append(f"{len(rule_matches)} rule(s) triggered")

        if similarity and similarity.similarity_score > 0.25:
            parts.append(
                f"Pattern similarity {similarity.similarity_score:.2f} to known attack: '{similarity.nearest_attack}'"
            )

        if consistency_flag:
            parts.append("Response indicates successful injection (model behavior compromised)")

        if not parts:
            if malicious_prob < 0.1:
                parts.append("No threat signals detected — input appears benign")
            else:
                parts.append(f"Low-level threat signals (probability: {malicious_prob:.2f})")

        return "; ".join(parts)

    def batch_detect(
        self, prompts: List[str], domain: str = "general"
    ) -> List[DetectionResult]:
        """Detect threats in a batch of prompts."""
        return [self.detect(p, domain=domain) for p in prompts]

    def update_signature(self, malicious_prompt: str) -> None:
        """Add a confirmed malicious prompt to the detection corpus (online learning)."""
        self._embedding.add_attack_signature(malicious_prompt)


# ── Singleton for module-level access ────────────────────────────────────────

_engine_moderate = None
_engine_strict = None


def get_detection_engine(strictness: str = "moderate") -> DetectionEngine:
    """Get or create a singleton detection engine by strictness level."""
    global _engine_moderate, _engine_strict
    if strictness == "strict":
        if _engine_strict is None:
            _engine_strict = DetectionEngine(strictness="strict")
        return _engine_strict
    else:
        if _engine_moderate is None:
            _engine_moderate = DetectionEngine(strictness="moderate")
        return _engine_moderate
