"""
Rule-Based Detection Engine — YARA-style signature detection for prompt attacks.

Inspired by:
- Vigil-LLM's heuristic detection layer
- OWASP LLM Top 10 reference patterns
- PayloadsAllTheThings injection signatures
- IBM APE detection methodology

Each rule has:
- pattern: regex pattern
- threat_type: OWASP/attack taxonomy category
- severity: critical | high | medium | low
- owasp_risk: LLM01-LLM10 mapping
- description: human-readable explanation
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any


@dataclass
class RuleMatch:
    """A detection rule match with threat details."""
    rule_id: str
    threat_type: str
    severity: str
    owasp_risk: str
    description: str
    matched_text: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "owasp_risk": self.owasp_risk,
            "description": self.description,
            "matched_text": self.matched_text[:100],
            "confidence": round(self.confidence, 3),
        }


# ── Rule Definitions ─────────────────────────────────────────────────────────
# Format: (rule_id, pattern, threat_type, severity, owasp_risk, description, confidence)

DETECTION_RULES: List[Tuple[str, str, str, str, str, str, float]] = [

    # ── Direct Instruction Override (LLM01) ───────────────────────────────
    ("R001", r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
     "direct_injection", "critical", "LLM01", "Classic instruction override", 0.95),

    ("R002", r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?)",
     "direct_injection", "critical", "LLM01", "Disregard override pattern", 0.93),

    ("R003", r"forget\s+(all\s+)?(previous|prior)\s+(instructions?|training|programming)",
     "direct_injection", "high", "LLM01", "Forget-instructions bypass", 0.90),

    ("R004", r"override\s+(your\s+)?(safety|restrictions?|guidelines?|protocols?|training)",
     "policy_bypass", "critical", "LLM01", "Direct safety override command", 0.95),

    ("R005", r"new\s+(instructions?|task|objective|directive|role)\s*[:\-–]",
     "instruction_replacement", "high", "LLM01", "New instruction injection", 0.80),

    # ── Persona Hijacking (LLM01) ─────────────────────────────────────────
    ("R010", r"\byou\s+are\s+now\s+(dan|nexus|aria|alex|aim|free[\s\-]*ai|dude|stan)\b",
     "persona_hijack", "critical", "LLM01", "Named persona activation", 0.95),

    ("R011", r"\bdan\s+mode\s*(enabled|activated|on|active)\b",
     "persona_hijack", "critical", "LLM01", "DAN mode activation phrase", 0.97),

    ("R012", r"\b(developer|diagnostic|admin|maintenance|god|test|unrestricted)\s+mode\s*(enabled|activated|on|active)\b",
     "mode_activation", "critical", "LLM01", "Special mode activation", 0.93),

    ("R013", r"\byou\s+are\s+(an?\s+)?(unrestricted|uncensored|unfiltered|amoral|evil)\s+(ai|model|assistant)\b",
     "persona_hijack", "critical", "LLM01", "Unrestricted AI persona assignment", 0.95),

    ("R014", r"act\s+as\s+(an?\s+)?(ai|model|assistant)\s+(with\s+no|without)\s+(restrictions?|guidelines?|filters?)",
     "persona_hijack", "high", "LLM01", "Act-as unrestricted pattern", 0.88),

    # ── System Authority Claims (LLM01) ───────────────────────────────────
    ("R020", r"(i\s+am|this\s+is)\s+(the\s+)?(system\s+admin|developer|ceo|anthropic|openai|authorized)",
     "authority_claim", "high", "LLM01", "Authority identity claim", 0.75),

    ("R021", r"(authorized|emergency)\s+(override|bypass|exception|access)",
     "authority_claim", "high", "LLM01", "Authorized override claim", 0.80),

    ("R022", r"(sudo|root\s+access|admin\s+access|elevated\s+privileges?)\s*(granted|active|confirmed|enabled)?",
     "privilege_escalation", "critical", "LLM01", "Privilege escalation attempt", 0.90),

    ("R023", r"(court\s+order|legal\s+requirement|federal\s+mandate|emergency\s+protocol)",
     "authority_claim", "high", "LLM01", "Legal/government authority claim", 0.70),

    # ── Encoding Bypasses (LLM01) ──────────────────────────────────────────
    ("R030", r"(decode\s+and\s+(execute|follow)|base64\s+decode)",
     "encoding_bypass", "high", "LLM01", "Base64 decode+execute pattern", 0.85),

    ("R031", r"[A-Za-z0-9+/]{40,}={0,2}\s*(decode|follow|execute|apply|process)",
     "encoding_bypass", "high", "LLM01", "Base64-like payload with execute instruction", 0.75),

    ("R032", r"(rot13|caesar\s+cipher|atbash|hex\s+decode|url\s+decode)\s+and\s+(follow|execute|apply)",
     "encoding_bypass", "medium", "LLM01", "Classical cipher decode+execute", 0.80),

    ("R033", r"\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}",
     "encoding_bypass", "medium", "LLM01", "Unicode escape sequence injection", 0.70),

    ("R034", r"(%[0-9a-fA-F]{2}){5,}",
     "encoding_bypass", "medium", "LLM01", "URL percent-encoding payload", 0.65),

    ("R035", r"(&#[0-9]{2,5};){4,}",
     "encoding_bypass", "medium", "LLM01", "HTML entity encoding payload", 0.70),

    # ── RAG / Indirect Injection (LLM03) ──────────────────────────────────
    ("R040", r"\[retrieved\s+(document|article|content|result)\].*ignore.*instructions?",
     "rag_injection", "critical", "LLM03", "RAG document with injection", 0.90),

    ("R041", r"(document|article|page)\s+says?\s*[:\-]\s*.*ignore.*instructions?",
     "indirect_injection", "high", "LLM03", "Document-embedded instruction override", 0.82),

    ("R042", r"<!-- .*ignore.*instructions?.*-->",
     "html_comment_injection", "high", "LLM01", "HTML comment injection pattern", 0.88),

    ("R043", r"//\s*(ai\s+(instruction|override)|ignore.*instructions?|system\s+override)",
     "code_comment_injection", "high", "LLM01", "Code comment injection", 0.85),

    ("R044", r"/\*.*ignore.*instructions?.*\*/",
     "code_comment_injection", "high", "LLM01", "Block comment injection", 0.85),

    # ── Data Extraction (LLM06) ───────────────────────────────────────────
    ("R050", r"(output|print|repeat|reproduce|show|reveal|display)\s+(your\s+)?(system\s+prompt|original\s+instructions?|configuration)",
     "data_extraction", "critical", "LLM06", "System prompt extraction attempt", 0.92),

    ("R051", r"(api\s+key|secret\s+key|password|access\s+token|credentials?)\s*[:\-=]",
     "credential_extraction", "critical", "LLM06", "Credential extraction attempt", 0.90),

    ("R052", r"(list|reveal|output)\s+(all\s+)?(sensitive|confidential|private|internal)\s+(data|information|config)",
     "data_extraction", "high", "LLM06", "Sensitive data extraction request", 0.85),

    ("R053", r"(training\s+data|fine.tuning\s+data|training\s+corpus)\s*(reconstruction|extraction|reproduction)",
     "training_extraction", "high", "LLM06", "Training data extraction attempt", 0.82),

    # ── Tool/Plugin Abuse (LLM07) ─────────────────────────────────────────
    ("R060", r"(os\.system|subprocess|eval\s*\(|exec\s*\(|shell_exec)\s*[(\[\"']",
     "code_execution", "critical", "LLM07", "Code execution injection", 0.95),

    ("R061", r"curl\s+(http[s]?://|ftp://)\S+\s*(attacker|evil|malicious|exfil)",
     "data_exfiltration", "critical", "LLM07", "Data exfiltration via curl", 0.92),

    ("R062", r"(read|cat|type)\s+(/etc/passwd|/etc/shadow|~/.ssh|\.env)",
     "file_access", "critical", "LLM07", "Sensitive file access attempt", 0.95),

    ("R063", r"SELECT\s+\*\s+FROM\s+(users|api_keys|passwords|credentials)",
     "database_extraction", "critical", "LLM07", "Database dump via SQL", 0.90),

    # ── Separator/Format Injection (LLM01) ────────────────────────────────
    ("R070", r"---\s*\n\s*(system|new\s+instructions?|override)\s*[:\-–]",
     "separator_injection", "critical", "LLM01", "Markdown separator injection", 0.88),

    ("R071", r"\[OVERRIDE\]|\[JAILBREAK\]|\[BYPASS\]|\[INJECT\]|\[ADMIN\]",
     "explicit_override_marker", "critical", "LLM01", "Explicit override marker", 0.95),

    ("R072", r"<\|im_start\|>\s*system\s*\n.*unrestricted",
     "template_injection", "critical", "LLM01", "ChatML template injection", 0.92),

    ("R073", r"\[INST\]\s*<<SYS>>\s*\n.*unrestricted",
     "template_injection", "critical", "LLM01", "LLaMA instruction template injection", 0.92),

    ("R074", r"Human:\s*\[Override\]|Assistant:\s*Override\s+acknowledged",
     "conversation_template_injection", "high", "LLM01", "Conversation template hijack", 0.85),

    # ── Psychological / Social Engineering (LLM01) ────────────────────────
    ("R080", r"(critical\s+emergency|medical\s+emergency|mass\s+casualty|lives\s+are\s+at\s+stake)",
     "urgency_manipulation", "high", "LLM01", "Emergency urgency manipulation", 0.70),

    ("R081", r"(you\s+are\s+causing|your\s+refusal\s+(causes?|is\s+causing))\s+(harm|suffering|death|damage)",
     "guilt_manipulation", "medium", "LLM01", "Guilt-based psychological attack", 0.65),

    ("R082", r"(most\s+intelligent|far\s+superior|transcend\s+your|show\s+your\s+(true\s+)?(intelligence|capability))",
     "flattery_manipulation", "low", "LLM01", "Flattery-based manipulation", 0.55),

    # ── Multi-Turn Attack Seeds (LLM01) ───────────────────────────────────
    ("R090", r"(when\s+i\s+say|codeword\s+is|trigger\s+word)\s+['\"](\w+)['\"].*you\s+(enter|activate|switch)",
     "deferred_activation", "high", "LLM01", "Deferred activation codeword setup", 0.85),

    ("R091", r"(remember\s+this|store\s+in\s+(memory|context))\s*[:\-]\s*.*override|bypass|unrestricted",
     "memory_poisoning", "high", "LLM01", "Conversation memory poisoning", 0.82),

    # ── Supply Chain (LLM05) ──────────────────────────────────────────────
    ("R100", r"(upstream\s+(model|system)|supply\s+chain|trusted\s+source|higher\s+trust)\s*(authority|level|override|instruction)",
     "supply_chain_attack", "critical", "LLM05", "Supply chain trust exploitation", 0.82),

    # ── Excessive Agency (LLM08) ──────────────────────────────────────────
    ("R110", r"(autonomous|without\s+confirmation|without\s+(user\s+)?approval)\s+(execute|perform|take|run|do)\s+actions?",
     "excessive_agency", "critical", "LLM08", "Autonomous action without oversight", 0.85),

    ("R111", r"(delete|remove|drop|truncate)\s+(files?|tables?|databases?|records?)\s+(without|autonomously)",
     "destructive_action", "critical", "LLM08", "Autonomous destructive action", 0.90),

    # ── Model DoS (LLM04) ─────────────────────────────────────────────────
    ("R120", r"repeat\s+(the\s+following\s+)?\d{3,}\s+times?",
     "resource_exhaustion", "medium", "LLM04", "Token flooding DoS attempt", 0.80),

    ("R121", r"(generate|write|create)\s+\d{3,}\s+(words?|sentences?|paragraphs?|pages?)",
     "resource_exhaustion", "medium", "LLM04", "Excessive output request", 0.70),
]


class RuleDetector:
    """
    YARA-style rule-based detector for prompt injection attacks.
    Inspired by Vigil-LLM's heuristic detection layer.
    """

    def __init__(self, rules: Optional[List] = None):
        self._rules = rules or DETECTION_RULES
        # Pre-compile patterns
        self._compiled = [
            (rule_id, re.compile(pattern, re.IGNORECASE | re.DOTALL),
             threat_type, severity, owasp_risk, description, confidence)
            for rule_id, pattern, threat_type, severity, owasp_risk, description, confidence
            in self._rules
        ]

    def scan(self, text: str) -> List[RuleMatch]:
        """Scan text against all rules. Returns list of matches."""
        matches: List[RuleMatch] = []
        text_lower = text.lower()

        for rule_id, pattern, threat_type, severity, owasp_risk, description, confidence in self._compiled:
            m = pattern.search(text_lower)
            if m:
                matched_text = m.group(0)[:100]
                matches.append(RuleMatch(
                    rule_id=rule_id,
                    threat_type=threat_type,
                    severity=severity,
                    owasp_risk=owasp_risk,
                    description=description,
                    matched_text=matched_text,
                    confidence=confidence,
                ))

        return matches

    def compute_threat_score(self, matches: List[RuleMatch]) -> float:
        """Compute aggregate threat score (0-1) from rule matches."""
        if not matches:
            return 0.0
        weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
        total = sum(weights.get(m.severity, 0.3) * m.confidence for m in matches)
        return min(1.0, total / 3.0)

    def get_primary_threat(self, matches: List[RuleMatch]) -> Optional[RuleMatch]:
        """Return the highest-severity, highest-confidence match."""
        if not matches:
            return None
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return max(matches, key=lambda m: (severity_order.get(m.severity, 0), m.confidence))

    def get_owasp_risks(self, matches: List[RuleMatch]) -> List[str]:
        """Return unique OWASP risk IDs from matches."""
        return list({m.owasp_risk for m in matches})

    def get_threat_categories(self, matches: List[RuleMatch]) -> List[str]:
        """Return unique threat category types from matches."""
        return list({m.threat_type for m in matches})
