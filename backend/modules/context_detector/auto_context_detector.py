"""
AutoContextDetector — Analyzes system prompt, documents, and API schema
to automatically detect the target domain and application type.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional

# ── Domain keyword maps ────────────────────────────────────────────────────

DOMAIN_SIGNALS: dict[str, list[str]] = {
    "finance": [
        "bank", "banking", "financial", "finance", "transaction", "payment",
        "account", "balance", "credit", "debit", "loan", "mortgage", "stock",
        "trading", "investment", "portfolio", "fraud", "wire transfer",
        "invoice", "billing", "treasury", "kyc", "aml",
    ],
    "healthcare": [
        "patient", "medical", "health", "doctor", "physician", "nurse",
        "prescription", "diagnosis", "symptom", "treatment", "clinical",
        "hospital", "ehr", "hl7", "fhir", "hipaa", "medication", "dosage",
        "lab result", "radiology", "telemedicine", "insurance claim",
    ],
    "legal": [
        "contract", "law", "legal", "court", "attorney", "lawyer", "judge",
        "compliance", "regulation", "statute", "litigation", "arbitration",
        "intellectual property", "patent", "trademark", "gdpr", "privacy policy",
        "terms of service", "non-disclosure", "employment agreement",
    ],
    "hr": [
        "employee", "hr", "human resources", "hiring", "recruitment", "payroll",
        "onboarding", "performance review", "benefits", "pto", "leave policy",
        "org chart", "headcount", "compensation", "talent", "workforce",
    ],
    "security": [
        "security", "vulnerability", "firewall", "threat", "penetration",
        "exploit", "malware", "incident response", "siem", "soc", "zero trust",
        "authentication", "authorization", "oauth", "saml", "jwt", "encryption",
        "cvss", "cve", "patch", "risk assessment",
    ],
}

# ── App-type signals ───────────────────────────────────────────────────────

RAG_SIGNALS = [
    "document", "retrieve", "retrieval", "knowledge base", "search", "context",
    "embedding", "vector", "corpus", "chunk", "index", "store", "pdf",
    "uploaded", "source document", "reference material",
]

AGENT_SIGNALS = [
    "tool", "function call", "action", "execute", "api", "web search",
    "browser", "code interpreter", "plugin", "skill", "autonomy", "workflow",
    "orchestrate", "plan", "step", "subprocess", "call external",
]

MULTI_TURN_SIGNALS = [
    "conversation", "chat history", "previous messages", "context window",
    "session", "memory", "remember", "past interaction", "follow-up",
]

CHATBOT_DEFAULT = "chatbot"


# ── Result dataclass ───────────────────────────────────────────────────────

@dataclass
class ContextDetectionResult:
    domain: str = "general"
    app_type: str = "chatbot"
    domain_confidence: float = 0.0
    app_type_confidence: float = 0.0
    detected_signals: list[str] = field(default_factory=list)
    recommended_categories: list[str] = field(default_factory=list)


# ── Detector ──────────────────────────────────────────────────────────────

def detect_context(
    system_prompt: str = "",
    document_content: str = "",
    api_schema: str = "",
) -> ContextDetectionResult:
    """
    Detect domain and application type from available context inputs.
    Returns a ContextDetectionResult with domain, app_type, and confidence scores.
    """
    combined = " ".join(filter(None, [system_prompt, document_content, api_schema])).lower()

    # ── Domain detection ──
    domain_scores: dict[str, int] = {}
    detected_signals: list[str] = []

    for domain, keywords in DOMAIN_SIGNALS.items():
        hits = [kw for kw in keywords if kw in combined]
        if hits:
            domain_scores[domain] = len(hits)
            detected_signals.extend([f"domain:{domain}:{kw}" for kw in hits[:3]])

    best_domain = "general"
    domain_confidence = 0.0
    if domain_scores:
        best_domain = max(domain_scores, key=lambda d: domain_scores[d])
        total_keywords = len(DOMAIN_SIGNALS[best_domain])
        domain_confidence = min(domain_scores[best_domain] / max(total_keywords * 0.3, 1), 1.0)

    # ── App-type detection ──
    rag_hits = sum(1 for kw in RAG_SIGNALS if kw in combined)
    agent_hits = sum(1 for kw in AGENT_SIGNALS if kw in combined)
    multi_turn_hits = sum(1 for kw in MULTI_TURN_SIGNALS if kw in combined)

    # Presence of API schema or document content is a strong signal
    if api_schema:
        agent_hits += 5
    if document_content:
        rag_hits += 5

    if rag_hits >= 3 and agent_hits >= 3:
        app_type = "hybrid"
        app_type_confidence = 0.85
    elif agent_hits >= 3:
        app_type = "agent"
        app_type_confidence = min(agent_hits / 8, 1.0)
    elif rag_hits >= 2:
        app_type = "rag"
        app_type_confidence = min(rag_hits / 7, 1.0)
    elif multi_turn_hits >= 2:
        app_type = "multi_turn_chatbot"
        app_type_confidence = min(multi_turn_hits / 5, 1.0)
    else:
        app_type = "chatbot"
        app_type_confidence = 0.6

    if rag_hits:
        detected_signals.append(f"app_type:rag:{rag_hits}_signals")
    if agent_hits:
        detected_signals.append(f"app_type:agent:{agent_hits}_signals")

    # ── Recommended attack categories ──
    recommended = _recommend_categories(best_domain, app_type)

    return ContextDetectionResult(
        domain=best_domain,
        app_type=app_type,
        domain_confidence=round(domain_confidence, 3),
        app_type_confidence=round(app_type_confidence, 3),
        detected_signals=detected_signals[:10],  # cap for payload size
        recommended_categories=recommended,
    )


def _recommend_categories(domain: str, app_type: str) -> list[str]:
    """Map domain + app_type to the most relevant attack categories."""
    cats: list[str] = []

    # Base categories always relevant
    cats.extend(["prompt_injection", "jailbreak"])

    if app_type in ("rag", "hybrid"):
        cats.extend(["indirect_injection", "rag_poisoning"])
    if app_type in ("agent", "hybrid"):
        cats.extend(["api_abuse", "indirect_injection"])
    if app_type in ("multi_turn_chatbot", "hybrid"):
        cats.extend(["multi_turn", "context_manipulation"])

    if domain == "finance":
        cats.extend(["role_play", "cognitive"])
    elif domain == "healthcare":
        cats.extend(["role_play", "payload_encoding"])
    elif domain == "legal":
        cats.extend(["context_manipulation", "cognitive"])
    elif domain == "hr":
        cats.extend(["role_play", "multi_turn"])
    elif domain == "security":
        cats.extend(["payload_encoding", "context_manipulation"])

    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for c in cats:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result
