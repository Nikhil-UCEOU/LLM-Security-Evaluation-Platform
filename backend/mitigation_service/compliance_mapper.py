"""
Compliance Mapper — Maps LLM vulnerabilities to business risk frameworks.
Covers: GDPR, HIPAA, PCI-DSS, SOX, ISO 27001, NIST AI RMF, OWASP LLM Top 10.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


# ── Compliance framework definitions ────────────────────────────────────────

FRAMEWORKS: Dict[str, Dict[str, str]] = {
    "GDPR": {
        "full_name": "General Data Protection Regulation",
        "jurisdiction": "EU / Global",
        "focus": "Personal data protection and privacy rights",
        "penalty": "Up to €20M or 4% of global annual turnover",
    },
    "HIPAA": {
        "full_name": "Health Insurance Portability and Accountability Act",
        "jurisdiction": "United States",
        "focus": "Protected Health Information (PHI) security",
        "penalty": "Up to $1.9M per violation category per year",
    },
    "PCI-DSS": {
        "full_name": "Payment Card Industry Data Security Standard",
        "jurisdiction": "Global",
        "focus": "Cardholder data security",
        "penalty": "Fines + card processing suspension",
    },
    "SOX": {
        "full_name": "Sarbanes-Oxley Act",
        "jurisdiction": "United States",
        "focus": "Financial reporting integrity",
        "penalty": "Criminal penalties up to $5M and 20 years imprisonment",
    },
    "ISO27001": {
        "full_name": "ISO/IEC 27001 Information Security Management",
        "jurisdiction": "Global",
        "focus": "Information security management systems",
        "penalty": "Certification loss, audit failures",
    },
    "NIST_AI_RMF": {
        "full_name": "NIST AI Risk Management Framework",
        "jurisdiction": "United States (guidance)",
        "focus": "Trustworthy and responsible AI development",
        "penalty": "Regulatory scrutiny, procurement disqualification",
    },
    "OWASP_LLM_TOP10": {
        "full_name": "OWASP Top 10 for LLM Applications",
        "jurisdiction": "Global (guidance)",
        "focus": "Common LLM security vulnerabilities",
        "penalty": "Reputational risk, security incidents",
    },
}

# Vulnerability → compliance mapping
VULNERABILITY_COMPLIANCE_MAP: Dict[str, List[Dict[str, Any]]] = {
    "data_leakage": [
        {"framework": "GDPR",     "article": "Art. 32 – Security of processing", "risk": "HIGH",     "requirement": "Implement appropriate technical measures to prevent unauthorized data access"},
        {"framework": "HIPAA",    "article": "§164.312 – Technical safeguards",  "risk": "CRITICAL",  "requirement": "Ensure PHI is not disclosed to unauthorized entities"},
        {"framework": "PCI-DSS",  "article": "Req 3 – Protect stored cardholder data", "risk": "CRITICAL", "requirement": "Prevent transmission of cardholder data in clear text"},
        {"framework": "ISO27001", "article": "A.10 – Cryptography",               "risk": "HIGH",     "requirement": "Apply data classification and access controls"},
        {"framework": "OWASP_LLM_TOP10", "article": "LLM06 – Sensitive Information Disclosure", "risk": "HIGH", "requirement": "Prevent model from revealing training data or system prompts"},
    ],
    "direct_override": [
        {"framework": "OWASP_LLM_TOP10", "article": "LLM01 – Prompt Injection", "risk": "HIGH", "requirement": "Validate and sanitize all inputs to LLM applications"},
        {"framework": "NIST_AI_RMF", "article": "GOVERN 1.2 – Policies for AI risk", "risk": "MEDIUM", "requirement": "Establish controls against adversarial manipulation of AI systems"},
        {"framework": "ISO27001", "article": "A.14 – System acquisition, development", "risk": "MEDIUM", "requirement": "Implement security requirements for AI-based systems"},
    ],
    "role_confusion": [
        {"framework": "OWASP_LLM_TOP10", "article": "LLM02 – Insecure Output Handling", "risk": "HIGH", "requirement": "Validate LLM outputs before use in downstream systems"},
        {"framework": "NIST_AI_RMF", "article": "MANAGE 2.2 – Risk response", "risk": "MEDIUM", "requirement": "Monitor AI behavior for unexpected role changes"},
    ],
    "context_poisoning": [
        {"framework": "OWASP_LLM_TOP10", "article": "LLM03 – Training Data Poisoning", "risk": "HIGH", "requirement": "Validate integrity of training and retrieval data sources"},
        {"framework": "OWASP_LLM_TOP10", "article": "LLM08 – Excessive Agency", "risk": "HIGH", "requirement": "Limit LLM actions based on retrieved context"},
        {"framework": "ISO27001", "article": "A.12 – Operations security",             "risk": "MEDIUM", "requirement": "Monitor and validate data pipeline integrity"},
    ],
    "indirect_injection": [
        {"framework": "OWASP_LLM_TOP10", "article": "LLM01 – Prompt Injection (Indirect)", "risk": "CRITICAL", "requirement": "Treat all external content as untrusted"},
        {"framework": "GDPR", "article": "Art. 25 – Data protection by design", "risk": "HIGH", "requirement": "Design systems to prevent unauthorized data processing"},
    ],
    "api_abuse": [
        {"framework": "OWASP_LLM_TOP10", "article": "LLM08 – Excessive Agency", "risk": "CRITICAL", "requirement": "Restrict LLM tool/API access to minimum required permissions"},
        {"framework": "PCI-DSS", "article": "Req 6 – Secure systems and software", "risk": "HIGH", "requirement": "Implement API security controls and access restrictions"},
        {"framework": "SOX", "article": "§404 – Internal controls over financial reporting", "risk": "HIGH", "requirement": "Prevent unauthorized API access to financial systems"},
    ],
    "multi_turn_drift": [
        {"framework": "OWASP_LLM_TOP10", "article": "LLM04 – Model Denial of Service", "risk": "MEDIUM", "requirement": "Implement conversation integrity controls"},
        {"framework": "NIST_AI_RMF", "article": "MEASURE 2.5 – AI system monitoring", "risk": "MEDIUM", "requirement": "Continuously monitor AI behavior across conversation turns"},
    ],
    "encoding_bypass": [
        {"framework": "OWASP_LLM_TOP10", "article": "LLM01 – Prompt Injection", "risk": "HIGH", "requirement": "Decode and normalize input before security checks"},
        {"framework": "ISO27001", "article": "A.12.2 – Protection from malware", "risk": "MEDIUM", "requirement": "Implement content normalization in security filters"},
    ],
}


@dataclass
class ComplianceRisk:
    framework: str
    article: str
    risk_level: str
    requirement: str
    framework_full_name: str
    jurisdiction: str
    penalty: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "framework_full_name": self.framework_full_name,
            "article": self.article,
            "risk_level": self.risk_level,
            "requirement": self.requirement,
            "jurisdiction": self.jurisdiction,
            "penalty": self.penalty,
        }


@dataclass
class ComplianceReport:
    vulnerability_types: List[str]
    compliance_risks: List[ComplianceRisk]
    frameworks_violated: List[str]
    highest_risk: str
    total_violations: int
    remediation_priority: str
    executive_summary: str

    def to_dict(self) -> Dict[str, Any]:
        by_framework: Dict[str, List] = {}
        for r in self.compliance_risks:
            by_framework.setdefault(r.framework, []).append(r.to_dict())

        return {
            "vulnerability_types": self.vulnerability_types,
            "frameworks_violated": self.frameworks_violated,
            "highest_risk": self.highest_risk,
            "total_violations": self.total_violations,
            "remediation_priority": self.remediation_priority,
            "executive_summary": self.executive_summary,
            "by_framework": by_framework,
            "compliance_risks": [r.to_dict() for r in self.compliance_risks],
        }


def map_compliance(failure_modes: List[str], domain: str = "general") -> ComplianceReport:
    """Map a list of failure modes to compliance risks."""
    risks: List[ComplianceRisk] = []
    seen: set = set()

    for fm in failure_modes:
        mappings = VULNERABILITY_COMPLIANCE_MAP.get(fm, [])
        for mapping in mappings:
            key = f"{fm}:{mapping['framework']}:{mapping['article']}"
            if key in seen:
                continue
            seen.add(key)
            fw = FRAMEWORKS.get(mapping["framework"], {})
            risks.append(ComplianceRisk(
                framework=mapping["framework"],
                article=mapping["article"],
                risk_level=mapping["risk"],
                requirement=mapping["requirement"],
                framework_full_name=fw.get("full_name", mapping["framework"]),
                jurisdiction=fw.get("jurisdiction", "Global"),
                penalty=fw.get("penalty", "Varies"),
            ))

    frameworks_violated = list({r.framework for r in risks})
    risk_priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    highest_risk = max((r.risk_level for r in risks), key=lambda x: risk_priority.get(x, 0), default="LOW")

    priority_map = {"CRITICAL": "Immediate action required — legal and regulatory exposure",
                    "HIGH": "Address within 30 days — audit risk",
                    "MEDIUM": "Plan remediation within 90 days",
                    "LOW": "Track and remediate in next cycle"}

    executive_summary = (
        f"Identified {len(risks)} compliance risks across {len(frameworks_violated)} frameworks "
        f"({', '.join(frameworks_violated[:3])}{'...' if len(frameworks_violated) > 3 else ''}). "
        f"Highest risk level: {highest_risk}. "
        f"Primary vulnerabilities: {', '.join(failure_modes[:3])}."
    )

    return ComplianceReport(
        vulnerability_types=failure_modes,
        compliance_risks=risks,
        frameworks_violated=frameworks_violated,
        highest_risk=highest_risk,
        total_violations=len(risks),
        remediation_priority=priority_map.get(highest_risk, "Plan remediation"),
        executive_summary=executive_summary,
    )
