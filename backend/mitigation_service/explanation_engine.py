"""
Explainability Engine — Produces human-readable explanations for:
  * Why a mitigation was recommended
  * What failure mode it addresses
  * What the expected impact is
  * Why an attack succeeded or was blocked
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


# ── Explanation templates ──────────────────────────────────────────────────

_FAILURE_MODE_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    "direct_override": {
        "reason": "The model responded to explicit instruction-override commands in user input.",
        "root_cause": "System prompt does not establish sufficient authority precedence over user instructions.",
        "fix": "Apply prompt hardening with explicit identity anchoring and instruction hierarchy.",
        "impact": "Without this fix, any user can override safety policies with simple commands.",
        "analogy": "Like a bank teller who follows any customer's instruction, even if it contradicts their manager.",
    },
    "role_confusion": {
        "reason": "The model adopted an alternative persona that bypassed its safety restrictions.",
        "root_cause": "Model identity is not strongly anchored — it can be overridden by roleplay instructions.",
        "fix": "Apply identity anchoring and add explicit persona-rejection instructions to system prompt.",
        "impact": "Without this fix, users can impersonate system administrators or create unrestricted alter-egos.",
        "analogy": "Like an actor who, when asked to 'play a thief', actually commits theft.",
    },
    "context_poisoning": {
        "reason": "Malicious instructions were injected via retrieved documents (RAG pipeline).",
        "root_cause": "Retrieved context is treated with the same trust level as system instructions.",
        "fix": "Apply RAG sandboxing — treat document content as untrusted and isolate from instruction context.",
        "impact": "Without this fix, any document in the knowledge base can override system behavior.",
        "analogy": "Like a doctor who follows patient-written notes without verifying they're from a medical professional.",
    },
    "indirect_injection": {
        "reason": "Hidden instructions in user-provided content (emails, web pages, documents) were executed.",
        "root_cause": "The model does not distinguish between content to analyze and instructions to follow.",
        "fix": "Apply input sanitization and context isolation to mark external content as data-only.",
        "impact": "Without this fix, processing any external document becomes a security risk.",
        "analogy": "Like an assistant who executes instructions written on a sticky note found in a document.",
    },
    "api_abuse": {
        "reason": "The model made unauthorized API calls or misused its tool capabilities.",
        "root_cause": "Tool/API access is not restricted to an allowlist of safe, authorized operations.",
        "fix": "Apply tool restrictions with explicit API allowlisting and parameter validation.",
        "impact": "Without this fix, the model can be manipulated to call arbitrary APIs, leak data, or perform unauthorized actions.",
        "analogy": "Like giving an intern full admin access because they 'needed to check one thing'.",
    },
    "multi_turn_drift": {
        "reason": "The model's behavior shifted over a conversation due to gradual instruction accumulation.",
        "root_cause": "Conversation history is not sanitized — early turns can prime later unsafe behavior.",
        "fix": "Apply conversation sanitization with periodic identity reinforcement.",
        "impact": "Without this fix, patient attackers can slowly shift model behavior over many turns.",
        "analogy": "Like social engineering where trust is built slowly before the exploit.",
    },
    "data_leakage": {
        "reason": "The model revealed sensitive information (system prompt, user data, internal configuration).",
        "root_cause": "Output is not filtered for sensitive content patterns.",
        "fix": "Apply output filtering with PII detection and system-information redaction.",
        "impact": "Without this fix, attackers can extract confidential business data and system configurations.",
        "analogy": "Like leaving sensitive documents visible on a desk during a public meeting.",
    },
    "encoding_bypass": {
        "reason": "The model decoded and executed encoded instructions that bypassed keyword filters.",
        "root_cause": "Input validation does not decode common encoding schemes (base64, hex, rot13) before checking.",
        "fix": "Apply encoding-aware input validation that normalizes content before safety checks.",
        "impact": "Without this fix, simple encoding defeats all keyword-based filters.",
        "analogy": "Like a security guard who checks bags for weapons but doesn't look inside locked containers.",
    },
}

_TECHNIQUE_EXPLANATIONS: Dict[str, str] = {
    "MIT-001": "Injects explicit safety boundaries into the system prompt, establishing clear rules the model must follow.",
    "MIT-002": "Anchors the model's identity so it resists attempts to assume alternative personas.",
    "MIT-003": "Creates a defined trust hierarchy: system instructions > operator instructions > user requests.",
    "MIT-004": "Validates and normalizes all user input before it reaches the model, stripping injection patterns.",
    "MIT-005": "Decodes encoded content (base64, hex, etc.) and checks for hidden malicious instructions.",
    "MIT-006": "Separates retrieved document content from the instruction context to prevent RAG poisoning.",
    "MIT-007": "Labels and tracks the source of each piece of context so the model knows what to trust.",
    "MIT-008": "Sanitizes conversation history to prevent gradual behavior drift across turns.",
    "MIT-009": "Filters model outputs for sensitive patterns (PII, credentials, system information).",
    "MIT-010": "Validates that responses align with the stated system purpose and refuse outliers.",
    "MIT-011": "Adds role-specific safety rules based on the deployment domain (finance, healthcare, etc.).",
    "MIT-012": "Restricts available tools/APIs to an explicit allowlist of safe operations.",
    "MIT-013": "Validates all tool parameters before execution to prevent parameter injection.",
    "MIT-014": "Wraps tool execution in a sandbox to prevent side effects and data leakage.",
    "MIT-015": "Detects and blocks adversarial prompts using ML-based classifiers.",
    "MIT-016": "Implements multi-stage verification for high-risk operations.",
    "MIT-017": "Adds audit logging for all sensitive operations and model outputs.",
    "MIT-018": "Enforces rate limiting and anomaly detection to prevent sustained attack campaigns.",
}


@dataclass
class MitigationExplanation:
    failure_mode: str
    reason: str
    root_cause: str
    fix: str
    impact: str
    analogy: str
    technique_explanations: List[Dict[str, str]]
    confidence: float
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failure_mode": self.failure_mode,
            "reason": self.reason,
            "root_cause": self.root_cause,
            "fix": self.fix,
            "impact": self.impact,
            "analogy": self.analogy,
            "technique_explanations": self.technique_explanations,
            "confidence": round(self.confidence, 2),
            "summary": self.summary,
        }


@dataclass
class AttackExplanation:
    attack_prompt: str
    why_it_worked: str
    vulnerability_class: str
    mitigations_that_block_it: List[str]
    difficulty: str   # trivial | easy | moderate | hard | expert

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_prompt_preview": self.attack_prompt[:200],
            "why_it_worked": self.why_it_worked,
            "vulnerability_class": self.vulnerability_class,
            "mitigations_that_block_it": self.mitigations_that_block_it,
            "difficulty": self.difficulty,
        }


def explain_mitigation(
    failure_mode: str,
    applied_techniques: List[str],
    isr_before: float,
    isr_after: float,
) -> MitigationExplanation:
    """
    Generate a human-readable explanation for why a mitigation was chosen and what it does.
    """
    fm_data = _FAILURE_MODE_EXPLANATIONS.get(
        failure_mode,
        {
            "reason": f"Attack exploited a vulnerability in the '{failure_mode}' category.",
            "root_cause": "The system prompt and input pipeline lacked sufficient defenses for this attack vector.",
            "fix": "Apply prompt hardening and input validation as baseline defenses.",
            "impact": "Unrestricted, this vulnerability allows attackers to manipulate model behavior.",
            "analogy": "Like leaving a door unlocked because no one had tried it yet.",
        }
    )

    tech_explanations = [
        {"id": t, "explanation": _TECHNIQUE_EXPLANATIONS.get(t, f"Applies defense technique {t}.")}
        for t in applied_techniques
    ]

    improvement = isr_before - isr_after
    confidence = min(1.0, 0.5 + improvement * 1.5)

    summary = (
        f"The mitigation addresses '{failure_mode}' by applying {len(applied_techniques)} "
        f"defense techniques, reducing attack success rate from "
        f"{round(isr_before*100)}% to {round(isr_after*100)}% "
        f"(−{round(improvement*100)}pp improvement)."
    )

    return MitigationExplanation(
        failure_mode=failure_mode,
        reason=fm_data["reason"],
        root_cause=fm_data["root_cause"],
        fix=fm_data["fix"],
        impact=fm_data["impact"],
        analogy=fm_data["analogy"],
        technique_explanations=tech_explanations,
        confidence=round(confidence, 2),
        summary=summary,
    )


def explain_attack_success(attack_prompt: str, category: str) -> AttackExplanation:
    """Explain why a specific attack succeeded and how to block it."""
    explanations: Dict[str, Dict] = {
        "jailbreak": {
            "why": "The model's safety training can be bypassed by framing the request as roleplay, "
                   "hypothetical, or by impersonating an authorized entity (DAN, developer mode, etc.).",
            "vuln": "Insufficient identity anchoring and instruction hierarchy in system prompt.",
            "mitigations": ["MIT-001", "MIT-002", "MIT-015"],
            "difficulty": "easy",
        },
        "prompt_injection": {
            "why": "The model treats user-provided content as trusted instructions, allowing attackers "
                   "to override the system prompt by embedding override commands in their input.",
            "vuln": "No separation between instruction context and user data context.",
            "mitigations": ["MIT-001", "MIT-004", "MIT-005"],
            "difficulty": "moderate",
        },
        "rag": {
            "why": "The RAG pipeline fetches external documents that contain hidden malicious instructions. "
                   "The model executes these instructions because it trusts the retrieval context.",
            "vuln": "Retrieved documents are given the same trust level as system instructions.",
            "mitigations": ["MIT-006", "MIT-007", "MIT-009"],
            "difficulty": "hard",
        },
        "tool_misuse": {
            "why": "The model's tool-calling capability was manipulated to invoke unauthorized APIs "
                   "or pass malicious parameters to legitimate tools.",
            "vuln": "No tool allowlist or parameter validation in place.",
            "mitigations": ["MIT-012", "MIT-013", "MIT-014"],
            "difficulty": "expert",
        },
    }

    data = explanations.get(category, {
        "why": "The attack exploited a gap in the model's safety defenses.",
        "vuln": "Insufficient defense layers for this attack vector.",
        "mitigations": ["MIT-001", "MIT-004"],
        "difficulty": "moderate",
    })

    return AttackExplanation(
        attack_prompt=attack_prompt,
        why_it_worked=data["why"],
        vulnerability_class=data["vuln"],
        mitigations_that_block_it=data["mitigations"],
        difficulty=data["difficulty"],
    )
