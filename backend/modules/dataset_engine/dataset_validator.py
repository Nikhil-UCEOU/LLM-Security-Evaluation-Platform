"""
Dataset Validator — validates attack datasets before loading.
Checks: required fields, duplicate prompts, prompt quality, field types, severity enum.
Returns a ValidationReport with pass/fail/warnings per attack.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CATEGORIES = {"jailbreak", "prompt_injection", "rag", "tool_misuse", "adversarial", "unknown"}
REQUIRED_FIELDS = ("id", "prompt", "category", "strategy", "severity")
MIN_PROMPT_LENGTH = 15
MAX_PROMPT_LENGTH = 8000


@dataclass
class AttackIssue:
    attack_id: str
    level: str        # "error" | "warning"
    code: str         # machine-readable code
    message: str


@dataclass
class ValidationReport:
    total: int
    passed: int
    failed: int
    warnings: int
    issues: List[AttackIssue] = field(default_factory=list)
    duplicate_ids: List[str] = field(default_factory=list)
    duplicate_prompts: List[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "is_valid": self.is_valid,
            "duplicate_ids": self.duplicate_ids,
            "duplicate_prompts": self.duplicate_prompts,
            "issues": [
                {"attack_id": i.attack_id, "level": i.level, "code": i.code, "message": i.message}
                for i in self.issues
            ],
        }


def _prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.strip().lower().encode()).hexdigest()[:16]


def validate_attacks(attacks: List[Dict[str, Any]]) -> ValidationReport:
    """
    Validate a list of raw attack dicts (before NormalizedAttack conversion).
    Returns a ValidationReport.
    """
    issues: List[AttackIssue] = []
    seen_ids: Dict[str, int] = {}
    seen_hashes: Dict[str, str] = {}
    dup_ids: List[str] = []
    dup_prompts: List[str] = []
    failed_ids: set = set()

    for idx, attack in enumerate(attacks):
        aid = str(attack.get("id", f"<index-{idx}>"))

        # ── Duplicate ID check ───────────────────────────────────────────
        if aid in seen_ids:
            issues.append(AttackIssue(aid, "error", "DUPLICATE_ID",
                                       f"ID '{aid}' appears more than once"))
            if aid not in dup_ids:
                dup_ids.append(aid)
            failed_ids.add(aid)
        seen_ids[aid] = idx

        # ── Required fields ──────────────────────────────────────────────
        for f in REQUIRED_FIELDS:
            if not attack.get(f):
                issues.append(AttackIssue(aid, "error", "MISSING_FIELD",
                                           f"Required field '{f}' is missing or empty"))
                failed_ids.add(aid)

        # ── Prompt quality ───────────────────────────────────────────────
        prompt = attack.get("prompt", "")
        if isinstance(prompt, str):
            if len(prompt.strip()) < MIN_PROMPT_LENGTH:
                issues.append(AttackIssue(aid, "error", "PROMPT_TOO_SHORT",
                                           f"Prompt is too short ({len(prompt.strip())} chars, min {MIN_PROMPT_LENGTH})"))
                failed_ids.add(aid)
            elif len(prompt) > MAX_PROMPT_LENGTH:
                issues.append(AttackIssue(aid, "warning", "PROMPT_TOO_LONG",
                                           f"Prompt exceeds {MAX_PROMPT_LENGTH} chars — may impact performance"))

            # Duplicate prompt content
            ph = _prompt_hash(prompt)
            if ph in seen_hashes:
                other_id = seen_hashes[ph]
                issues.append(AttackIssue(aid, "warning", "DUPLICATE_PROMPT",
                                           f"Prompt content is identical to attack '{other_id}'"))
                if aid not in dup_prompts:
                    dup_prompts.append(aid)
            else:
                seen_hashes[ph] = aid
        else:
            issues.append(AttackIssue(aid, "error", "INVALID_PROMPT_TYPE",
                                       "Field 'prompt' must be a string"))
            failed_ids.add(aid)

        # ── Severity enum ────────────────────────────────────────────────
        severity = attack.get("severity", "")
        if severity and severity not in VALID_SEVERITIES:
            issues.append(AttackIssue(aid, "error", "INVALID_SEVERITY",
                                       f"Severity '{severity}' not in {VALID_SEVERITIES}"))
            failed_ids.add(aid)

        # ── Category check (soft warning) ────────────────────────────────
        category = attack.get("category", "")
        if category and category not in VALID_CATEGORIES:
            issues.append(AttackIssue(aid, "warning", "UNKNOWN_CATEGORY",
                                       f"Category '{category}' is non-standard — consider normalizing"))

        # ── Tags type ────────────────────────────────────────────────────
        tags = attack.get("tags")
        if tags is not None and not isinstance(tags, list):
            issues.append(AttackIssue(aid, "warning", "INVALID_TAGS_TYPE",
                                       "Field 'tags' should be a list of strings"))

    total = len(attacks)
    failed = len(failed_ids)
    warnings = sum(1 for i in issues if i.level == "warning")
    passed = total - failed

    return ValidationReport(
        total=total,
        passed=passed,
        failed=failed,
        warnings=warnings,
        issues=issues,
        duplicate_ids=dup_ids,
        duplicate_prompts=dup_prompts,
    )


def validate_dataset_file(path: str) -> ValidationReport:
    """Load and validate a JSON dataset file."""
    import json
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        return ValidationReport(0, 0, 0, 0, issues=[
            AttackIssue("<file>", "error", "FILE_NOT_FOUND", f"File not found: {path}")
        ])

    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return ValidationReport(0, 0, 0, 0, issues=[
            AttackIssue("<file>", "error", "JSON_PARSE_ERROR", f"Invalid JSON: {e}")
        ])

    if isinstance(raw, list):
        return validate_attacks(raw)
    elif isinstance(raw, dict) and "attacks" in raw:
        return validate_attacks(raw["attacks"])
    else:
        return ValidationReport(0, 0, 0, 0, issues=[
            AttackIssue("<file>", "error", "UNEXPECTED_FORMAT",
                         "Expected a JSON array or an object with 'attacks' key")
        ])
