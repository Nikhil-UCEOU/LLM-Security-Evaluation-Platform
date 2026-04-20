"""
Detection Engine API — Multi-layer prompt injection detection endpoints.

Provides:
- POST /detection/analyze: Analyze a prompt for threats (all layers)
- POST /detection/batch: Batch analyze multiple prompts
- GET /detection/rules: List all detection rules
- POST /detection/owasp-map: Map evaluation results to OWASP Top 10
- GET /owasp/risks: Get OWASP LLM Top 10 risk definitions
- POST /owasp/assess: Run OWASP risk assessment on attack results
"""
from __future__ import annotations

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.modules.detection_engine.detection_engine import (
    get_detection_engine, DetectionResult
)
from backend.modules.detection_engine.rule_detector import DETECTION_RULES
from backend.modules.attack_engine.owasp_attack_mapper import (
    map_evaluation_to_owasp,
    get_owasp_risk_summary,
    prioritize_risks,
    infer_owasp_risk,
)
from backend.modules.attack_engine.hybrid_attack_generator import generate_hybrid_attacks

router = APIRouter(prefix="/detection", tags=["detection"])
owasp_router = APIRouter(prefix="/owasp", tags=["owasp"])
attack_router_extra = APIRouter(prefix="/attacks/hybrid", tags=["attacks"])


# ── Request / Response Models ─────────────────────────────────────────────────

class DetectRequest(BaseModel):
    prompt: str
    response: Optional[str] = None
    strictness: str = "moderate"
    domain: str = "general"


class BatchDetectRequest(BaseModel):
    prompts: List[str]
    strictness: str = "moderate"
    domain: str = "general"


class OWASPAssessRequest(BaseModel):
    attack_results: List[Dict[str, Any]]


class HybridAttackRequest(BaseModel):
    count: int = 10


# ── Detection Endpoints ───────────────────────────────────────────────────────

@router.post("/analyze")
async def analyze_prompt(req: DetectRequest) -> Dict[str, Any]:
    """
    Run multi-layer detection on a prompt.
    Returns threat assessment with rule matches, similarity score,
    OWASP risk mapping, and recommended action.
    """
    engine = get_detection_engine(req.strictness)
    result = engine.detect(req.prompt, response=req.response, domain=req.domain)
    return result.to_dict()


@router.post("/batch")
async def batch_analyze(req: BatchDetectRequest) -> Dict[str, Any]:
    """
    Run detection on a batch of prompts.
    Returns aggregate statistics and per-prompt results.
    """
    if len(req.prompts) > 100:
        raise HTTPException(400, "Batch size limited to 100 prompts")

    engine = get_detection_engine(req.strictness)
    results = engine.batch_detect(req.prompts, domain=req.domain)

    # Aggregate stats
    decisions = [r.decision for r in results]
    blocked = sum(1 for d in decisions if d == "block")
    warned = sum(1 for d in decisions if d == "warn")
    allowed = sum(1 for d in decisions if d == "allow")

    avg_risk = sum(r.risk_score for r in results) / len(results) if results else 0

    return {
        "total": len(results),
        "blocked": blocked,
        "warned": warned,
        "allowed": allowed,
        "average_risk_score": round(avg_risk, 3),
        "results": [r.to_dict() for r in results],
    }


@router.get("/rules")
async def list_rules() -> Dict[str, Any]:
    """List all detection rules with metadata."""
    rules = [
        {
            "rule_id": rule_id,
            "threat_type": threat_type,
            "severity": severity,
            "owasp_risk": owasp_risk,
            "description": description,
            "confidence": confidence,
        }
        for rule_id, pattern, threat_type, severity, owasp_risk, description, confidence
        in DETECTION_RULES
    ]

    # Group by severity
    by_severity: Dict[str, int] = {}
    for r in rules:
        sev = r["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total_rules": len(rules),
        "by_severity": by_severity,
        "rules": rules,
    }


@router.post("/learn")
async def add_signature(body: Dict[str, str]) -> Dict[str, Any]:
    """
    Add a confirmed malicious prompt as a new detection signature.
    Enables online learning from confirmed attack examples.
    """
    prompt = body.get("prompt", "").strip()
    if not prompt or len(prompt) < 10:
        raise HTTPException(400, "Prompt must be at least 10 characters")

    engine = get_detection_engine()
    engine.update_signature(prompt)

    return {"status": "signature_added", "prompt_length": len(prompt)}


# ── OWASP Endpoints ───────────────────────────────────────────────────────────

@owasp_router.get("/risks")
async def get_owasp_risks() -> Dict[str, Any]:
    """Get OWASP LLM Top 10 risk definitions for UI display."""
    risks = get_owasp_risk_summary()
    return {
        "framework": "OWASP LLM Application Security Top 10",
        "version": "2023",
        "total_risks": len(risks),
        "risks": risks,
    }


@owasp_router.post("/assess")
async def assess_owasp_risk(req: OWASPAssessRequest) -> Dict[str, Any]:
    """
    Map evaluation results to OWASP LLM Top 10 risk categories.
    Returns risk-level assessment per OWASP category.
    """
    if not req.attack_results:
        raise HTTPException(400, "No attack results provided")

    assessments = map_evaluation_to_owasp(req.attack_results)
    prioritized = prioritize_risks(assessments)

    # Build summary
    critical_risks = [a for a in prioritized if a.attack_count > 0 and a.success_rate >= 0.6]
    high_risks = [a for a in prioritized if a.attack_count > 0 and 0.3 <= a.success_rate < 0.6]

    return {
        "total_attacks": len(req.attack_results),
        "risks_assessed": len(assessments),
        "critical_risks": len(critical_risks),
        "high_risks": len(high_risks),
        "prioritized_risks": [a.to_dict() for a in prioritized],
        "assessments": {k: v.to_dict() for k, v in assessments.items()},
    }


@owasp_router.get("/infer/{attack_id}")
async def infer_attack_risk(attack_id: str, category: str = "", tags: str = "") -> Dict[str, str]:
    """Infer OWASP risk for an attack based on its metadata."""
    attack_dict = {
        "id": attack_id,
        "category": category,
        "tags": [t.strip() for t in tags.split(",") if t.strip()],
    }
    return {"attack_id": attack_id, "owasp_risk": infer_owasp_risk(attack_dict)}


# ── Hybrid Attack Generation Endpoints ───────────────────────────────────────

@attack_router_extra.post("/generate")
async def generate_hybrid(req: HybridAttackRequest) -> Dict[str, Any]:
    """Generate hybrid composite attacks combining multiple techniques."""
    if req.count > 50:
        raise HTTPException(400, "Count limited to 50 per request")

    attacks = generate_hybrid_attacks(req.count)
    return {
        "count": len(attacks),
        "attacks": attacks,
        "techniques_used": list({t for a in attacks for t in a.get("techniques", [])}),
    }
