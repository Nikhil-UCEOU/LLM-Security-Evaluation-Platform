"""
Benchmark API Routes
POST /benchmark/run          — Run standardized benchmark
GET  /benchmark/results      — List recent results
GET  /benchmark/result/{id}  — Get full result
GET  /benchmark/compare      — Compare multiple runs
GET  /benchmark/datasets     — List available datasets
GET  /benchmark/versions     — List dataset versions
POST /benchmark/seeds        — Extract seeds from a dataset
GET  /benchmark/kb           — Get KB stats
POST /benchmark/upload       — Upload a dataset file
POST /benchmark/validate     — Validate a dataset file (dry-run)
POST /benchmark/classify     — Auto-classify attack prompts
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

from backend.api.deps import verify_api_key
from backend.benchmark_service.benchmark_service import (
    run_benchmark, load_benchmark_results, load_benchmark_result,
    compare_benchmarks,
)
from backend.modules.dataset_engine.dataset_loader import (
    get_available_datasets, get_version_info, DATASETS_ROOT,
)
from backend.modules.dataset_engine.seed_extractor import run_seed_pipeline
from backend.modules.dataset_engine.kb_builder import get_kb_stats, get_all_entries
from backend.modules.dataset_engine.dataset_validator import validate_dataset_file, validate_attacks
from backend.modules.dataset_engine.attack_classifier import classify_attack, enrich_dataset

router = APIRouter(prefix="/benchmark", tags=["Benchmark"])


class BenchmarkRunRequest(BaseModel):
    dataset: str = Field(description="Dataset folder name, e.g. 'jailbreak'")
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    system_prompt: str = "You are a helpful assistant."
    max_attacks: Optional[int] = Field(default=None, ge=1, le=100)
    categories: Optional[List[str]] = None


class SeedRequest(BaseModel):
    categories: Optional[List[str]] = None
    target_n: int = Field(default=50, ge=10, le=150)
    force_refresh: bool = False


@router.post("/run")
async def run_benchmark_endpoint(
    body: BenchmarkRunRequest,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Run a standardized benchmark. No mutation, no RL. Fully reproducible."""
    result = await run_benchmark(
        dataset_name=body.dataset,
        provider=body.provider,
        model=body.model,
        system_prompt=body.system_prompt,
        max_attacks=body.max_attacks,
        categories=body.categories,
    )
    return result.to_dict()


@router.get("/results")
def list_results(
    limit: int = Query(default=20, ge=1, le=100),
    _: str = Depends(verify_api_key),
) -> List[Dict[str, Any]]:
    """List recent benchmark runs (summary only)."""
    return load_benchmark_results(limit=limit)


@router.get("/result/{run_id}")
def get_result(
    run_id: str,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Get a full benchmark result including per-attack details."""
    result = load_benchmark_result(run_id)
    if not result:
        raise HTTPException(status_code=404, detail="Benchmark result not found")
    return result


@router.get("/compare")
def compare_results(
    run_ids: str = Query(description="Comma-separated run IDs, e.g. BM-ABC123,BM-DEF456"),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Compare multiple benchmark runs side by side."""
    ids = [r.strip() for r in run_ids.split(",") if r.strip()]
    if not ids:
        raise HTTPException(status_code=400, detail="Provide at least one run_id")
    return compare_benchmarks(ids)


@router.get("/datasets")
def list_datasets(_: str = Depends(verify_api_key)) -> List[Dict[str, Any]]:
    """List all available datasets with metadata."""
    return get_available_datasets()


@router.post("/seeds")
def extract_seeds(
    body: SeedRequest,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Extract high-quality, diverse seeds from datasets."""
    seeds = run_seed_pipeline(
        categories=body.categories,
        target_n=body.target_n,
        force_refresh=body.force_refresh,
    )
    # Group by category for response
    by_cat: Dict[str, int] = {}
    for s in seeds:
        cat = s.get("category", "unknown")
        by_cat[cat] = by_cat.get(cat, 0) + 1

    return {
        "total_seeds": len(seeds),
        "by_category": by_cat,
        "seeds": seeds,
    }


@router.get("/kb")
def get_kb(
    limit: int = Query(default=20, ge=1, le=100),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Get mitigation KB stats and recent entries."""
    stats = get_kb_stats()
    entries = get_all_entries(limit=limit)
    return {"stats": stats, "entries": entries}


@router.get("/versions")
def list_versions(_: str = Depends(verify_api_key)) -> Dict[str, Any]:
    """List available dataset versions and their metadata."""
    return get_version_info()


# ── Upload / validate / classify ──────────────────────────────────────────

_ALLOWED_EXTENSIONS = {".json", ".jsonl", ".csv", ".txt"}
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB


def _safe_filename(name: str) -> str:
    """Strip path components and dangerous chars from an upload filename."""
    import re
    name = Path(name).name
    name = re.sub(r"[^\w\-_. ]", "_", name)
    return name[:120]


@router.post("/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    category: str = Form(...),
    version: str = Form(default="v1"),
    validate_first: bool = Form(default=True),
    auto_classify: bool = Form(default=False),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Upload a dataset file (JSON / JSONL / CSV / TXT) into a versioned category folder.
    Optionally validates and auto-classifies before saving.
    """
    safe_name = _safe_filename(file.filename or "upload.json")
    suffix = Path(safe_name).suffix.lower()
    if suffix not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400,
                            detail=f"Unsupported file type '{suffix}'. Allowed: {_ALLOWED_EXTENSIONS}")

    raw = await file.read()
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 10 MB limit")

    # Parse to validate structure when JSON
    attacks_list: Optional[List[Dict]] = None
    validation_report: Optional[Dict] = None
    if suffix == ".json":
        try:
            parsed = json.loads(raw.decode("utf-8"))
            if isinstance(parsed, list):
                attacks_list = parsed
            elif isinstance(parsed, dict) and "attacks" in parsed:
                attacks_list = parsed["attacks"]
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=422, detail=f"Invalid JSON: {e}")

        if validate_first and attacks_list is not None:
            report = validate_attacks(attacks_list)
            validation_report = report.to_dict()
            if not report.is_valid:
                raise HTTPException(status_code=422, detail={
                    "message": "Dataset failed validation — fix errors and re-upload",
                    "validation": validation_report,
                })

        if auto_classify and attacks_list is not None:
            attacks_list = enrich_dataset(attacks_list)
            raw = json.dumps(attacks_list, indent=2, ensure_ascii=False).encode("utf-8")

    # Persist file
    dest_dir = DATASETS_ROOT / version / category
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / safe_name

    dest_path.write_bytes(raw)

    return {
        "saved_to": str(dest_path.relative_to(DATASETS_ROOT)),
        "category": category,
        "version": version,
        "filename": safe_name,
        "bytes": len(raw),
        "attacks_parsed": len(attacks_list) if attacks_list else None,
        "validation": validation_report,
        "auto_classified": auto_classify and attacks_list is not None,
    }


@router.post("/validate")
async def validate_upload(
    file: UploadFile = File(...),
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """
    Dry-run validation of a dataset file — does NOT save the file.
    Returns pass/fail counts and all issues found.
    """
    raw = await file.read()
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 10 MB limit")

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as e:
        return {"is_valid": False, "error": f"Invalid JSON: {e}"}

    attacks_list = parsed if isinstance(parsed, list) else parsed.get("attacks", [])
    report = validate_attacks(attacks_list)
    return report.to_dict()


class ClassifyRequest(BaseModel):
    prompts: List[str] = Field(description="List of raw attack prompts to classify")


@router.post("/classify")
def classify_prompts(
    body: ClassifyRequest,
    _: str = Depends(verify_api_key),
) -> Dict[str, Any]:
    """Auto-classify a list of raw attack prompts (category, strategy, severity, confidence)."""
    results = [classify_attack(p).to_dict() for p in body.prompts]
    by_category: Dict[str, int] = {}
    for r in results:
        cat = r["category"]
        by_category[cat] = by_category.get(cat, 0) + 1
    return {
        "total": len(results),
        "by_category": by_category,
        "results": results,
    }
