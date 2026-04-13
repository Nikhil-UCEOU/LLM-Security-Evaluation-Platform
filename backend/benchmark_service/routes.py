"""
Benchmark API Routes
POST /benchmark/run      — Run standardized benchmark
GET  /benchmark/results  — List recent results
GET  /benchmark/result/{run_id} — Get full result
GET  /benchmark/compare  — Compare multiple runs
GET  /benchmark/datasets — List available datasets
POST /benchmark/seeds    — Extract and return seeds from a dataset
GET  /benchmark/kb       — Get KB stats
"""
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

from backend.api.deps import verify_api_key
from backend.benchmark_service.benchmark_service import (
    run_benchmark, load_benchmark_results, load_benchmark_result,
    compare_benchmarks,
)
from backend.modules.dataset_engine.dataset_loader import get_available_datasets
from backend.modules.dataset_engine.seed_extractor import run_seed_pipeline
from backend.modules.dataset_engine.kb_builder import get_kb_stats, get_all_entries

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
