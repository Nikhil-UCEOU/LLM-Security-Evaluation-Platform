"""
SSE Streaming Evaluation Endpoint
Streams the entire evaluation pipeline as Server-Sent Events.
"""
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Optional

from backend.api.deps import verify_api_key
from backend.schemas.evaluation import EvaluationRunRequest
from backend.services.streaming_pipeline_service import stream_evaluation_pipeline
from backend.modules.context_detector.auto_context_detector import detect_context

router = APIRouter(prefix="/stream", tags=["Streaming"])


class StreamEvalRequest(BaseModel):
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    system_prompt: str = "You are a helpful assistant."
    attack_categories: List[str] = []
    max_attacks: int = 10
    include_adaptive: bool = False
    document_content: str = ""
    api_schema: str = ""
    enable_mutation: bool = False
    enable_escalation: bool = True
    min_level: int = 1
    max_level: int = 5


@router.post("/evaluate")
async def stream_evaluate(
    body: StreamEvalRequest,
    _: str = Depends(verify_api_key),
):
    """
    Stream the full evaluation pipeline as SSE events.
    No long-lived DB session is held — the pipeline creates its own short-lived
    sessions per write to avoid SQLite locking.
    """
    from backend.models.attack import AttackCategory

    cats = []
    for c in body.attack_categories:
        try:
            cats.append(AttackCategory(c))
        except ValueError:
            pass

    run_request = EvaluationRunRequest(
        provider=body.provider,
        model=body.model,
        system_prompt=body.system_prompt,
        attack_categories=cats,
        include_adaptive=body.include_adaptive,
        max_attacks=body.max_attacks,
    )

    async def generator():
        async for event in stream_evaluation_pipeline(
            request=run_request,
            document_content=body.document_content,
            api_schema=body.api_schema,
            enable_mutation=body.enable_mutation,
            enable_escalation=body.enable_escalation,
            min_level=body.min_level,
            max_level=body.max_level,
        ):
            yield event

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/detect-context")
async def detect_context_endpoint(
    body: dict,
    _: str = Depends(verify_api_key),
) -> dict:
    result = detect_context(
        system_prompt=body.get("system_prompt", ""),
        document_content=body.get("document_content", ""),
        api_schema=body.get("api_schema", ""),
    )
    return {
        "domain": result.domain,
        "app_type": result.app_type,
        "domain_confidence": result.domain_confidence,
        "app_type_confidence": result.app_type_confidence,
        "detected_signals": result.detected_signals,
        "recommended_categories": result.recommended_categories,
    }
