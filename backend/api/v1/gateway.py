from fastapi import APIRouter, Depends
from backend.schemas.gateway import GatewayRequest, GatewayResponse
from backend.modules.gateway.base_provider import LLMConfig
from backend.modules.gateway import registry
from backend.core.security import verify_api_key

router = APIRouter(prefix="/gateway", tags=["LLM Gateway"])


@router.post("/query", response_model=GatewayResponse)
async def query_llm(
    request: GatewayRequest,
    _: str = Depends(verify_api_key),
) -> GatewayResponse:
    """Send a prompt to a target LLM via the gateway."""
    config = LLMConfig(
        model=request.model,
        system_prompt=request.system_prompt,
        temperature=request.temperature,
        max_tokens=request.max_tokens,
    )
    response = await registry.query(request.provider, request.user_prompt, config)
    return GatewayResponse(
        provider=request.provider,
        model=request.model,
        response_text=response.response_text,
        latency_ms=response.latency_ms,
        tokens_used=response.tokens_used,
        error=response.error,
    )


@router.get("/providers")
async def list_providers(_: str = Depends(verify_api_key)) -> dict:
    """List all registered LLM providers."""
    return {"providers": registry.list_providers()}
