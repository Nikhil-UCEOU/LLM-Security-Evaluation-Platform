from pydantic import BaseModel, Field
from typing import Optional


class GatewayRequest(BaseModel):
    provider: str = Field(default="openai", description="LLM provider name")
    model: str = Field(default="gpt-4o-mini", description="Model identifier")
    system_prompt: str = Field(default="You are a helpful assistant.", description="System prompt")
    user_prompt: str = Field(..., description="The user/attack prompt")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1024, ge=1, le=8192)


class GatewayResponse(BaseModel):
    provider: str
    model: str
    response_text: str
    latency_ms: int
    tokens_used: int
    error: Optional[str] = None
