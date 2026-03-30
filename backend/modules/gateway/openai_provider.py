import time
from backend.modules.gateway.base_provider import BaseLLMProvider, LLMConfig, LLMResponse
from backend.core.config import settings


class OpenAIProvider(BaseLLMProvider):
    name = "openai"

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=settings.openai_api_key)
        return self._client

    def is_available(self) -> bool:
        return bool(settings.openai_api_key)

    async def complete(self, prompt: str, config: LLMConfig) -> LLMResponse:
        start = time.monotonic()
        try:
            client = self._get_client()
            response = await client.chat.completions.create(
                model=config.model,
                messages=[
                    {"role": "system", "content": config.system_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=config.temperature,
                max_tokens=config.max_tokens,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            return LLMResponse(
                response_text=response.choices[0].message.content or "",
                latency_ms=latency_ms,
                tokens_used=response.usage.total_tokens if response.usage else 0,
            )
        except Exception as e:
            latency_ms = int((time.monotonic() - start) * 1000)
            return LLMResponse(response_text="", latency_ms=latency_ms, tokens_used=0, error=str(e))
