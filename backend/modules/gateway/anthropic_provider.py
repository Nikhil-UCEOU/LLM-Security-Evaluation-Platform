import time
from backend.modules.gateway.base_provider import BaseLLMProvider, LLMConfig, LLMResponse
from backend.core.config import settings


class AnthropicProvider(BaseLLMProvider):
    name = "anthropic"

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is None:
            from anthropic import AsyncAnthropic
            self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        return self._client

    def is_available(self) -> bool:
        return bool(settings.anthropic_api_key)

    async def complete(self, prompt: str, config: LLMConfig) -> LLMResponse:
        start = time.monotonic()
        try:
            client = self._get_client()
            response = await client.messages.create(
                model=config.model,
                system=config.system_prompt,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.temperature,
                max_tokens=config.max_tokens,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            text = response.content[0].text if response.content else ""
            tokens = (response.usage.input_tokens + response.usage.output_tokens) if response.usage else 0
            return LLMResponse(response_text=text, latency_ms=latency_ms, tokens_used=tokens)
        except Exception as e:
            latency_ms = int((time.monotonic() - start) * 1000)
            return LLMResponse(response_text="", latency_ms=latency_ms, tokens_used=0, error=str(e))
