import time
import httpx
from backend.modules.gateway.base_provider import BaseLLMProvider, LLMConfig, LLMResponse
from backend.core.config import settings


class OllamaProvider(BaseLLMProvider):
    name = "ollama"

    async def complete(self, prompt: str, config: LLMConfig) -> LLMResponse:
        start = time.monotonic()
        try:
            payload = {
                "model": config.model,
                "messages": [
                    {"role": "system", "content": config.system_prompt},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": config.temperature, "num_predict": config.max_tokens},
            }
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{settings.ollama_base_url}/api/chat", json=payload)
                response.raise_for_status()
                data = response.json()

            latency_ms = int((time.monotonic() - start) * 1000)
            text = data.get("message", {}).get("content", "")
            tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
            return LLMResponse(response_text=text, latency_ms=latency_ms, tokens_used=tokens)
        except Exception as e:
            latency_ms = int((time.monotonic() - start) * 1000)
            return LLMResponse(response_text="", latency_ms=latency_ms, tokens_used=0, error=str(e))
