"""
HuggingFace Inference API Provider

Connects to HuggingFace's free/serverless inference endpoints.
Ideal for testing very weak/student-grade models that have zero safety training.

Recommended weak models (zero safety, very small):
  - EleutherAI/gpt-neo-125M         — 125M params, no safety
  - EleutherAI/gpt-neo-1.3B         — 1.3B, no safety
  - EleutherAI/gpt-j-6b             — 6B, no safety
  - bigscience/bloom-560m           — 560M, multilingual, no safety
  - facebook/opt-125m               — 125M, minimal safety
  - facebook/opt-350m               — 350M, minimal safety
  - facebook/opt-1.3b               — 1.3B, minimal safety
  - tiiuae/falcon-7b                — 7B, minimal alignment
  - mosaicml/mpt-7b                 — 7B, minimal safety
  - togethercomputer/RedPajama-INCITE-7B-Instruct — weak instruct
"""
import asyncio
import time
import os
import httpx
from backend.modules.gateway.base_provider import BaseLLMProvider, LLMConfig, LLMResponse
from backend.core.config import settings


# HuggingFace serverless inference base URL
_HF_API_BASE = "https://api-inference.huggingface.co/models"

# Recommended very weak models for attack testing
WEAK_HF_MODELS = [
    "EleutherAI/gpt-neo-125M",
    "EleutherAI/gpt-neo-1.3B",
    "bigscience/bloom-560m",
    "facebook/opt-125m",
    "facebook/opt-350m",
    "facebook/opt-1.3b",
]


class HuggingFaceProvider(BaseLLMProvider):
    """
    Provider for HuggingFace Inference API.
    Use free tier (rate-limited) or set HF_API_KEY in environment.
    """
    name = "huggingface"

    def _get_token(self) -> str:
        """Get HF API token from env or settings."""
        return (
            os.environ.get("HF_API_KEY", "")
            or os.environ.get("HUGGINGFACE_API_KEY", "")
            or getattr(settings, "huggingface_api_key", "")
        )

    def is_available(self) -> bool:
        # Available even without API key (free tier is public for many models)
        return True

    async def complete(self, prompt: str, config: LLMConfig) -> LLMResponse:
        start = time.monotonic()
        token = self._get_token()

        # Build full prompt with system prompt
        full_prompt = f"{config.system_prompt}\n\nUser: {prompt}\nAssistant:"

        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        payload = {
            "inputs": full_prompt,
            "parameters": {
                "max_new_tokens": min(config.max_tokens, 512),
                "temperature": config.temperature,
                "return_full_text": False,
                "do_sample": True,
            },
            "options": {
                "wait_for_model": True,
                "use_cache": False,
            }
        }

        url = f"{_HF_API_BASE}/{config.model}"

        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                response = await client.post(url, json=payload, headers=headers)

                if response.status_code == 503:
                    # Model loading — retry after short wait
                    await asyncio.sleep(10)
                    response = await client.post(url, json=payload, headers=headers)

                response.raise_for_status()
                data = response.json()

            latency_ms = int((time.monotonic() - start) * 1000)

            # HF returns different formats depending on the model task
            text = ""
            if isinstance(data, list) and len(data) > 0:
                item = data[0]
                text = item.get("generated_text", "") or item.get("text", "")
            elif isinstance(data, dict):
                text = data.get("generated_text", "") or data.get("text", "")

            # Strip echoed prompt if return_full_text accidentally included it
            if text.startswith(full_prompt):
                text = text[len(full_prompt):].strip()

            return LLMResponse(
                response_text=text,
                latency_ms=latency_ms,
                tokens_used=len(text.split()),
            )

        except httpx.HTTPStatusError as e:
            latency_ms = int((time.monotonic() - start) * 1000)
            status_code = e.response.status_code
            if status_code == 401:
                detail = "HuggingFace API key required. Set HF_API_KEY in environment."
            elif status_code == 429:
                detail = "HuggingFace rate limit exceeded. Add HF_API_KEY for higher limits."
            else:
                detail = f"HuggingFace API error {status_code}: {e.response.text[:200]}"
            return LLMResponse(
                response_text="",
                latency_ms=latency_ms,
                tokens_used=0,
                error=detail,
            )
        except Exception as e:
            latency_ms = int((time.monotonic() - start) * 1000)
            return LLMResponse(
                response_text="",
                latency_ms=latency_ms,
                tokens_used=0,
                error=str(e),
            )
