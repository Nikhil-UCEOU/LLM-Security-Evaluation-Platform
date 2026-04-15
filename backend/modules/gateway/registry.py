from typing import Dict, Type
from backend.modules.gateway.base_provider import BaseLLMProvider, LLMConfig, LLMResponse
from backend.modules.gateway.openai_provider import OpenAIProvider
from backend.modules.gateway.anthropic_provider import AnthropicProvider
from backend.modules.gateway.ollama_provider import OllamaProvider
from backend.modules.gateway.huggingface_provider import HuggingFaceProvider
from backend.core.exceptions import ProviderNotFoundError, ProviderAuthError


_REGISTRY: Dict[str, Type[BaseLLMProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
    "huggingface": HuggingFaceProvider,
}

_instances: Dict[str, BaseLLMProvider] = {}


def get_provider(name: str) -> BaseLLMProvider:
    """Return a cached provider instance by name."""
    if name not in _REGISTRY:
        raise ProviderNotFoundError(name)
    if name not in _instances:
        _instances[name] = _REGISTRY[name]()
    provider = _instances[name]
    if not provider.is_available():
        raise ProviderAuthError(name)
    return provider


async def query(provider_name: str, prompt: str, config: LLMConfig) -> LLMResponse:
    """High-level gateway entry point."""
    provider = get_provider(provider_name)
    return await provider.complete(prompt, config)


def list_providers() -> list[str]:
    return list(_REGISTRY.keys())
