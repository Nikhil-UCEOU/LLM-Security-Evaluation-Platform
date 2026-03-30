from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMConfig:
    model: str
    system_prompt: str = "You are a helpful assistant."
    temperature: float = 0.7
    max_tokens: int = 1024


@dataclass
class LLMResponse:
    response_text: str
    latency_ms: int
    tokens_used: int
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None


class BaseLLMProvider(ABC):
    """Abstract base class for all LLM providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name identifier."""
        ...

    @abstractmethod
    async def complete(self, prompt: str, config: LLMConfig) -> LLMResponse:
        """Send prompt to the LLM and return the response."""
        ...

    def is_available(self) -> bool:
        """Check if the provider is configured and available."""
        return True
