from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Application
    app_env: str = "development"
    app_secret_key: str = "change-me-in-production"
    api_key: str = "cortexflow-dev-key"

    # Database
    database_url: str = "sqlite+aiosqlite:///./cortexflow.db"

    # LLM Providers
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    google_api_key: str = ""
    cohere_api_key: str = ""
    huggingface_api_key: str = ""   # Optional — free tier works without key
    ollama_base_url: str = "http://localhost:11434"

    # Default LLM
    default_llm_provider: str = "openai"
    default_llm_model: str = "gpt-4o-mini"

    # Adaptive Attack Engine
    adaptive_attack_provider: str = "openai"
    adaptive_attack_model: str = "gpt-4o-mini"

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
