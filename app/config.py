"""
Configuration management for IAM Multi-Agent Security System.
Loads settings from environment variables with sensible defaults.
"""
import os
from typing import Literal
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    """App configuration from environment variables"""
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    
    environment: Literal["development", "production"] = "development"
    
    # OpenAI setup
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    
    # Anthropic (optional)
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-3-5-haiku-20241022"
    
    # Ollama for local dev
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    
    # Which LLM to use
    llm_provider: Literal["openai", "ollama", "anthropic"] = "openai"
    judge_llm_provider: Literal["openai", "ollama", "anthropic"] = "openai"
    
    # LLM params
    temperature: float = 0.0  # deterministic
    max_tokens: int = 2000
    request_timeout: int = 60
    
    # Retry config
    max_retries: int = 3
    retry_min_wait: int = 1
    retry_max_wait: int = 10
    
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()

def get_llm_config(provider: str = None) -> dict:
    """Return config dict for the specified LLM provider"""
    provider = provider or settings.llm_provider
    
    configs = {
        "openai": {
            "api_key": settings.openai_api_key,
            "model": settings.openai_model,
            "temperature": settings.temperature,
            "max_tokens": settings.max_tokens,
        },
        "ollama": {
            "base_url": settings.ollama_base_url,
            "model": settings.ollama_model,
            "temperature": settings.temperature,
        },
        "anthropic": {
            "api_key": settings.anthropic_api_key,
            "model": settings.anthropic_model,
            "temperature": settings.temperature,
            "max_tokens": settings.max_tokens,
        }
    }
    
    return configs.get(provider, configs["openai"])
