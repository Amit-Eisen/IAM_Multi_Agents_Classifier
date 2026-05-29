"""
Abstract LLM interface for agent communication.
Allows swapping between OpenAI, Ollama, Anthropic without changing agent code.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
from app.config import settings
from app.utils import get_logger

logger = get_logger(__name__)


# Pricing per 1M tokens (as of 2024, update as needed)
MODEL_PRICING = {
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
}


@dataclass
class LLMUsageStats:
    """Tracks token usage and costs for an LLM call."""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    model: str = ""


@dataclass
class LLMResponse:
    """Response from LLM including content and usage stats."""
    content: str
    usage: LLMUsageStats


class LLMInterface(ABC):
    """Abstract base class for LLM providers."""
    
    def __init__(self, model: str, temperature: float = 0.0, max_tokens: int = 2000):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.logger = logger
        # Track cumulative usage across all calls
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost_usd = 0.0
        self.call_count = 0
    
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost based on model pricing."""
        pricing = MODEL_PRICING.get(self.model, {"input": 0.0, "output": 0.0})
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        return round(input_cost + output_cost, 6)
    
    @retry(
        stop=stop_after_attempt(settings.max_retries),
        wait=wait_exponential(
            min=settings.retry_min_wait,
            max=settings.retry_max_wait
        ),
        retry=retry_if_exception_type((TimeoutError, ConnectionError)),
        reraise=True,
    )
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = True,
    ) -> str:
        """
        Generate completion from LLM.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            json_mode: Whether to enforce JSON output
            
        Returns:
            Generated text response
        """
        import time
        start_time = time.time()
        
        try:
            self.logger.info(
                "llm_request",
                model=self.model,
                prompt_length=len(prompt),
                json_mode=json_mode,
            )
            
            response = await self._generate_impl(prompt, system_prompt, json_mode)
            
            latency_ms = (time.time() - start_time) * 1000
            
            # Get usage stats if available
            usage = getattr(response, 'usage', None) if hasattr(response, 'usage') else None
            
            if isinstance(response, LLMResponse):
                content = response.content
                usage_stats = response.usage
                usage_stats.latency_ms = latency_ms
            else:
                content = response
                usage_stats = LLMUsageStats(latency_ms=latency_ms, model=self.model)
            
            # Update cumulative stats
            self.total_input_tokens += usage_stats.input_tokens
            self.total_output_tokens += usage_stats.output_tokens
            self.total_cost_usd += usage_stats.cost_usd
            self.call_count += 1
            
            self.logger.info(
                "llm_response",
                model=self.model,
                response_length=len(content),
                input_tokens=usage_stats.input_tokens,
                output_tokens=usage_stats.output_tokens,
                cost_usd=usage_stats.cost_usd,
                latency_ms=round(latency_ms, 1),
            )
            
            return content
            
        except Exception as e:
            self.logger.error(
                "llm_error",
                model=self.model,
                error=str(e),
                exc_info=True,
            )
            raise
    
    def get_total_usage(self) -> Dict[str, Any]:
        """Get cumulative usage stats for this client instance."""
        return {
            "total_calls": self.call_count,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "model": self.model,
        }
    
    @abstractmethod
    async def _generate_impl(
        self,
        prompt: str,
        system_prompt: Optional[str],
        json_mode: bool,
    ) -> str:
        """Implementation-specific generation logic."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if LLM provider is accessible."""
        pass


class LLMFactory:
    """Factory for creating LLM client instances."""
    
    @staticmethod
    def create(
        provider: str = None,
        model: str = None,
        temperature: float = None,
        max_tokens: int = None,
    ) -> LLMInterface:
        """
        Create LLM client instance.
        
        Args:
            provider: LLM provider (openai, ollama, anthropic)
            model: Model name (overrides config)
            temperature: Temperature (overrides config)
            max_tokens: Max tokens (overrides config)
            
        Returns:
            LLM client instance
        """
        from .openai_client import OpenAIClient
        from .ollama_client import OllamaClient
        
        provider = provider or settings.llm_provider
        
        # Get default config for provider
        if provider == "openai":
            model = model or settings.openai_model
            return OpenAIClient(
                model=model,
                temperature=temperature or settings.temperature,
                max_tokens=max_tokens or settings.max_tokens,
            )
        elif provider == "ollama":
            model = model or settings.ollama_model
            return OllamaClient(
                model=model,
                temperature=temperature or settings.temperature,
                max_tokens=max_tokens or settings.max_tokens,
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
