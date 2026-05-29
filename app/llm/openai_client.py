"""OpenAI LLM client implementation."""
from typing import Optional
from openai import AsyncOpenAI
from app.config import settings
from .llm_interface import LLMInterface, LLMResponse, LLMUsageStats


class OpenAIClient(LLMInterface):
    """OpenAI API client with usage tracking."""
    
    def __init__(self, model: str, temperature: float = 0.0, max_tokens: int = 2000):
        super().__init__(model, temperature, max_tokens)
        self.client = AsyncOpenAI(
            api_key=settings.openai_api_key,
            timeout=settings.request_timeout,
        )
    
    async def _generate_impl(
        self,
        prompt: str,
        system_prompt: Optional[str],
        json_mode: bool,
    ) -> LLMResponse:
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        params = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        
        # JSON mode works with gpt-4/3.5 models
        if json_mode and ("gpt-4" in self.model or "gpt-3.5" in self.model):
            params["response_format"] = {"type": "json_object"}
        
        response = await self.client.chat.completions.create(**params)
        
        content = response.choices[0].message.content.strip()
        
        # Extract usage info
        input_tokens = response.usage.prompt_tokens if response.usage else 0
        output_tokens = response.usage.completion_tokens if response.usage else 0
        total_tokens = response.usage.total_tokens if response.usage else 0
        
        cost = self.estimate_cost(input_tokens, output_tokens)
        
        usage = LLMUsageStats(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cost_usd=cost,
            model=self.model,
        )
        
        return LLMResponse(content=content, usage=usage)
    
    async def health_check(self) -> bool:
        """Quick health check"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5,
            )
            return bool(response.choices)
        except Exception as e:
            self.logger.error("openai_health_check_failed", error=str(e))
            return False
