"""Ollama LLM client implementation (local models)."""
from typing import Optional
import httpx
from app.config import settings
from .llm_interface import LLMInterface, LLMResponse, LLMUsageStats


class OllamaClient(LLMInterface):
    """Ollama local LLM client. Free to run locally, no API costs."""
    
    def __init__(self, model: str, temperature: float = 0.0, max_tokens: int = 2000):
        super().__init__(model, temperature, max_tokens)
        self.base_url = settings.ollama_base_url
    
    async def _generate_impl(
        self,
        prompt: str,
        system_prompt: Optional[str],
        json_mode: bool,
    ) -> LLMResponse:
        """Generate completion using Ollama API."""
        
        # Build full prompt with system message
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        
        # Add JSON instruction if needed
        if json_mode:
            full_prompt += "\n\nRespond with valid JSON only."
        
        async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "num_predict": self.max_tokens,
                    }
                }
            )
            response.raise_for_status()
            result = response.json()
            content = result.get("response", "").strip()
            
            # Ollama returns some token info but it's free so cost = 0
            usage = LLMUsageStats(
                input_tokens=result.get("prompt_eval_count", 0),
                output_tokens=result.get("eval_count", 0),
                total_tokens=result.get("prompt_eval_count", 0) + result.get("eval_count", 0),
                cost_usd=0.0,  # Local = free
                model=self.model,
            )
            
            return LLMResponse(content=content, usage=usage)
    
    async def health_check(self) -> bool:
        """Check Ollama server accessibility."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception as e:
            self.logger.error("ollama_health_check_failed", error=str(e))
            return False
