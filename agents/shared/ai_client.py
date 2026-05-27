"""
SOC Platform - Universal AI Client
عميل الذكاء الاصطناعي الشامل (متوافق مع OpenAI API)

هذا الكلاس يتيح للـ SOC الاتصال بأي نموذج لغوي (Ollama, vLLM, Llama.cpp)
بدون تغيير الكود. يدعم Structured Outputs و Tool Calling.
"""

import json
import logging
import re
import os
from typing import Optional

try:
    import openai
except ImportError:
    logging.getLogger("soc.ai").critical("openai package not found. Please pip install openai.")
    openai = None

from .config import SOCConfig
from .metrics import LLM_REQUEST_DURATION, LLM_REQUESTS_TOTAL, LLM_TOKENS_USED

logger = logging.getLogger("soc.ai")


class AIClient:
    """
    Universal AI Client wrapping OpenAI API standards.
    """

    def __init__(self, role: str = "commander", config: Optional[SOCConfig] = None):
        soc_config = config or SOCConfig.get_instance()

        # Determine the role and config
        if role == "router":
            self._cfg = getattr(soc_config, "vllm_router", soc_config.vllm_worker)
        elif role == "tactical":
            self._cfg = getattr(soc_config, "vllm_tactical", soc_config.vllm_worker)
        elif role == "commander":
            self._cfg = getattr(soc_config, "vllm_commander", soc_config.vllm_commander)
        else:
            self._cfg = soc_config.vllm_worker

        self._base_url = self._cfg.url.rstrip("/")
        if not self._base_url.endswith("/v1"):
            self._base_url = f"{self._base_url}/v1"

        self.model = self._cfg.model
        self.role = role
        self.temperature = self._cfg.temperature
        self.max_tokens = self._cfg.max_tokens

        api_key = os.environ.get("OPENAI_API_KEY", "sk-local-soc")

        if openai is None:
            raise RuntimeError("OpenAI package is required for AIClient")

        # Initialize the OpenAI Client pointing to our local API
        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=self._base_url,
            timeout=self._cfg.timeout, # type: ignore
            max_retries=2
        )
        logger.info(f"Initialized AI Client [{role}] -> {self.model} at {self._base_url}")

    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_mode: bool = False) -> str:
        """
        Generate text using the configured LLM.
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        # Some models support strict JSON mode via the API
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        start_time = time.time()
        try:
            response = self.client.chat.completions.create(**kwargs)
            duration = time.time() - start_time

            # Record Prometheus metrics
            LLM_REQUEST_DURATION.labels(model=self.model, role=self.role).observe(duration)
            LLM_REQUESTS_TOTAL.labels(model=self.model, role=self.role, status="success").inc()

            # Track token usage if available
            if response.usage:
                LLM_TOKENS_USED.labels(model=self.model, role=self.role, token_type="prompt").inc(response.usage.prompt_tokens or 0)
                LLM_TOKENS_USED.labels(model=self.model, role=self.role, token_type="completion").inc(response.usage.completion_tokens or 0)

            if response.choices:
                return response.choices[0].message.content or ""
            return ""
        except Exception as e:
            duration = time.time() - start_time
            LLM_REQUEST_DURATION.labels(model=self.model, role=self.role).observe(duration)
            LLM_REQUESTS_TOTAL.labels(model=self.model, role=self.role, status="error").inc()

            logger.error(f"AI Generation failed ({self.model}): {e}")
            # Fallback logic for SOC continuity
            if json_mode:
                return '{"incident_summary": "AI Unavailable", "overall_severity": "unknown", "actions": []}'
            return "AI unavailable - Manual analysis required."

    def extract_json(self, response_text: str) -> dict:
        """
        Safely parse JSON from LLM responses, stripping out markdown formatting.
        """
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass

        # Look for JSON block
        json_match = re.search(r'```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```', response_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except Exception:
                pass

        # Last resort: find anything resembling a JSON object
        obj_match = re.search(r'(\{.*\})', response_text, re.DOTALL)
        if obj_match:
            try:
                return json.loads(obj_match.group(1))
            except Exception:
                pass

        return {"error": "Failed to parse AI response as JSON", "raw_response": response_text}
