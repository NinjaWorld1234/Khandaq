"""
SOC Platform - Ollama LLM Client
عميل نموذج اللغة الكبير (أولاما)

Provides SOC-specific LLM analysis capabilities:
- Alert analysis and context enrichment
- Event correlation and pattern detection
- Report generation
- Graceful fallback when the LLM service is unavailable
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from .config import SOCConfig

logger = logging.getLogger("soc.llm")

# Fallback message when Ollama is unavailable
_LLM_UNAVAILABLE = "LLM unavailable — manual analysis required."


class LLMClient:
    """
    Ollama LLM client for SOC AI analysis.
    عميل أولاما لتحليل الأمن السيبراني بالذكاء الاصطناعي

    All methods return a string result. If the LLM is down or times out,
    a fallback message is returned instead of raising an exception.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        """
        Initialize the LLM client.

        Args:
            config: SOCConfig instance. Falls back to singleton if not provided.
        """
        self._cfg = (config or SOCConfig.get_instance()).ollama
        self._base_url = self._cfg.url.rstrip("/")
        self._http = httpx.Client(timeout=self._cfg.timeout)

    # ------------------------------------------------------------------
    # Core generation / التوليد الأساسي
    # ------------------------------------------------------------------

    def _generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Send a prompt to Ollama's /api/generate endpoint.

        Args:
            prompt:        User prompt text.
            system_prompt: Optional system instruction.

        Returns:
            Generated text, or fallback message on failure.
        """
        payload: dict[str, Any] = {
            "model": self._cfg.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self._cfg.temperature,
                "num_predict": self._cfg.max_tokens,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            resp = self._http.post(
                f"{self._base_url}/api/generate",
                json=payload,
                timeout=self._cfg.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", _LLM_UNAVAILABLE)
        except httpx.TimeoutException:
            logger.warning("LLM request timed out after %ds", self._cfg.timeout)
            return _LLM_UNAVAILABLE
        except httpx.RequestError as exc:
            logger.error("LLM request failed: %s", exc)
            return _LLM_UNAVAILABLE
        except httpx.HTTPStatusError as exc:
            logger.error("LLM returned HTTP %d: %s", exc.response.status_code, exc)
            return _LLM_UNAVAILABLE

    # ------------------------------------------------------------------
    # SOC-specific analysis methods / أساليب التحليل الأمني
    # ------------------------------------------------------------------

    _SYSTEM_SOC = (
        "You are a senior SOC (Security Operations Center) analyst AI assistant. "
        "You analyze security alerts, events, and logs. Provide concise, actionable "
        "analysis in structured format. Include severity assessment, potential impact, "
        "recommended actions, and confidence level. "
        "أنت محلل أمني ذكي في مركز العمليات الأمنية."
    )

    def analyze_alert(self, alert_data: dict[str, Any]) -> str:
        """
        Analyze a single security alert and provide context.

        Args:
            alert_data: Dict containing alert fields (rule_id, description,
                        source_ip, dest_ip, agent_name, etc.)

        Returns:
            Free-text analysis string.
        """
        prompt = (
            "Analyze the following security alert and provide:\n"
            "1. **Threat Assessment**: What is happening?\n"
            "2. **Risk Level**: LOW / MEDIUM / HIGH / CRITICAL\n"
            "3. **Potential Impact**: What could happen if ignored?\n"
            "4. **Recommended Actions**: Immediate steps to take.\n"
            "5. **False Positive Likelihood**: HIGH / MEDIUM / LOW with reasoning.\n\n"
            f"Alert Data:\n```json\n{json.dumps(alert_data, indent=2, default=str)}\n```"
        )
        logger.info("Analyzing alert via LLM: %s", alert_data.get("title", "unknown"))
        return self._generate(prompt, system_prompt=self._SYSTEM_SOC)

    def generate_report(self, events: list[dict[str, Any]]) -> str:
        """
        Generate a summary report from a collection of events.

        Args:
            events: List of event dicts to summarize.

        Returns:
            Formatted report string.
        """
        # Limit event data to avoid exceeding context window
        truncated = events[:50]
        event_summary = json.dumps(truncated, indent=2, default=str)

        prompt = (
            f"Generate a concise SOC shift report based on {len(events)} events "
            f"(showing first {len(truncated)}).\n\n"
            "Include:\n"
            "1. **Executive Summary**: Key findings in 2-3 sentences.\n"
            "2. **Notable Incidents**: Top threats detected.\n"
            "3. **Statistics**: Event counts by severity/type.\n"
            "4. **Recommendations**: Priority actions for the next shift.\n\n"
            f"Events:\n```json\n{event_summary}\n```"
        )
        logger.info("Generating report for %d events via LLM", len(events))
        return self._generate(prompt, system_prompt=self._SYSTEM_SOC)

    def correlate_events(self, events: list[dict[str, Any]]) -> str:
        """
        Analyze multiple events for correlations and attack patterns.

        Args:
            events: List of event dicts that may be related.

        Returns:
            Correlation analysis string.
        """
        truncated = events[:30]
        event_data = json.dumps(truncated, indent=2, default=str)

        prompt = (
            "Analyze the following security events for correlations and patterns.\n\n"
            "Identify:\n"
            "1. **Attack Chain**: Are these events part of a multi-stage attack?\n"
            "2. **Common Indicators**: Shared IPs, domains, techniques (MITRE ATT&CK).\n"
            "3. **Timeline**: Sequence of events and progression.\n"
            "4. **Kill Chain Stage**: Reconnaissance, weaponization, delivery, "
            "exploitation, installation, C2, actions on objectives.\n"
            "5. **Confidence**: How confident are you in this correlation? (%).\n\n"
            f"Events ({len(truncated)} of {len(events)}):\n```json\n{event_data}\n```"
        )
        logger.info("Correlating %d events via LLM", len(events))
        return self._generate(prompt, system_prompt=self._SYSTEM_SOC)

    def classify_severity(self, alert_data: dict[str, Any]) -> str:
        """
        Quick severity classification for an alert.

        Args:
            alert_data: Alert fields dict.

        Returns:
            One of: INFO, LOW, MEDIUM, HIGH, CRITICAL.
        """
        prompt = (
            "Classify the severity of this security alert. "
            "Respond with EXACTLY one word: INFO, LOW, MEDIUM, HIGH, or CRITICAL.\n\n"
            f"Alert: {json.dumps(alert_data, default=str)}"
        )
        result = self._generate(prompt, system_prompt=self._SYSTEM_SOC).strip().upper()
        # Validate the response
        valid = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if result in valid:
            return result
        # Try to extract a valid severity from the response
        for sev in valid:
            if sev in result:
                return sev
        logger.warning("LLM returned invalid severity '%s', defaulting to MEDIUM", result)
        return "MEDIUM"

    # ------------------------------------------------------------------
    # Health check / فحص الصحة
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """
        Check if Ollama is reachable and the model is loaded.

        Returns:
            Dict with 'healthy' bool and model info.
        """
        try:
            resp = self._http.get(f"{self._base_url}/api/tags", timeout=10)
            resp.raise_for_status()
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            model_available = any(self._cfg.model in m for m in models)
            return {
                "healthy": True,
                "model_available": model_available,
                "configured_model": self._cfg.model,
                "available_models": models,
            }
        except Exception as exc:
            return {
                "healthy": False,
                "error": str(exc),
                "configured_model": self._cfg.model,
            }

    # ------------------------------------------------------------------
    # Cleanup / التنظيف
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the HTTP client."""
        self._http.close()

    def __enter__(self) -> LLMClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
