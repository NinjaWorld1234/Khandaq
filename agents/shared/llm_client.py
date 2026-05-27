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

# Fallback message when LLM is unavailable
_LLM_UNAVAILABLE = "LLM unavailable — manual analysis required."


class LLMClient:
    """
    vLLM client (OpenAI-compatible) for SOC AI analysis.
    عميل vLLM لتحليل الأمن السيبراني بالذكاء الاصطناعي

    All methods return a string result. If the LLM is down or times out,
    a fallback message is returned instead of raising an exception.
    """

    def __init__(
            self,
            config: Optional[SOCConfig] = None,
            role: str = "commander") -> None:
        """
        Initialize the LLM client.

        Args:
            config: SOCConfig instance. Falls back to singleton if not provided.
            role: "commander" or "worker". Determines which vLLM config to use.
        """
        soc_config = config or SOCConfig.get_instance()
        if role == "worker":
            self._cfg = soc_config.vllm_worker
        else:
            self._cfg = soc_config.vllm_commander

        self._base_url = self._cfg.url.rstrip("/")
        # Some setups have /v1 in the URL, others don't. We'll ensure it's
        # compatible.
        if not self._base_url.endswith("/v1"):
            self._base_url = f"{self._base_url}/v1"

        self._http = httpx.Client(timeout=self._cfg.timeout)

    # ------------------------------------------------------------------
    # Core generation / التوليد الأساسي
    # ------------------------------------------------------------------

    def _generate(
            self,
            prompt: str,
            system_prompt: Optional[str] = None) -> str:
        """
        Send a prompt to vLLM's /v1/chat/completions endpoint.

        Args:
            prompt:        User prompt text.
            system_prompt: Optional system instruction.

        Returns:
            Generated text, or fallback message on failure.
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self._cfg.model,
            "messages": messages,
            "stream": False,
            "temperature": self._cfg.temperature,
            "max_tokens": self._cfg.max_tokens,
        }

        try:
            resp = self._http.post(
                f"{self._base_url}/chat/completions",
                json=payload,
            timeout=self._cfg.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            choices = data.get("choices", [])
            if choices and len(choices) > 0:
                return choices[0].get(
                    "message", {}).get(
                    "content", _LLM_UNAVAILABLE)
            return _LLM_UNAVAILABLE
        except httpx.TimeoutException:
            logger.warning(
                "LLM request timed out after %ds",
                self._cfg.timeout)
            return _LLM_UNAVAILABLE
        except httpx.RequestError as exc:
            logger.error("LLM request failed: %s", exc)
            return _LLM_UNAVAILABLE
        except httpx.HTTPStatusError as exc:
            logger.error(
                "LLM returned HTTP %d: %s",
                exc.response.status_code,
                exc)
            return _LLM_UNAVAILABLE

    # ------------------------------------------------------------------
    # SOC-specific analysis methods / أساليب التحليل الأمني
    # ------------------------------------------------------------------

    _SYSTEM_SOC = (
        "You are a senior SOC (Security Operations Center) analyst AI assistant. "
        "You analyze security alerts, events, and logs. Provide concise, actionable "
        "analysis in structured format. Include severity assessment, potential impact, "
        "recommended actions, and confidence level. "
        "أنت محلل أمني ذكي في مركز العمليات الأمنية.")

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
            f"Alert Data:\n```json\n{json.dumps(alert_data, indent=2, default=str)}\n```")
        logger.info(
            "Analyzing alert via LLM: %s",
            alert_data.get(
                "title",
                "unknown"))
        return self._generate(prompt, system_prompt=self._SYSTEM_SOC)

    def rag_analyze_alert(
            self, alert_data: dict[str, Any], os_client: Any) -> str:
        """
        RAG-enhanced analysis. Fetches similar/recent alerts from OpenSearch
        before sending to the LLM to provide historical context.

        Args:
            alert_data: The current alert dict.
            os_client: OpenSearchClient instance.

        Returns:
            Free-text analysis string.
        """
        try:
            # Simple RAG implementation: fetch alerts from same host or IP in
            # last 24h
            host = alert_data.get("host", "unknown")
            if host != "unknown":
                query = {"match": {"host": host}}
                recent_alerts = os_client.get_events_since(
                    index="wazuh-alerts-*",
                    minutes=1440,
                    query=query,
                    size=10
                )
            else:
                recent_alerts = []

            context_str = json.dumps([a.get("description", "")
                                     for a in recent_alerts], indent=2, default=str)
        except Exception as e:
            logger.warning(f"RAG context fetch failed: {e}")
            context_str = "[]"

        prompt = (
            "Analyze the following security alert using the provided historical context.\n\n"
            "**Task**:\n"
            "1. **Threat Assessment**: What is happening?\n"
            "2. **Context Correlation**: How does this relate to the historical alerts on this host?\n"
            "3. **Risk Level**: LOW / MEDIUM / HIGH / CRITICAL\n"
            "4. **Recommended Actions**: Specific playbook steps.\n\n"
            f"**Current Alert Data**:\n```json\n{json.dumps(alert_data, indent=2, default=str)}\n```\n\n"
            f"**Historical Context (Last 24h on same host)**:\n```json\n{context_str}\n```")

        logger.info(
            "RAG Analyzing alert via LLM: %s with %d historical events",
            alert_data.get(
                "title",
                "unknown"),
            len(recent_alerts) if 'recent_alerts' in locals() else 0)
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
            f"Events:\n```json\n{event_summary}\n```")
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
            f"Events ({len(truncated)} of {len(events)}):\n```json\n{event_data}\n```")
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
            f"Alert: {json.dumps(alert_data, default=str)}")
        result = self._generate(
            prompt, system_prompt=self._SYSTEM_SOC).strip().upper()
        # Validate the response
        valid = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if result in valid:
            return result
        # Try to extract a valid severity from the response
        for sev in valid:
            if sev in result:
                return sev
        logger.warning(
            "LLM returned invalid severity '%s', defaulting to MEDIUM",
            result)
        return "MEDIUM"

    def extract_json_from_llm(self, text: str) -> Optional[dict]:
        """
        Safely extract and parse JSON from an LLM response.
        Handles markdown code blocks and extra text.
        """
        import re
        try:
            # If it's already pure JSON
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to find a JSON block
        json_match = re.search(
            r'```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```',
            text,
            re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Fallback: try to find anything that looks like a JSON object or array
        obj_match = re.search(r'(\{.*\}|\[.*\])', text, re.DOTALL)
        if obj_match:
            try:
                return json.loads(obj_match.group(1))
            except json.JSONDecodeError:
                pass

        logger.error("Failed to extract JSON from LLM response")
        return None

    # ------------------------------------------------------------------
    # Health check / فحص الصحة
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """
        Check if vLLM is reachable and the model is loaded.

        Returns:
            Dict with 'healthy' bool and model info.
        """
        try:
            resp = self._http.get(f"{self._base_url}/models", timeout=10)
            resp.raise_for_status()
            data = resp.json()
            models = [m.get("id", "") for m in data.get("data", [])]
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
