# SOC Platform - Worker Agent W49: Dark Web OSINT
# وكيل مراقبة تسريبات الدارك ويب
"""
Dark Web OSINT Agent
====================

Monitors OSINT feeds and Dark Web sources for corporate leaks.
Uses httpx with optional SOCKS5 (Tor) proxy support to query threat intel APIs.
Alerts if corporate keywords (domains, emails, names) appear in data breaches.

Interval: 3600 seconds (Once an hour)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.worker.w49_darkweb")


class DarkWebOSINTAgent(BaseAgent):
    """
    Dark Web & OSINT Monitor - Watches for leaked corporate data.
    وكيل مراقبة الدارك ويب والتسريبات
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w49_darkweb_osint",
            description="Monitors Dark Web and OSINT feeds for corporate leaks.",
            interval_seconds=3600,  # Run once an hour
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self.keywords = self._agent_config.get(
            "keywords", ["khandaq", "khandaq.local", "vip@khandaq.com"]
        )
        self.otx_api_url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        self.api_key = self._agent_config.get("otx_api_key", "")

        # Optional Tor/SOCKS5 Proxy Support
        proxy_url = self._agent_config.get("tor_proxy_url", None)
        self._http = httpx.Client(proxies=proxy_url) if proxy_url else httpx.Client()

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Fetch OSINT feeds and Dark Web pulses."""
        findings = []

        if not self.api_key:
            logger.debug("No API key configured. Simulating OSINT fetch.")
            # Simulate a leak for testing if no API key
            findings.append({
                "source": "Pastebin_Simulated",
                "content": "Hackers selling access to khandaq.local admin panel",
                "timestamp": time.time()
            })
            return findings

        try:
            headers = {"X-OTX-API-KEY": self.api_key}
            response = self._http.get(self.otx_api_url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            for pulse in data.get("results", []):
                try:
                    findings.append({
                        "source": f"AlienVault OTX Pulse: {pulse.get('id')}",
                        "content": str(pulse.get("description", "")) + " " + str(pulse.get("name", "")),
                        "timestamp": time.time()
                    })
                except Exception as e:
                    logger.warning("Error processing pulse: %s", e)
        except httpx.RequestError as exc:
            logger.error("Failed to fetch OSINT pulses: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan OSINT data for corporate keywords."""
        findings = []
        for item in data:
            try:
                content_lower = item.get("content", "").lower()
                for kw in self.keywords:
                    if kw.lower() in content_lower:
                        findings.append({
                            "type": "DATA_LEAK_DETECTED",
                            "severity": Severity.CRITICAL,
                            "host": "External (OSINT)",
                            "keyword": kw,
                            "source": item["source"],
                            "details": (
                                f"Corporate keyword '{kw}' found in {item['source']}. "
                                f"Content snippet: {item['content'][:150]}..."
                            ),
                        })
            except Exception as e:
                logger.warning("Error evaluating dark web item: %s", e)
        return findings

    # ------------------------------------------------------------------
    # Decide / قرار
    # ------------------------------------------------------------------
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Formulate alert and escalation actions."""
        actions = []
        for finding in findings:
            try:
                alert = {
                    "severity": finding["severity"],
                    "title": f"🚨 DARK WEB LEAK: Keyword '{finding['keyword']}' Detected",
                    "details": {
                        "source": finding["source"],
                        "keyword": finding["keyword"],
                        "details": finding["details"]
                    },
                }
                actions.append({"action": "alert", "data": alert})

                # Prepare supervisor report
                actions.append({
                    "action": "escalate",
                    "data": {
                        "type": "data_leak_report",
                        "severity": finding["severity"],
                        "title": alert["title"],
                        "details": alert["details"]
                    }
                })
            except Exception as e:
                logger.warning("Error creating alert action: %s", e)
        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Dispatch alerts and supervisor reports."""
        results = {"escalated": 0, "alerts_sent": 0}

        for action in actions:
            try:
                if action["action"] == "alert":
                    alert_data = action["data"]
                    self.alerter.send_alert(
                        severity=alert_data["severity"],
                        title=alert_data["title"],
                        details=alert_data["details"],
                        agent_name=self.name
                    )
                    results["alerts_sent"] += 1

                elif action["action"] == "escalate":
                    self.report_to_supervisor(action["data"])
                    results["escalated"] += 1
            except Exception as e:
                logger.warning("Error executing dark web action: %s", e)

        if results["alerts_sent"] > 0:
            self._events_processed += results["alerts_sent"]
            self._metrics.inc_events(results["alerts_sent"])

        return results


# ---------------------------------------------------------------------------
# Entry point / نقطة الدخول
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = DarkWebOSINTAgent()
    agent.run_loop()
