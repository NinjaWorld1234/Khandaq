# SOC Platform - Worker Agent W50: Zero Day Predictor
# وكيل توقع الثغرات (Zero-Day)
"""
Zero Day Predictor Agent
========================

Analyzes unknown/failed attack signatures to predict Zero-Day exploits.
Queries Wazuh alerts for low/medium severity anomalies (e.g., segfaults,
unrecognized binaries, heap corruption).
Passes these event sequences to the local SecureBERT ML model. If SecureBERT
classifies the sequence as semantically similar to a critical attack pattern
despite Wazuh not having a specific signature, it escalates it as a suspected
Zero-Day attack.

Interval: 3600 seconds (Hourly)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.securebert_client import SecureBERTClient

logger = logging.getLogger("soc.worker.w50_zeroday")


class ZeroDayPredictorAgent(BaseAgent):
    """
    Zero Day Predictor - ML-based semantic threat detection.
    وكيل توقع الثغرات قبل حدوثها باستخدام تعلم الآلة
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w50_zero_day_predictor",
            description="Analyzes unknown anomalies via SecureBERT to predict Zero-Day exploits.",
            interval_seconds=3600,  # Run hourly
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self.anomaly_threshold = self._agent_config.get("anomaly_threshold", 3)
        self._securebert: Optional[SecureBERTClient] = None

    @property
    def securebert(self) -> SecureBERTClient:
        if self._securebert is None:
            self._securebert = SecureBERTClient.get_instance()
        return self._securebert

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Fetch low/medium severity anomalies that might form an attack chain."""
        query = {
            "bool": {
                "must": [
                    # Low/Medium severity rules that shouldn't be ignored if chained
                    {"range": {"rule.level": {"gte": 3, "lte": 7}}},
                ],
                "should": [
                    {"match": {"rule.description": "segfault"}},
                    {"match": {"rule.description": "unknown binary"}},
                    {"match": {"rule.description": "heap corruption"}},
                    {"match": {"rule.description": "buffer overflow"}},
                    {"match": {"rule.description": "access denied"}},
                    {"match": {"rule.description": "process crash"}},
                ],
                "minimum_should_match": 1
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=60,
                query=query,
                size=10000
            )
        except Exception as e:
            logger.error("Failed to collect anomaly events: %s", e)
            return []

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group anomalies by host and use SecureBERT to classify semantic threat."""
        findings = []
        host_anomalies: Dict[str, List[str]] = {}

        for event in data:
            try:
                host = (event.get("agent") or {}).get("name", "unknown")
                # Extract full log text or description for ML analysis
                desc = (event.get("rule") or {}).get("description", "")
                full_log = event.get("full_log", desc)

                if host not in host_anomalies:
                    host_anomalies[host] = []
                host_anomalies[host].append(full_log)
            except Exception as e:
                logger.error("Error parsing event for ML analysis: %s", e)

        for host, anomalies in host_anomalies.items():
            try:
                if len(anomalies) >= self.anomaly_threshold:
                    # Combine anomalies into a sequence text
                    sequence_text = " | ".join(anomalies[:10])  # limit to 10 for context window

                    # Ask SecureBERT to classify the raw text semantics
                    ml_severity_str = self.securebert.classify_severity_fast(sequence_text)

                    if ml_severity_str in ("HIGH", "CRITICAL"):
                        severity = Severity.CRITICAL if ml_severity_str == "CRITICAL" else Severity.HIGH
                        findings.append({
                            "type": "potential_zero_day_recon",
                            "severity": severity,
                            "host": host,
                            "anomaly_count": len(anomalies),
                            "ml_severity": ml_severity_str,
                            "details": (
                                f"SecureBERT detected {ml_severity_str} semantic threat from "
                                f"{len(anomalies)} un-signatured faults on {host}. "
                                f"This sequence resembles a Zero-Day exploit attempt. "
                                f"Sample: {anomalies[0][:100]}..."
                            )
                        })
            except Exception as e:
                logger.warning("Error predicting zero-day for host: %s", e)
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
                    "title": f"🤖 Zero-Day Prediction: {finding['ml_severity']} Semantic Threat",
                    "details": {
                        "host": finding["host"],
                        "anomaly_count": finding["anomaly_count"],
                        "ml_confidence": finding["ml_severity"],
                        "details": finding["details"]
                    },
                }
                actions.append({"action": "alert", "data": alert})

                # Escalate directly to Detection Supervisor for correlation
                actions.append({
                    "action": "escalate",
                    "data": {
                        "type": "zeroday_prediction_report",
                        "severity": finding["severity"],
                        "title": alert["title"],
                        "details": alert["details"]
                    }
                })
            except Exception as e:
                logger.warning("Error processing prediction finding: %s", e)
        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Dispatch alerts and supervisor reports."""
        results = {"alerts_sent": 0, "escalated": 0}

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
                logger.warning("Error executing zero-day action: %s", e)

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
    agent = ZeroDayPredictorAgent()
    agent.run_loop()
