# SOC Platform - Worker Agent W48: Hardware Anomaly
# وكيل كشف التلاعب بموارد الخادم (تعدين، حرارة)
"""
Hardware Anomaly Agent
======================

Monitors hardware metrics (CPU, Temperature) to detect cryptojacking
or denial-of-service via resource exhaustion.
Queries OpenSearch for hardware metrics sent by Wazuh/Metricbeat.
If CPU is sustained above 95% for 30 minutes, it flags a warning.
If Temperature exceeds 85C alongside high CPU, it escalates as CRITICAL.

Interval: 300 seconds (Every 5 minutes)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.worker.w48_hardware")


class HardwareAnomalyAgent(BaseAgent):
    """
    Hardware Anomaly Agent - Detects cryptojacking and thermal threats.
    وكيل كشف الشذوذ في الموارد الصلبة
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w48_hardware_anomaly",
            description="Monitors hardware metrics (CPU, Temp) for cryptojacking.",
            interval_seconds=300,  # Run every 5 minutes
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self.cpu_threshold_pct = self._agent_config.get("cpu_threshold_pct", 95.0)
        self.cpu_sustained_minutes = self._agent_config.get("cpu_sustained_minutes", 30)

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Wazuh system inventory or Metricbeat data indicating high CPU/Temp."""
        query = {
            "bool": {
                "must": [
                    {"match": {"rule.groups": "hardware_monitor"}},
                ]
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=self.cpu_sustained_minutes,
                query=query,
                size=10000
            )
        except Exception as e:
            logger.error("Failed to collect hardware events: %s", e)
            return []

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify sustained high CPU and dangerous temperatures."""
        findings = []
        host_stats: Dict[str, Dict[str, Any]] = {}

        for event in data:
            try:
                agent_name = (event.get("agent") or {}).get("name", "unknown")
                # Parse numeric hardware metrics
                data_dict = event.get("data") or {}
                hw_dict = data_dict.get("hardware") or {}
                cpu_usage = float(hw_dict.get("cpu_pct", 0))
                temp_celsius = float(hw_dict.get("temp_c", 0))

                if agent_name not in host_stats:
                    host_stats[agent_name] = {"high_cpu_hits": 0, "max_temp": 0.0}

                if cpu_usage > self.cpu_threshold_pct:
                    host_stats[agent_name]["high_cpu_hits"] += 1

                if temp_celsius > host_stats[agent_name]["max_temp"]:
                    host_stats[agent_name]["max_temp"] = temp_celsius

            except (ValueError, TypeError) as e:
                logger.debug("Skipping event due to parse error: %s", e)

        for host, stats in host_stats.items():
            try:
                # If CPU is maxed out in most of our 5-minute polling intervals over the last 30 minutes
                # (Assuming Wazuh sends metrics every 5 mins -> 6 hits max)
                expected_hits = (self.cpu_sustained_minutes / 5) * 0.8
                if stats["high_cpu_hits"] >= expected_hits and stats["high_cpu_hits"] > 0:

                    severity = Severity.HIGH
                    # Thermal danger zone
                    if stats["max_temp"] > 85.0:
                        severity = Severity.CRITICAL

                    findings.append({
                        "type": "suspected_cryptojacking",
                        "severity": severity,
                        "host": host,
                        "max_temp": stats["max_temp"],
                        "high_cpu_hits": stats["high_cpu_hits"],
                        "details": (
                            f"Sustained >{self.cpu_threshold_pct}% CPU usage over "
                            f"{self.cpu_sustained_minutes} mins on {host}. "
                            f"Max Temp: {stats['max_temp']}°C"
                        )
                    })
            except Exception as e:
                logger.warning("Error evaluating hardware stats: %s", e)

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
                    "title": f"🔥 Hardware Anomaly: {finding['type']}",
                    "details": {
                        "host": finding["host"],
                        "max_temp_celsius": finding["max_temp"],
                        "high_cpu_hits": finding["high_cpu_hits"],
                        "details": finding["details"]
                    },
                }
                actions.append({"action": "alert", "data": alert})

                # Escalate critical hardware issues directly to Response Supervisor
                # to potentially isolate the box or kill unknown miners.
                if finding["severity"] == Severity.CRITICAL:
                    actions.append({
                        "action": "escalate",
                        "data": {
                            "type": "hardware_critical_report",
                            "severity": finding["severity"],
                            "title": alert["title"],
                            "details": alert["details"]
                        }
                    })
            except Exception as e:
                logger.warning("Error evaluating hardware finding: %s", e)
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
                logger.warning("Error executing hardware action: %s", e)

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
    agent = HardwareAnomalyAgent()
    agent.run_loop()
