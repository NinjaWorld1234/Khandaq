# SOC Platform - Worker Agent W08: Data Exfiltration
# وكيل كشف تسريب وسحب البيانات من السيرفر
"""
Data Exfiltration Agent
=======================

Monitors outbound data volume for exfiltration.
Analyzes Zeek connection logs for:
1. Massive single outbound transfers (> 500MB).
2. Unusual upload-to-download ratios.
3. High cumulative data transfers over a short period.
Increases severity if these transfers occur outside normal business hours.

Interval: 120 seconds
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.worker.w08_exfiltration")


class DataExfiltrationAgent(BaseAgent):
    """
    Data Exfiltration Agent - Detects massive outbound data.
    وكيل كشف تسريب وسحب البيانات
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w08_data_exfiltration",
            description="Monitors outbound data volume for exfiltration.",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self.whitelist_ips = self._agent_config.get(
            "whitelist_ips", ["8.8.8.8", "8.8.4.4"])
        self.single_transfer_threshold = self._agent_config.get(
            "single_transfer_threshold_mb", 500) * 1024 * 1024
        self.cumulative_threshold = self._agent_config.get(
            "cumulative_threshold_mb", 100) * 1024 * 1024

    def is_outside_business_hours(self) -> bool:
        """Return True if current UTC time is outside 08:00-18:00 or is weekend."""
        now = datetime.now(timezone.utc)
        if now.weekday() >= 5:  # Saturday or Sunday
            return True
        if now.hour < 8 or now.hour >= 18:
            return True
        return False

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Zeek connection logs with byte counts."""
        query = {
            "bool": {
                "must": [
                    {"exists": {"field": "orig_bytes"}},
                    {"exists": {"field": "resp_bytes"}},
                ]
            }
        }
        try:
            return self.os_client.get_events_since(
                index="zeek-conn-*",
                minutes=2,
                query=query,
                size=10000
            )
        except Exception as e:
            logger.error("Failed to collect Zeek events: %s", e)
            return []

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify suspicious outbound data transfers."""
        findings = []
        host_bytes_out: Dict[str, float] = {}

        outside_hours = self.is_outside_business_hours()
        time_context = " (Outside Business Hours)" if outside_hours else ""

        for event in data:
            try:
                src_ip = str(event.get("id.orig_h") or "")
                dst_ip = str(event.get("id.resp_h") or "")

                try:
                    orig_bytes = float(event.get("orig_bytes") or 0.0)
                except (ValueError, TypeError):
                    orig_bytes = 0.0

                try:
                    resp_bytes = float(event.get("resp_bytes") or 0.0)
                except (ValueError, TypeError):
                    resp_bytes = 0.0

                # Skip internal traffic safely
                is_internal = False
                if dst_ip:
                    if dst_ip.startswith("10.") or dst_ip.startswith("192.168."):
                        is_internal = True
                    elif dst_ip.startswith("172."):
                        try:
                            parts = dst_ip.split('.')
                            if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
                                is_internal = True
                        except (ValueError, IndexError):
                            pass

                if is_internal:
                    continue

                if not dst_ip or dst_ip in self.whitelist_ips or not src_ip:
                    continue

                if src_ip not in host_bytes_out:
                    host_bytes_out[src_ip] = 0.0
                host_bytes_out[src_ip] += orig_bytes

                # Rule 1: Single massive transfer
                if orig_bytes > self.single_transfer_threshold:
                    severity = Severity.CRITICAL if outside_hours else Severity.HIGH
                    findings.append({
                        "type": "large_single_transfer",
                        "severity": severity,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "bytes": orig_bytes,
                        "details": f"Massive single transfer of {orig_bytes / (1024*1024):.2f} MB to {dst_ip}{time_context}"
                    })

                # Rule 2: Upload > Download unusual ratio (e.g. over 10MB
                # uploaded, and up is 5x down)
                if orig_bytes > (
                        10 *
                        1024 *
                        1024) and orig_bytes > (
                        resp_bytes *
                        5):
                    severity = Severity.HIGH if outside_hours else Severity.MEDIUM
                    findings.append({
                        "type": "unusual_upload_ratio",
                        "severity": severity,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "orig_bytes": orig_bytes,
                        "resp_bytes": resp_bytes,
                        "details": f"Unusual upload ratio to {dst_ip} (Up: {orig_bytes/1024/1024:.1f} MB, Down: {resp_bytes/1024/1024:.1f} MB){time_context}"
                    })

            except Exception as e:
                logger.warning("Error parsing bytes for event: %s", e)

        # Rule 3: Cumulative transfer anomaly across all external destinations
        for src_ip, total_bytes in host_bytes_out.items():
            try:
                if total_bytes > self.cumulative_threshold:
                    severity = Severity.CRITICAL if outside_hours else Severity.HIGH
                    findings.append({
                        "type": "high_cumulative_transfer",
                        "severity": severity,
                        "src_ip": src_ip,
                        "bytes": total_bytes,
                        "details": f"High cumulative external data transfer from {src_ip}: {total_bytes / (1024*1024):.2f} MB within 2 mins{time_context}"
                    })
            except Exception as e:
                logger.warning("Error calculating cumulative transfer: %s", e)

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    # ------------------------------------------------------------------
    # Decide / قرار
    # ------------------------------------------------------------------
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Formulate alert and escalation actions."""
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"📤 Data Exfiltration: {finding['type']}",
                "details": {
                    "src_ip": finding["src_ip"],
                    "dst_ip": finding.get("dst_ip", "MULTIPLE"),
                    "details": finding["details"]
                },
            }
            actions.append({"action": "alert", "data": alert})

            # Escalate HIGH/CRITICAL findings
            if finding["severity"] in (Severity.HIGH, Severity.CRITICAL):
                actions.append({
                    "action": "escalate",
                    "data": {
                        "type": "data_exfiltration_report",
                        "severity": finding["severity"],
                        "title": alert["title"],
                        "details": alert["details"]
                    }
                })

        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Dispatch alerts and supervisor reports."""
        results = {"alerts_sent": 0, "escalated": 0}

        for action in actions:
            if action["action"] == "alert":
                alert_data = action["data"]
                sent = self.alerter.send_alert(
                    severity=alert_data["severity"],
                    title=alert_data["title"],
                    details=alert_data["details"],
                    agent_name=self.name
                )
                if sent:
                    results["alerts_sent"] += 1
                    self._metrics.inc_alerts(alert_data["severity"].name)

            elif action["action"] == "escalate":
                self.report_to_supervisor(action["data"])
                results["escalated"] += 1

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
    agent = DataExfiltrationAgent()
    agent.run_loop()
