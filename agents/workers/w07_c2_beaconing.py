# SOC Platform - Worker Agent W07: C2 Beaconing
# وكيل كشف نبضات القيادة والسيطرة للهاكرز
"""
C2 Beaconing Agent
==================

Monitors connections for periodic beaconing patterns indicative of Command & Control.
Analyzes network connection logs (e.g. from Zeek/Suricata) via OpenSearch.
Groups connections by Source-Destination IP pairs.
Calculates the mean interval between connections, the variance (Jitter),
and checks for consistent packet sizes.

If variance < 10% -> Highly regular beaconing (CRITICAL)
If variance < 20% -> Jittered beaconing (HIGH)

Interval: 120 seconds
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.worker.w07_c2_beaconing")


class C2BeaconingAgent(BaseAgent):
    """
    C2 Beaconing Agent - Detects periodic malware callbacks.
    وكيل كشف قنوات القيادة والسيطرة
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w07_c2_beaconing",
            description="Monitors connection jitter and packet sizes for C2 beaconing.",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self.min_connections = self._agent_config.get("min_connections", 10)
        self.window_minutes = self._agent_config.get("window_minutes", 60)

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Fetch network connection logs from OpenSearch."""
        # Note: We look at zeek-conn-* or any index that provides connection
        # stats
        query = {
            "bool": {
                "must": [
                    {"exists": {"field": "id.orig_h"}},
                    {"exists": {"field": "id.resp_h"}},
                    {"exists": {"field": "orig_bytes"}},
                ]
            }
        }
        try:
            return self.os_client.get_events_since(
                index="zeek-conn-*",
                minutes=self.window_minutes,
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
        """Calculate Jitter (variance) and packet size consistency."""
        findings = []
        connections: Dict[str, List[Dict[str, float]]] = {}

        for event in data:
            try:
                src_ip = str(event.get("id.orig_h") or "")
                dst_ip = str(event.get("id.resp_h") or "")

                ts_val = event.get("ts")
                ts = float(ts_val) if ts_val is not None else 0.0

                orig_bytes_val = event.get("orig_bytes")
                orig_bytes = float(
                    orig_bytes_val) if orig_bytes_val is not None else 0.0

                # Ignore internal traffic for C2 checks
                if dst_ip and (dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or (
                        dst_ip.startswith("172.") and 16 <= int(dst_ip.split('.')[1]) <= 31)):
                    continue

                if not src_ip or not dst_ip or ts == 0:
                    continue

                pair_key = f"{src_ip}->{dst_ip}"
                if pair_key not in connections:
                    connections[pair_key] = []
                connections[pair_key].append({"ts": ts, "bytes": orig_bytes})

            except Exception as e:
                logger.warning("Error parsing event: %s", e)

        # Analyze intervals and byte consistency
        for pair_key, conn_data in connections.items():
            try:
                if len(conn_data) < self.min_connections:
                    continue

                conn_data.sort(key=lambda x: x["ts"])
                intervals = [
                    conn_data[i]["ts"] - conn_data[i - 1]["ts"]
                    for i in range(1, len(conn_data))
                ]

                bytes_list = [c["bytes"] for c in conn_data]

                mean_interval = sum(intervals) / len(intervals)
                if mean_interval == 0:
                    continue

                # Std Dev for intervals
                variance_sq = sum(
                    (x - mean_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = math.sqrt(variance_sq)
                variance_pct = (std_dev / mean_interval) * 100

                # Std Dev for payload size
                mean_bytes = sum(bytes_list) / len(bytes_list)
                byte_variance_sq = sum(
                    (x - mean_bytes) ** 2 for x in bytes_list) / len(bytes_list)
                byte_std_dev = math.sqrt(byte_variance_sq)
                byte_variance_pct = (byte_std_dev / mean_bytes) * \
                    100 if mean_bytes > 0 else 0

                src_ip, dst_ip = pair_key.split("->")

                # C2 beacons usually have consistent sizes (low byte variance) and
                # regular intervals
                if variance_pct < 15 and byte_variance_pct < 25:
                    findings.append({
                        "type": "c2_regular_beaconing",
                        "severity": Severity.CRITICAL,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "mean_interval_sec": round(mean_interval, 1),
                        "variance_pct": round(variance_pct, 1),
                        "mean_bytes": round(mean_bytes, 1),
                        "byte_variance_pct": round(byte_variance_pct, 1),
                        "connection_count": len(conn_data),
                        "details": (
                            f"Highly regular beaconing detected to {dst_ip}. "
                            f"Interval: {mean_interval:.1f}s (Jitter: {variance_pct:.1f}%). "
                            f"Payload Size: {mean_bytes:.1f}B (Var: {byte_variance_pct:.1f}%)."
                        )
                    })
                elif variance_pct < 35 and byte_variance_pct < 45:
                    findings.append({
                        "type": "c2_jittered_beaconing",
                        "severity": Severity.HIGH,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "mean_interval_sec": round(mean_interval, 1),
                        "variance_pct": round(variance_pct, 1),
                        "mean_bytes": round(mean_bytes, 1),
                        "byte_variance_pct": round(byte_variance_pct, 1),
                        "connection_count": len(conn_data),
                        "details": (
                            f"Jittered beaconing detected to {dst_ip}. "
                            f"Interval: {mean_interval:.1f}s (Jitter: {variance_pct:.1f}%). "
                            f"Payload Size: {mean_bytes:.1f}B (Var: {byte_variance_pct:.1f}%)."
                        )
                    })
            except Exception as e:
                logger.warning("Error analyzing beacon interval: %s", e)

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
                "title": f"📡 C2 Beaconing: {finding['type']}",
                "details": {
                    "src_ip": finding["src_ip"],
                    "dst_ip": finding["dst_ip"],
                    "interval_sec": finding["mean_interval_sec"],
                    "jitter_pct": finding["variance_pct"],
                    "payload_bytes": finding["mean_bytes"],
                    "details": finding["details"]
                },
            }
            actions.append({"action": "alert", "data": alert})

            # Escalate to detection supervisor for correlation with threat
            # intel
            actions.append({
                "action": "escalate",
                "data": {
                    "type": "c2_beaconing_report",
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
    agent = C2BeaconingAgent()
    agent.run_loop()
