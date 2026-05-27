# SOC Platform - Worker Agent W05: Memory Monitor
# وكيل مراقبة الذاكرة وكشف الحقن (Fileless Malware)
"""
Memory Monitor Agent
====================

Monitors memory access, process injection, and credential dumping attempts.
Analyzes Windows Sysmon Events via OpenSearch:
- Event ID 10: ProcessAccess (e.g. lsass.exe dumping by mimikatz/procdump)
- Event ID 8: CreateRemoteThread (Process Injection / Fileless Malware)
- Event ID 7: ImageLoaded (Unusual DLLs loaded into critical processes)

Interval: 30 seconds
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.worker.w05_memory")


class MemoryMonitorAgent(BaseAgent):
    """
    Memory Monitor Agent - Detects memory manipulation and LSASS dumping.
    وكيل مراقبة الذاكرة وكشف برمجيات الحقن
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w05_memory_monitor",
            description="Monitors memory access and credential dumping attempts.",
            interval_seconds=30,
            config=config,
            supervisor_channel="soc:response-supervisor",
        )

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Sysmon memory-related events."""
        # Sysmon Event ID 10 (ProcessAccess), 8 (CreateRemoteThread), 7 (ImageLoad)
        query = {
            "bool": {
                "should": [
                    {"match": {"rule.groups": "sysmon_event10"}},
                    {"match": {"rule.groups": "sysmon_event8"}},
                    {"match": {"rule.groups": "sysmon_event7"}},
                ],
                "minimum_should_match": 1
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=2,
                query=query,
                size=10000
            )
        except Exception as e:
            logger.error("Failed to collect Sysmon events: %s", e)
            return []

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify memory anomalies."""
        findings = []
        for event in data:
            try:
                data_obj = event.get("data") or {}
                win_obj = data_obj.get("win") or {}
                system_obj = win_obj.get("system") or {}
                event_id = str(system_obj.get("eventID", ""))
                
                agent_obj = event.get("agent") or {}
                agent_name = agent_obj.get("name", "unknown")
                
                event_data = win_obj.get("eventdata") or {}

                # Rule 1: LSASS memory access (Event 10)
                if event_id == "10":
                    target_image = str(event_data.get("targetImage") or "").lower()
                    source_image = str(event_data.get("sourceImage") or "").lower()
                    granted_access = str(event_data.get("grantedAccess") or "").lower()

                    if "lsass.exe" in target_image:
                        # Common access rights for mimikatz/procdump: 0x1010, 0x1410, 0x143a, 0x1fffff
                        suspicious_access = ["0x1010", "0x1410", "0x143a", "0x1fffff"]
                        if any(acc in granted_access for acc in suspicious_access):
                            findings.append({
                                "type": "lsass_memory_access",
                                "severity": Severity.CRITICAL,
                                "source": source_image,
                                "target": target_image,
                                "host": agent_name,
                                "details": f"Suspicious LSASS memory access by {source_image} (Access: {granted_access})"
                            })

                # Rule 2: CreateRemoteThread (Event 8) - Process Injection
                elif event_id == "8":
                    target_image = str(event_data.get("targetImage") or "").lower()
                    source_image = str(event_data.get("sourceImage") or "").lower()

                    # Ignore common known benign injectors if necessary
                    findings.append({
                        "type": "process_injection",
                        "severity": Severity.HIGH,
                        "source": source_image,
                        "target": target_image,
                        "host": agent_name,
                        "details": f"Process Injection: {source_image} created a remote thread in {target_image}"
                    })

                # Rule 3: Suspicious DLL loaded into LSASS (Event 7)
                elif event_id == "7":
                    image = str(event_data.get("image") or "").lower()
                    image_loaded = str(event_data.get("imageLoaded") or "").lower()

                    if "lsass.exe" in image:
                        whitelist = ["system32", "winsxs", "syswow64"]
                        if not any(wl in image_loaded for wl in whitelist):
                            findings.append({
                                "type": "lsass_dll_load",
                                "severity": Severity.CRITICAL,
                                "target": image,
                                "dll": image_loaded,
                                "host": agent_name,
                                "details": f"Unusual DLL loaded into LSASS: {image_loaded}"
                            })

            except Exception as e:
                logger.warning("Error analyzing sysmon event: %s", e)

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
                "title": f"🧠 Memory Anomaly: {finding['type']}",
                "details": {
                    "host": finding["host"],
                    "source": finding.get("source", "N/A"),
                    "target": finding.get("target", "N/A"),
                    "details": finding["details"]
                },
            }
            actions.append({"action": "alert", "data": alert})

            # Memory injection/dumping is almost always critical -> Response Supervisor
            if finding["severity"] in (Severity.HIGH, Severity.CRITICAL):
                actions.append({
                    "action": "escalate",
                    "data": {
                        "type": "memory_anomaly_report",
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
    agent = MemoryMonitorAgent()
    agent.run_loop()
