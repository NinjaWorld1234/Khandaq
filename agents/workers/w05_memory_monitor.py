import logging
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("W05-MemoryMonitor")

class MemoryMonitorAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="W05_MemoryMonitor",
            description="Monitors memory access and credential dumping attempts",
            interval_seconds=30,
            supervisor_channel="soc:endpoint-supervisor"
        )

    def collect(self) -> List[Dict[str, Any]]:
        # Fetch Sysmon Event ID 10 (ProcessAccess), 8 (CreateRemoteThread), 25 (ProcessTampering)
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"rule.groups": "sysmon_event10"}},
                        {"match": {"rule.groups": "sysmon_event8"}},
                        {"match": {"rule.groups": "sysmon_event25"}},
                        {"match": {"rule.groups": "sysmon_event7"}}, # DLL load
                    ],
                    "minimum_should_match": 1
                }
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=1,
                query=query
            )
        except Exception as e:
            logger.error(f"Failed to collect events: {e}")
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for event in data:
            try:
                event_id = event.get("data", {}).get("win", {}).get("system", {}).get("eventID")
                agent_name = event.get("agent", {}).get("name", "unknown")
                event_data = event.get("data", {}).get("win", {}).get("eventdata", {})
                
                # Rule 1: LSASS memory access (Event 10)
                if event_id == "10":
                    target_image = event_data.get("targetImage", "").lower()
                    source_image = event_data.get("sourceImage", "").lower()
                    granted_access = event_data.get("grantedAccess", "")
                    
                    if "lsass.exe" in target_image:
                        # Common access rights for mimikatz/procdump: 0x1010, 0x1410, 0x143a, 0x1FFFFF
                        if any(acc in granted_access for acc in ["0x1010", "0x1410", "0x143a", "0x1fffff"]):
                            findings.append({
                                "type": "lsass_memory_access",
                                "severity": Severity.CRITICAL,
                                "source": source_image,
                                "target": target_image,
                                "agent": agent_name,
                                "details": f"Suspicious LSASS memory access by {source_image} (Access: {granted_access})"
                            })

                # Rule 2: CreateRemoteThread (Event 8) - Process Injection
                elif event_id == "8":
                    target_image = event_data.get("targetImage", "").lower()
                    source_image = event_data.get("sourceImage", "").lower()
                    findings.append({
                        "type": "process_injection",
                        "severity": Severity.HIGH,
                        "source": source_image,
                        "target": target_image,
                        "agent": agent_name,
                        "details": f"Process Injection: {source_image} created remote thread in {target_image}"
                    })

                # Rule 3: Suspicious DLL loaded into LSASS (Event 7)
                elif event_id == "7":
                    image = event_data.get("image", "").lower()
                    image_loaded = event_data.get("imageLoaded", "").lower()
                    if "lsass.exe" in image and not any(whitelisted in image_loaded for whitelisted in ["system32", "winsxs"]):
                        findings.append({
                            "type": "lsass_dll_load",
                            "severity": Severity.CRITICAL,
                            "target": image,
                            "dll": image_loaded,
                            "agent": agent_name,
                            "details": f"Unusual DLL loaded into LSASS: {image_loaded}"
                        })

            except Exception as e:
                logger.error(f"Error analyzing event: {e}")
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"Memory Anomaly: {finding['type']}",
                "details": finding["details"],
                "agent_name": finding["agent"]
            }
            actions.append({"action": "alert", "data": alert})
            
            if finding["severity"] in [Severity.HIGH, Severity.CRITICAL]:
                actions.append({"action": "escalate", "data": finding})
                
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"alerts_sent": 0, "escalations": 0}
        for action in actions:
            if action["action"] == "alert":
                alert_data = action["data"]
                self.alerter.send_alert(
                    severity=alert_data["severity"],
                    title=alert_data["title"],
                    details=alert_data["details"],
                    agent_name=alert_data["agent_name"]
                )
                results["alerts_sent"] += 1
            elif action["action"] == "escalate":
                self.report_to_supervisor(action["data"])
                results["escalations"] += 1
        return results

if __name__ == "__main__":
    agent = MemoryMonitorAgent()
    agent.run_loop()
