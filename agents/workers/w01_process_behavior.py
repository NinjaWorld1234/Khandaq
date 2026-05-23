import logging
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("W01-ProcessBehavior")

class ProcessBehaviorAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="W01_ProcessBehavior",
            description="Monitors process creation for suspicious parent-child chains and LOLBins",
            interval_seconds=30,
            supervisor_channel="soc:endpoint-supervisor"
        )
        self.known_bad_pairs = {
            "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
            "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
            "powerpnt.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
            "explorer.exe": ["powershell.exe", "cmd.exe"],
        }
        self.lolbins = ["certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "wmic.exe"]
        self.suspicious_paths = ["\\temp\\", "\\appdata\\", "\\programdata\\"]

    def collect(self) -> List[Dict[str, Any]]:
        # Fetch Sysmon Event ID 1 (Process Creation) from Wazuh alerts
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"rule.groups": "sysmon_event1"}},
                    ]
                }
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=1, # slightly overlapping to not miss events
                query=query
            )
        except Exception as e:
            logger.error(f"Failed to collect events: {e}")
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for event in data:
            try:
                parent_process = event.get("data", {}).get("win", {}).get("eventdata", {}).get("parentImage", "").lower()
                child_process = event.get("data", {}).get("win", {}).get("eventdata", {}).get("image", "").lower()
                cmdline = event.get("data", {}).get("win", {}).get("eventdata", {}).get("commandLine", "").lower()
                agent_name = event.get("agent", {}).get("name", "unknown")

                if not parent_process or not child_process:
                    continue

                parent_name = parent_process.split("\\")[-1]
                child_name = child_process.split("\\")[-1]

                # Rule 1: Known Bad Pairs (Macro execution, etc.)
                if parent_name in self.known_bad_pairs and child_name in self.known_bad_pairs[parent_name]:
                    findings.append({
                        "type": "suspicious_parent_child",
                        "severity": Severity.CRITICAL,
                        "parent": parent_name,
                        "child": child_name,
                        "cmdline": cmdline,
                        "agent": agent_name,
                        "details": f"Suspicious process execution: {parent_name} spawned {child_name}"
                    })
                    continue

                # Rule 2: Execution from unusual paths
                is_unusual_path = any(path in child_process for path in self.suspicious_paths)
                if is_unusual_path:
                    findings.append({
                        "type": "unusual_execution_path",
                        "severity": Severity.HIGH,
                        "parent": parent_name,
                        "child": child_name,
                        "path": child_process,
                        "agent": agent_name,
                        "details": f"Process spawned from unusual path: {child_process}"
                    })
                    continue

                # Rule 3: LOLBins usage
                if child_name in self.lolbins:
                    # Very basic check, in reality we'd check cmdline arguments for specific flags (-urlcache, http, etc.)
                    if "http" in cmdline or "urlcache" in cmdline or "javascript:" in cmdline:
                        findings.append({
                            "type": "lolbin_usage",
                            "severity": Severity.HIGH,
                            "parent": parent_name,
                            "child": child_name,
                            "cmdline": cmdline,
                            "agent": agent_name,
                            "details": f"Suspicious LOLBin execution: {child_name} with args {cmdline}"
                        })

            except Exception as e:
                logger.error(f"Error analyzing event: {e}")
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"Process Behavior Anomaly: {finding['type']}",
                "details": finding["details"],
                "agent_name": finding["agent"]
            }
            actions.append({"action": "alert", "data": alert})
            
            # If critical, we might suggest isolation, but we leave that to supervisor/commander
            if finding["severity"] == Severity.CRITICAL:
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
    agent = ProcessBehaviorAgent()
    agent.run_loop()
