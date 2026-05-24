import logging
import time
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("W48-HardwareAnomaly")

class HardwareAnomalyAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="W48_HardwareAnomaly",
            description="Monitors hardware metrics (CPU, Temp) for cryptojacking",
            interval_seconds=300, # Run every 5 minutes
            supervisor_channel="soc:endpoint-supervisor"
        )
        self.cpu_threshold_pct = 95.0
        self.cpu_sustained_minutes = 30
        
    def collect(self) -> List[Dict[str, Any]]:
        # Fetch Wazuh system inventory or Metricbeat data indicating high CPU / Temp
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"rule.groups": "hardware_monitor"}},
                    ]
                }
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=self.cpu_sustained_minutes,
                query=query
            )
        except Exception as e:
            logger.error(f"Failed to collect hardware events: {e}")
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        host_cpu_counts = {}

        for event in data:
            try:
                agent_name = event.get("agent", {}).get("name", "unknown")
                cpu_usage = event.get("data", {}).get("hardware", {}).get("cpu_pct", 0)
                temp_celsius = event.get("data", {}).get("hardware", {}).get("temp_c", 0)

                if agent_name not in host_cpu_counts:
                    host_cpu_counts[agent_name] = {"high_cpu_hits": 0, "max_temp": 0}

                if float(cpu_usage) > self.cpu_threshold_pct:
                    host_cpu_counts[agent_name]["high_cpu_hits"] += 1
                
                if float(temp_celsius) > host_cpu_counts[agent_name]["max_temp"]:
                    host_cpu_counts[agent_name]["max_temp"] = float(temp_celsius)

            except Exception as e:
                logger.error(f"Error parsing hardware event: {e}")

        for host, stats in host_cpu_counts.items():
            # If CPU is maxed out in most of our 5-minute polling intervals over the last 30 minutes
            # (Assuming Wazuh sends metrics every 5 mins -> 6 hits max)
            if stats["high_cpu_hits"] >= (self.cpu_sustained_minutes / 5) * 0.8:
                severity = Severity.HIGH
                if stats["max_temp"] > 85:
                    severity = Severity.CRITICAL

                findings.append({
                    "type": "suspected_cryptojacking",
                    "severity": severity,
                    "agent": host,
                    "max_temp": stats["max_temp"],
                    "details": f"Sustained 95%+ CPU usage over {self.cpu_sustained_minutes} mins on {host}. Max Temp: {stats['max_temp']}C"
                })

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"Hardware Anomaly: {finding['type']}",
                "details": finding["details"],
                "agent_name": finding["agent"]
            }
            actions.append({"action": "alert", "data": alert})
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
    agent = HardwareAnomalyAgent()
    agent.run_loop()
