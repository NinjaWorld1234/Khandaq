import json
import time
import logging
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("Commander")

class CommanderAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Commander",
            description="Supreme coordinator. Subscribes to all supervisor channels.",
            supervisor_queue="none", # It doesn't report to anyone
            interval_seconds=10
        )
        self.config = SOCConfig()
        self.recent_alerts = []
        self.threat_level = "GREEN"

    def collect(self) -> List[Dict[str, Any]]:
        alerts_to_process = self.recent_alerts.copy()
        self.recent_alerts = []
        return alerts_to_process

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        if not data:
            return findings

        # Example correlation across supervisors
        net_c2 = [a for a in data if "c2" in a.get("type", "").lower() and a.get("supervisor") == "NetworkSupervisor"]
        end_proc = [a for a in data if "process" in a.get("type", "").lower() and a.get("supervisor") == "EndpointSupervisor"]
        
        for n in net_c2:
            agent_ip = n.get("alert", {}).get("src_ip")
            for e in end_proc:
                if e.get("alert", {}).get("agent") == agent_ip:
                    findings.append({
                        "type": "CONFIRMED_INTRUSION",
                        "severity": Severity.CRITICAL,
                        "details": f"Network C2 and Endpoint Suspicious Process correlated on {agent_ip}"
                    })

        for alert in data:
            findings.append(alert.get("alert", alert))

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        new_threat_level = self.threat_level
        
        for finding in findings:
            if finding.get("type") == "CONFIRMED_INTRUSION" or finding.get("severity") == Severity.CRITICAL:
                new_threat_level = "RED"
                actions.append({
                    "action": "page_humans",
                    "data": finding
                })
            elif finding.get("severity") == Severity.HIGH and new_threat_level not in ["RED", "ORANGE"]:
                new_threat_level = "ORANGE"

        if new_threat_level != self.threat_level:
            self.threat_level = new_threat_level
            actions.append({
                "action": "update_threat_level",
                "level": self.threat_level
            })

        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"paged": 0, "level_changes": 0}
        for action in actions:
            if action["action"] == "page_humans":
                alert_data = action["data"]
                self.alerter.send_alert(
                    severity=alert_data.get("severity", Severity.CRITICAL),
                    title=f"COMMANDER ESCALATION: {alert_data.get('type', 'Critical Alert')}",
                    details=alert_data.get("details", str(alert_data)),
                    agent_name="Commander"
                )
                results["paged"] += 1
            elif action["action"] == "update_threat_level":
                self.redis_bus.publish("soc:commander-broadcast", json.dumps({
                    "type": "threat_level_update",
                    "level": action["level"]
                }))
                results["level_changes"] += 1
                logger.warning(f"GLOBAL THREAT LEVEL UPDATED TO: {action['level']}")
                
        return results

    def handle_supervisor_message(self, message: str):
        try:
            data = json.loads(message)
            logger.info(f"Received escalation from {data.get('supervisor')}")
            self.recent_alerts.append(data)
        except Exception as e:
            logger.error(f"Failed parsing supervisor message: {e}")

    def run_loop(self):
        # Subscribe to supervisor-to-commander channel
        self.redis_bus.subscribe("soc:supervisor-to-commander", self.handle_supervisor_message)
        super().run_loop()

if __name__ == "__main__":
    agent = CommanderAgent()
    agent.start_in_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
