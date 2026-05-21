import json
import time
import logging
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("ResponseSupervisor")

class ResponseSupervisor(BaseAgent):
    def __init__(self, supervisor_queue):
        super().__init__(
            name="ResponseSupervisor",
            description="Supervises response and decision agents",
            supervisor_queue=supervisor_queue,
            interval_seconds=15
        )
        self.config = SOCConfig()
        self.managed_workers = ["W23_AutoCase", "W26_SmartDecision", "W29_VulnerabilityMonitor"]
        self.recent_alerts = []

    def collect(self) -> List[Dict[str, Any]]:
        alerts_to_process = self.recent_alerts.copy()
        self.recent_alerts = []
        return alerts_to_process

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        if not data:
            return findings

        # Forward high/critical alerts to commander
        for alert in data:
            if alert.get("severity") in [Severity.HIGH, Severity.CRITICAL]:
                findings.append(alert)

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            actions.append({
                "action": "escalate",
                "data": finding
            })
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"escalated": 0}
        for action in actions:
            if action["action"] == "escalate":
                self.redis_bus.publish("soc:supervisor-to-commander", json.dumps({
                    "supervisor": self.name,
                    "alert": action["data"]
                }))
                results["escalated"] += 1
        return results

    def handle_worker_message(self, message: str):
        try:
            data = json.loads(message)
            source = data.get("source_agent")
            if source in self.managed_workers:
                logger.info(f"Received alert from {source}")
                alert_data = data.get("data", {})
                alert_data["agent_source"] = source
                self.recent_alerts.append(alert_data)
        except Exception as e:
            logger.error(f"Failed parsing worker message: {e}")

    def run_loop(self):
        self.redis_bus.subscribe(self.supervisor_queue, self.handle_worker_message)
        super().run_loop()

if __name__ == "__main__":
    agent = ResponseSupervisor(supervisor_queue="soc:response-supervisor")
    agent.start_in_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
