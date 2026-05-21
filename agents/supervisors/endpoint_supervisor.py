import json
import time
import logging
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("EndpointSupervisor")

class EndpointSupervisor(BaseAgent):
    def __init__(self, supervisor_queue):
        super().__init__(
            name="EndpointSupervisor",
            description="Supervises endpoint-focused agents and correlates events",
            supervisor_queue=supervisor_queue,
            interval_seconds=10
        )
        self.config = SOCConfig()
        self.managed_workers = ["W01_ProcessBehavior", "W03_RansomwareCanary", "W05_MemoryMonitor"]
        self.recent_alerts = [] # Sliding window

    def collect(self) -> List[Dict[str, Any]]:
        alerts_to_process = self.recent_alerts.copy()
        self.recent_alerts = []
        return alerts_to_process

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        if not data:
            return findings

        proc_alerts = [a for a in data if a.get("agent_source") == "W01_ProcessBehavior"]
        mem_alerts = [a for a in data if a.get("agent_source") == "W05_MemoryMonitor"]
        rans_alerts = [a for a in data if a.get("agent_source") == "W03_RansomwareCanary"]

        # Rule 1: Suspicious process + LSASS access on same host = CRITICAL
        for proc in proc_alerts:
            agent = proc.get("agent") or proc.get("agent_name")
            for mem in mem_alerts:
                if (mem.get("agent") or mem.get("agent_name")) == agent:
                    findings.append({
                        "type": "active_attack_credential_access",
                        "severity": Severity.CRITICAL,
                        "agent": agent,
                        "details": f"Correlated suspicious process and LSASS access on {agent}"
                    })

        # Rule 2: Ransomware indicator + Suspicious process = CRITICAL
        for rans in rans_alerts:
            agent = rans.get("agent") or rans.get("agent_name")
            for proc in proc_alerts:
                if (proc.get("agent") or proc.get("agent_name")) == agent:
                    findings.append({
                        "type": "ransomware_executing",
                        "severity": Severity.CRITICAL,
                        "agent": agent,
                        "details": f"Correlated ransomware indicators and suspicious process on {agent}"
                    })

        # Forward individual high/critical alerts to commander
        for alert in data:
            if alert.get("severity") in [Severity.HIGH, Severity.CRITICAL]:
                findings.append(alert)

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            if finding.get("type") in ["active_attack_credential_access", "ransomware_executing"]:
                # Auto-isolate host
                actions.append({
                    "action": "isolate_host",
                    "agent": finding.get("agent")
                })
                actions.append({
                    "action": "escalate",
                    "data": finding
                })
            elif finding.get("severity") in [Severity.HIGH, Severity.CRITICAL]:
                actions.append({
                    "action": "escalate",
                    "data": finding
                })
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"escalated": 0, "isolated": 0}
        for action in actions:
            if action["action"] == "escalate":
                self.redis_bus.publish("soc:supervisor-to-commander", json.dumps({
                    "supervisor": self.name,
                    "alert": action["data"]
                }))
                results["escalated"] += 1
            elif action["action"] == "isolate_host":
                try:
                    agent = action.get("agent")
                    if agent:
                        logger.warning(f"ACTION: Isolating host {agent}")
                        # self.wazuh_client.trigger_active_response("host-deny", agent_id=agent)
                        results["isolated"] += 1
                except Exception as e:
                    logger.error(f"Failed to isolate host: {e}")
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
    agent = EndpointSupervisor(supervisor_queue="soc:endpoint-supervisor")
    agent.start_in_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
