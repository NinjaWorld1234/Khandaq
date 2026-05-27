import threading
import logging
from typing import Dict, Any, List, Optional
from shared.base_agent import BaseAgent
from shared.alerter import Severity
from shared.config import SOCConfig

logger = logging.getLogger("EndpointSupervisor")


class EndpointSupervisor(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None):
        super().__init__(
            name="EndpointSupervisor",
            description="Supervises endpoint-focused agents and correlates events",
            interval_seconds=10,
            config=config,
            supervisor_channel="soc:endpoint-supervisor"
        )
        self.recent_alerts: list[dict] = []  # Sliding window
        self._cache_lock = threading.Lock()

    def collect(self) -> List[Dict[str, Any]]:
        with self._cache_lock:
            alerts_to_process = self.recent_alerts.copy()
            self.recent_alerts.clear()
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
            try:
                agent = proc.get("agent") or proc.get("agent_name")
                for mem in mem_alerts:
                    if (mem.get("agent") or mem.get("agent_name")) == agent:
                        findings.append({
                            "type": "active_attack_credential_access",
                            "severity": Severity.CRITICAL,
                            "agent": agent,
                            "details": f"Correlated suspicious process and LSASS access on {agent}"
                        })
            except Exception as e:
                logger.warning("Error in rule 1 correlation: %s", e)

        # Rule 2: Ransomware indicator + Suspicious process = CRITICAL
        for rans in rans_alerts:
            try:
                agent = rans.get("agent") or rans.get("agent_name")
                for proc in proc_alerts:
                    if (proc.get("agent") or proc.get("agent_name")) == agent:
                        findings.append({
                            "type": "ransomware_executing",
                            "severity": Severity.CRITICAL,
                            "agent": agent,
                            "details": f"Correlated ransomware indicators and suspicious process on {agent}"
                        })
            except Exception as e:
                logger.warning("Error in rule 2 correlation: %s", e)

        # Forward individual high/critical alerts to commander
        for alert in data:
            try:
                if alert.get("severity") in [Severity.HIGH, Severity.CRITICAL]:
                    findings.append(alert)
            except Exception as e:
                logger.warning("Error evaluating raw alert: %s", e)

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            try:
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
            except Exception as e:
                logger.warning("Error processing finding in decide: %s", e)
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"escalated": 0, "isolated": 0}
        for action in actions:
            try:
                if action["action"] == "escalate":
                    f = action.get("data", {})
                    severity = f.get("severity")
                    sev_str = severity.name if hasattr(severity, "name") else str(severity)
                    self.redis_bus.publish("soc:supervisor-to-commander", {
                        "supervisor": self.name,
                        "type": f.get("type"),
                        "severity": sev_str,
                        "host": f.get("agent", ""),
                        "details": f.get("details", "")
                    }, sender=self.name, message_type="escalation")
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
            except Exception as e:
                logger.warning("Error processing action: %s", e)
        return results

    def handle_worker_message(self, message: dict):
        try:
            payload = message.get("payload") or {}
            source = message.get("sender") or payload.get("agent_name", "unknown")
            logger.info(f"Received alert from {source}")
            alert_data = payload
            alert_data["agent_source"] = source
            with self._cache_lock:

                self.recent_alerts.append(alert_data)
        except Exception as e:
            logger.error(f"Failed parsing worker message: {e}")

    def run_loop(self):
        self.redis_bus.subscribe(self.supervisor_channel, self.handle_worker_message)
        super().run_loop()


if __name__ == "__main__":
    agent = EndpointSupervisor()
    agent.run_loop()
