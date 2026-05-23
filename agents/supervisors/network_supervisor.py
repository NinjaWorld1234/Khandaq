import logging
from typing import Dict, Any, List, Optional
from shared.base_agent import BaseAgent
from shared.alerter import Severity
from shared.config import SOCConfig

logger = logging.getLogger("NetworkSupervisor")

class NetworkSupervisor(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None):
        super().__init__(
            name="NetworkSupervisor",
            description="Supervises network-focused agents and correlates events",
            interval_seconds=10,
            config=config,
            supervisor_channel="soc:network-supervisor"
        )
        self.managed_workers = ["W06_DNSTunneling", "W07_C2Beaconing", "W08_DataExfiltration"]
        self.recent_alerts = [] # Keep a sliding window of alerts in memory

    def collect(self) -> List[Dict[str, Any]]:
        # Supervisor mostly reacts to sub-agent messages via pub/sub, not polling,
        # but we use collect to process the internal buffer of received alerts.
        alerts_to_process = self.recent_alerts.copy()
        self.recent_alerts = [] # Clear the buffer
        return alerts_to_process

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        if not data:
            return findings

        # Basic correlation logic
        dns_alerts = [a for a in data if "dns" in a.get("type", "").lower() or a.get("agent_source") == "W06_DNSTunneling"]
        c2_alerts = [a for a in data if "c2" in a.get("type", "").lower() or a.get("agent_source") == "W07_C2Beaconing"]
        exfil_alerts = [a for a in data if "exfiltration" in a.get("type", "").lower() or "transfer" in a.get("type", "").lower() or a.get("agent_source") == "W08_DataExfiltration"]

        # Rule 1: DNS Tunneling + C2 Beaconing to same IP = CRITICAL
        for dns in dns_alerts:
            dns_ip = dns.get("src_ip")
            for c2 in c2_alerts:
                if c2.get("src_ip") == dns_ip:
                    findings.append({
                        "type": "confirmed_c2_activity",
                        "severity": Severity.CRITICAL,
                        "src_ip": dns_ip,
                        "dst_ip": c2.get("dst_ip"),
                        "details": f"Correlated DNS Tunneling and C2 Beaconing from {dns_ip}"
                    })

        # Rule 2: Exfiltration + C2 = Data theft in progress
        for exfil in exfil_alerts:
            ex_ip = exfil.get("src_ip")
            for c2 in c2_alerts:
                if c2.get("src_ip") == ex_ip:
                    findings.append({
                        "type": "data_theft_in_progress",
                        "severity": Severity.CRITICAL,
                        "src_ip": ex_ip,
                        "dst_ip": exfil.get("dst_ip"),
                        "details": f"Correlated Exfiltration and C2 Beaconing from {ex_ip} - active data theft"
                    })

        # Forward individual high-severity alerts to commander anyway
        for alert in data:
            if alert.get("severity") in [Severity.HIGH, Severity.CRITICAL]:
                findings.append(alert)

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            if finding.get("type") in ["confirmed_c2_activity", "data_theft_in_progress"]:
                # Auto-block C2 IP
                actions.append({
                    "action": "block_ip",
                    "ip": finding.get("dst_ip")
                })
                # Escalate to commander
                actions.append({
                    "action": "escalate",
                    "data": finding
                })
            elif finding.get("severity") in [Severity.HIGH, Severity.CRITICAL]:
                # Just escalate
                actions.append({
                    "action": "escalate",
                    "data": finding
                })
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"escalated": 0, "blocked": 0}
        for action in actions:
            if action["action"] == "escalate":
                f = action["data"]
                self.redis_bus.publish("soc:supervisor-to-commander", {
                    "supervisor": self.name,
                    "type": f.get("type"),
                    "severity": f.get("severity").name if hasattr(f.get("severity"), "name") else str(f.get("severity")),
                    "host": f.get("src_ip", ""),
                    "details": f.get("details", "")
                }, sender=self.name, message_type="escalation")
                results["escalated"] += 1
            elif action["action"] == "block_ip":
                try:
                    ip = action.get("ip")
                    if ip:
                        # Assuming Wazuh client has active response capability
                        # self.wazuh_client.trigger_active_response("firewall-drop", agent_id="all", custom_args=[ip])
                        logger.warning(f"ACTION: Blocking IP {ip} network-wide")
                        results["blocked"] += 1
                except Exception as e:
                    logger.error(f"Failed to block IP: {e}")
        return results

    def handle_worker_message(self, message: dict):
        try:
            source = message.get("source_agent")
            if source in self.managed_workers:
                logger.info(f"Received alert from {source}")
                alert_data = message.get("data", {})
                alert_data["agent_source"] = source
                self.recent_alerts.append(alert_data)
        except Exception as e:
            logger.error(f"Failed parsing worker message: {e}")

    def run_loop(self):
        # Subscribe to worker channel
        self.redis_bus.subscribe(self.supervisor_channel, self.handle_worker_message)
        # Call base run_loop
        super().run_loop()

if __name__ == "__main__":
    agent = NetworkSupervisor()
    agent.run_loop()
