"""
SOC Platform - Deception Agent
Processes alerts from the Deception Mesh (Honeypots).
Since interaction with a honeypot is 100% malicious, this agent bypasses standard analysis
and issues immediate CRITICAL threat scores to the Commander.
"""

import time
import logging
import threading
from typing import List, Dict, Any, Optional

from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.deception_agent")

class DeceptionAgent(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="deception_agent",
            description="Processes high-fidelity honeypot alerts with zero false positives",
            interval_seconds=5, # Fast interval for immediate response
            config=config,
            supervisor_channel="soc:deception-alerts"
        )
        self.pending_alerts = []
        self._lock = threading.Lock()

    def handle_worker_message(self, message: dict) -> None:
        try:
            payload = message.get("payload", {})
            if not payload:
                return
            with self._lock:
                self.pending_alerts.append(payload)
        except Exception as exc:
            logger.error("Failed to parse deception alert: %s", exc)

    def collect(self) -> List[Dict[str, Any]]:
        with self._lock:
            batch = list(self.pending_alerts)
            self.pending_alerts.clear()
        return batch

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.enabled or not data:
            return []
            
        findings = []
        for alert in data:
            src_ip = alert.get("src_ip")
            service = alert.get("service", "Unknown")
            
            logger.critical(f"🛑 DECEPTION TRIGGERED by {src_ip} on {service}! Generating maximum threat response.")
            
            # Construct a definitive finding
            finding = {
                "mitre_tactic": "Defense Evasion / Lateral Movement",
                "mitre_technique_id": "T1040", # Network Sniffing / Discovery
                "iocs": [src_ip],
                "technical_analysis": f"Entity {src_ip} interacted with a deception trap ({service}). This is a definitive indicator of compromise.",
                "escalate_to_commander": True,
                "threat_score": 100.0, # Max score
                "src_ip": src_ip,
                "event_type": "honeypot_trigger",
                "summary": f"[HONEYPOT] {src_ip} caught probing {service} trap."
            }
            findings.append(finding)
            
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Ensure they are formatted for the Commander
        return findings

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"sent_to_commander": 0}
        
        for action in actions:
            try:
                # Add source tag
                action["source_role"] = "deception_agent"
                
                # Send to Commander's queue (not directly to execution, still needs HITL/Commander awareness)
                payload = {
                    "source": self.name,
                    "payload": action
                }
                
                logger.info(f"Forwarding CRITICAL Deception alert for {action.get('src_ip')} to Commander.")
                self.redis_bus.publish("soc:supervisor-to-commander", payload, sender=self.name, message_type="DECEPTION_ALERT")
                results["sent_to_commander"] += 1
            except Exception as e:
                logger.error(f"Error acting on deception alert: {e}")
                
        return results

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = DeceptionAgent()
    agent.run_loop()
