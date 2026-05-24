import time
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("soc.worker.w51_self_reflection")

class SelfReflectionAgent(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w51_self_reflection",
            description="Reviews past decisions and proposes auto-tuning system rules (Semi-Supervised).",
            interval_seconds=86400, # Run once a day
            config=config,
            supervisor_channel="soc:detection-supervisor"
        )

    def collect(self) -> List[Dict[str, Any]]:
        # Query OpenSearch for all HITL "reject" decisions and false positives
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"action": "HITL_REJECTION"}},
                    ]
                }
            }
        }
        try:
            return self.os_client.get_events_since(
                index="soc-metrics-*",
                minutes=1440, # last 24 hours
                query=query
            )
        except Exception as e:
            logger.error(f"Failed to fetch HITL rejections: {e}")
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        host_rejection_counts = {}

        for event in data:
            host = event.get("host", "unknown")
            rule_id = event.get("rule_id", "unknown")
            reason = event.get("reason", "Human decided this was a false positive.")
            
            key = f"{host}_{rule_id}"
            if key not in host_rejection_counts:
                host_rejection_counts[key] = {"host": host, "rule_id": rule_id, "count": 0, "reason": reason}
            
            host_rejection_counts[key]["count"] += 1

        for key, info in host_rejection_counts.items():
            if info["count"] >= 3: # If human rejected the same rule on the same host 3+ times
                findings.append({
                    "type": "RULE_TUNING_REQUIRED",
                    "severity": Severity.MEDIUM,
                    "host": info["host"],
                    "rule_id": info["rule_id"],
                    "details": f"Human rejected rule {info['rule_id']} for {info['host']} {info['count']} times yesterday. Reason: {info['reason']}. Proposing a whitelist rule.",
                    "response": "PROPOSE_WAZUH_WHITELIST"
                })

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            actions.append({
                "action": "propose_whitelist_rule",
                "finding": finding
            })
            # Escalate the proposal to the commander
            actions.append({
                "action": "escalate",
                "finding": finding
            })
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"rules_proposed": 0, "escalated": 0}
        for action in actions:
            if action["action"] == "propose_whitelist_rule":
                logger.info(f"🧠 Self-Reflection PROPOSAL drafted (Pending Human Approval): {action['finding']['details']}")
                results["rules_proposed"] += 1
            elif action["action"] == "escalate":
                self.report_to_supervisor(action["finding"])
                results["escalated"] += 1
        return results

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    agent = SelfReflectionAgent()
    agent.run_loop()
