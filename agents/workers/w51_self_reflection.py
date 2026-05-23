"""
Worker 51: Self-Reflection & Auto-Tuning (وكيل التأمل الذاتي وإعادة البرمجة)

This agent wakes up at a specific time (e.g., 3:00 AM) and reviews
all alerts, Commander decisions, and specifically HITL (Human-in-the-Loop) 
rejections from the previous day. 
It then formulates new logic/Sigma rules or updates the whitelist to 
prevent future false positives and false negatives.
"""

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
            description="Reviews past decisions and auto-tunes system rules.",
            interval_seconds=86400, # Run once a day
            config=config,
        )

    def collect(self) -> List[Dict[str, Any]]:
        # In production, query OpenSearch for all HITL "reject" decisions 
        # and all alerts generated in the last 24 hours.
        logger.info("Gathering yesterday's SOC events and HITL decisions for self-reflection...")
        
        # Simulated HITL Rejection log
        simulated_history = [
            {
                "type": "HITL_REJECTION",
                "host": "opensearch-node1",
                "action": "isolate_host",
                "reason": "Human decided this was a false positive during DB backup."
            }
        ]
        return simulated_history

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for event in data:
            if event.get("type") == "HITL_REJECTION":
                host = event.get("host", "unknown")
                findings.append({
                    "type": "RULE_TUNING_REQUIRED",
                    "severity": Severity.MEDIUM,
                    "host": host,
                    "details": f"Human rejected isolation for {host} yesterday. Auto-generating a whitelist rule to ignore similar behavior during backup windows.",
                    "response": "UPDATE_WAZUH_WHITELIST"
                })
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            actions.append({
                "action": "generate_whitelist_rule",
                "finding": finding
            })
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"rules_updated": 0}
        for action in actions:
            if action["action"] == "generate_whitelist_rule":
                # In a live environment, this would write a new XML rule 
                # to /var/ossec/etc/rules/local_rules.xml via Wazuh API.
                logger.info(f"🧠 Self-Reflection applied: {action['finding']['details']}")
                results["rules_updated"] += 1
        return results

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    agent = SelfReflectionAgent()
    agent.run_loop()
