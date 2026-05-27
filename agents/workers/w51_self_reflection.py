# SOC Platform - Worker Agent W51: Self Reflection
# وكيل التأمل الذاتي والبرمجة الذاتية
"""
Self Reflection Agent
=====================

Reviews past decisions and proposes auto-tuning system rules (Semi-Supervised).
Queries OpenSearch for all HITL (Human-in-the-loop) "reject" decisions and false positives
over the last 24 hours. Uses the LLM to generate a customized Wazuh whitelist rule
and escalates it to the commander for application.

Interval: 86400 seconds (Once a day)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.llm_client import LLMClient

logger = logging.getLogger("soc.worker.w51_self_reflection")


class SelfReflectionAgent(BaseAgent):
    """
    Self Reflection Agent - Analyzes false positives and tunes Wazuh rules.
    وكيل التأمل الذاتي والبرمجة الذاتية
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w51_self_reflection",
            description="Reviews past decisions and proposes auto-tuning system rules (Semi-Supervised).",
            interval_seconds=86400,  # Run once a day
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self._llm: Optional[LLMClient] = None

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = LLMClient(self.config)
        return self._llm

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Collect HITL rejection actions from the past 24 hours."""
        query = {
            "bool": {
                "must": [
                    {"match": {"action": "HITL_REJECTION"}},
                ]
            }
        }
        try:
            return self.os_client.get_events_since(
                index="soc-metrics-*",
                minutes=1440,  # last 24 hours
                query=query,
                size=10000
            )
        except Exception as e:
            logger.error("Failed to fetch HITL rejections: %s", e)
            return []

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze rejections and use LLM to draft whitelist rules."""
        findings = []
        host_rejection_counts: Dict[str, Dict[str, Any]] = {}

        # Group rejections by host and rule_id
        for event in data:
            try:
                host = event.get("host", "unknown")
                rule_id = event.get("rule_id", "unknown")
                reason = event.get(
                    "reason", "Human decided this was a false positive.")

                key = f"{host}_{rule_id}"
                if key not in host_rejection_counts:
                    host_rejection_counts[key] = {
                        "host": host,
                        "rule_id": rule_id,
                        "count": 0,
                        "reason": reason,
                        "sample_event": event.get("original_event", {})
                    }

                host_rejection_counts[key]["count"] += 1
            except Exception as e:
                logger.warning("Error evaluating data event: %s", e)

        # Use LLM to formulate a rule for cases with high rejection counts
        for key, info in host_rejection_counts.items():
            try:
                if info["count"] >= 3:
                    logger.info(
                        "Drafting whitelist rule for rule_id %s on host %s",
                        info["rule_id"],
                        info["host"])

                    llm_prompt = (
                        "As a SOC Engineering AI, write a Wazuh XML child rule to whitelist/suppress "
                        f"rule ID {info['rule_id']} for the hostname '{info['host']}'.\n"
                        f"Reason given by analyst: {info['reason']}\n\n"
                        "Output ONLY the raw XML <rule> block, no markdown, no explanations.")

                    proposed_xml = self.llm._generate(
                        llm_prompt, system_prompt="You write valid Wazuh XML rules.")

                    findings.append({
                        "type": "RULE_TUNING_REQUIRED",
                        "severity": Severity.MEDIUM,
                        "host": info["host"],
                        "rule_id": info["rule_id"],
                        "rejection_count": info["count"],
                        "reason": info["reason"],
                        "proposed_rule_xml": proposed_xml.strip("`\n "),
                    })
            except Exception as e:
                logger.warning("Error drafting whitelist rule: %s", e)

        return findings

    # ------------------------------------------------------------------
    # Decide / قرار
    # ------------------------------------------------------------------
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Formulate escalation actions."""
        actions = []
        for finding in findings:
            try:
                actions.append({
                    "action": "escalate",
                    "finding": finding
                })
            except Exception as e:
                logger.warning("Error evaluating finding: %s", e)
        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Report rule proposals to supervisor."""
        results = {"rules_proposed": 0, "escalated": 0}
        for action in actions:
            try:
                if action["action"] == "escalate":
                    finding = action["finding"]
                    logger.info(
                        "🧠 Self-Reflection PROPOSAL drafted for %s (Rule %s)",
                        finding["host"], finding["rule_id"]
                    )
                    self.report_to_supervisor({
                        "type": "rule_tuning_proposal",
                        "severity": finding["severity"],
                        "title": f"🛠️ Wazuh Rule Tuning Proposed: Suppress {finding['rule_id']} on {finding['host']}",
                        "details": {
                            "host": finding["host"],
                            "rule_id": finding["rule_id"],
                            "rejection_count": finding["rejection_count"],
                            "analyst_reason": finding["reason"],
                            "proposed_xml": finding["proposed_rule_xml"]
                        }
                    })
                    results["rules_proposed"] += 1
                    results["escalated"] += 1
                    self._events_processed += 1
                    self._metrics.inc_events(1)
            except Exception as e:
                logger.warning("Error executing self-reflection action: %s", e)

        return results


# ---------------------------------------------------------------------------
# Entry point / نقطة الدخول
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = SelfReflectionAgent()
    agent.run_loop()
