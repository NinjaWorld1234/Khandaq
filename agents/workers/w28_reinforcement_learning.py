"""
SOC Worker Agent W28 — Reinforcement Learning / Feedback Agent
Learns from past decisions to improve future detection and response accuracy.
Tracks TP/FP rates per rule, updates confidence scores, and outputs tuning recommendations.
"""

import logging
import hashlib
from typing import Dict, Any, List, Optional
from collections import defaultdict
from datetime import datetime, timezone
from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("W28-ReinforcementLearning")

CASES_INDEX = "soc-cases"
FEEDBACK_INDEX = "soc-ml-feedback"

# Thresholds for generating recommendations
HIGH_FP_RATE = 0.60        # rule with ≥60% FP rate → recommend tuning
LOW_CONFIDENCE_IOC = 0.30  # IOC confidence below 30% → recommend aging out
MIN_SAMPLES = 5            # minimum closed cases to evaluate a rule
CONFIDENCE_DECAY = 0.05    # per-cycle decay for IOCs without recent TPs


class ReinforcementLearningAgent(BaseAgent):
    """Learns from closed-case feedback to tune detection rules and IOC confidence."""

    def __init__(self) -> None:
        super().__init__(
            name="W28_ReinforcementLearning",
            description="Tunes detection thresholds based on analyst feedback",
            interval_seconds=3600,
            supervisor_channel="soc:response-supervisor",
        )
        self.rule_scores: Dict[str, Dict[str, float]] = {}   # rule_id → {tp, fp, confidence}
        self.ioc_scores: Dict[str, float] = {}                # ioc_value → confidence
        self.action_scores: Dict[str, Dict[str, int]] = {}    # action → {effective, ineffective}

    # ------------------------------------------------------------------
    # Collect: fetch closed cases with analyst resolutions
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        query = {
            "bool": {
                "must": [
                    {"term": {"status.keyword": "closed"}},
                    {"terms": {"resolution.keyword": ["true_positive", "false_positive"]}},
                ]
            }
        }
        try:
            cases = self.os_client.get_events_since(
                index=CASES_INDEX, minutes=1500, query=query, size=500,
            )
            logger.info("Collected %d closed cases for learning", len(cases))
            return cases
        except Exception as exc:
            logger.error("Failed to collect closed cases: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Analyze: compute TP/FP rates per rule, IOC, and response action
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        rule_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0})
        ioc_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0})
        action_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"effective": 0, "ineffective": 0})

        for case in data:
            resolution = case.get("resolution", "")
            is_tp = resolution == "true_positive"

            # --- Rule-level stats ---
            rule_id = case.get("rule_id", case.get("detection_rule", "unknown"))
            if rule_id != "unknown":
                rule_stats[rule_id]["tp" if is_tp else "fp"] += 1

            # --- IOC-level stats ---
            for ioc in case.get("iocs", []):
                ioc_val = ioc if isinstance(ioc, str) else ioc.get("value", "")
                if ioc_val:
                    ioc_stats[ioc_val]["tp" if is_tp else "fp"] += 1

            # --- Response action effectiveness ---
            for act in case.get("actions_taken", []):
                act_name = act if isinstance(act, str) else act.get("action", "")
                if act_name:
                    effective_key = "effective" if is_tp else "ineffective"
                    action_stats[act_name][effective_key] += 1

        findings: List[Dict[str, Any]] = []

        # Evaluate rules
        for rule_id, stats in rule_stats.items():
            total = stats["tp"] + stats["fp"]
            if total < MIN_SAMPLES:
                continue
            fp_rate = stats["fp"] / total
            confidence = 1.0 - fp_rate
            self.rule_scores[rule_id] = {"tp": stats["tp"], "fp": stats["fp"], "confidence": confidence}
            if fp_rate >= HIGH_FP_RATE:
                findings.append({
                    "type": "rule_tune",
                    "rule_id": rule_id,
                    "fp_rate": round(fp_rate, 3),
                    "confidence": round(confidence, 3),
                    "total_cases": total,
                    "recommendation": f"Rule '{rule_id}' has {fp_rate:.0%} FP rate — raise threshold or add exceptions",
                })

        # Evaluate IOCs
        for ioc_val, stats in ioc_stats.items():
            total = stats["tp"] + stats["fp"]
            if total == 0:
                continue
            confidence = stats["tp"] / total
            prev = self.ioc_scores.get(ioc_val, 0.5)
            # exponential moving average with prior
            updated = 0.7 * confidence + 0.3 * prev
            self.ioc_scores[ioc_val] = updated
            if updated < LOW_CONFIDENCE_IOC:
                findings.append({
                    "type": "ioc_age_out",
                    "ioc": ioc_val,
                    "confidence": round(updated, 3),
                    "recommendation": f"IOC '{ioc_val}' confidence {updated:.0%} — consider aging out",
                })

        # Evaluate actions
        for act_name, stats in action_stats.items():
            total = stats["effective"] + stats["ineffective"]
            if total < MIN_SAMPLES:
                continue
            eff_rate = stats["effective"] / total
            self.action_scores[act_name] = stats
            if eff_rate < 0.40:
                findings.append({
                    "type": "action_review",
                    "action": act_name,
                    "effectiveness": round(eff_rate, 3),
                    "recommendation": f"Action '{act_name}' effective only {eff_rate:.0%} — review playbook",
                })

        # Apply decay to IOCs not seen this cycle
        seen_iocs = set(ioc_stats.keys())
        for ioc_val in list(self.ioc_scores.keys()):
            if ioc_val not in seen_iocs:
                self.ioc_scores[ioc_val] = max(0.0, self.ioc_scores[ioc_val] - CONFIDENCE_DECAY)

        logger.info("Analysis complete: %d recommendations generated", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Decide: package recommendations as actionable items
    # ------------------------------------------------------------------
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        for f in findings:
            actions.append({"action": "store_feedback", "finding": f})
            if f["type"] == "rule_tune" and f.get("fp_rate", 0) >= 0.80:
                actions.append({"action": "escalate", "finding": f})
        return actions

    # ------------------------------------------------------------------
    # Act: persist feedback and alert / escalate as needed
    # ------------------------------------------------------------------
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"stored": 0, "escalated": 0}
        for action in actions:
            finding = action["finding"]

            if action["action"] == "store_feedback":
                doc = {
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    "agent_name": self.name,
                    **finding,
                }
                try:
                    doc_id = hashlib.sha256(str(finding).encode()).hexdigest()[:16]
                    self.os_client.index_document(FEEDBACK_INDEX, doc, doc_id=doc_id)
                    results["stored"] += 1
                except Exception as exc:
                    logger.error("Failed to store feedback: %s", exc)

            elif action["action"] == "escalate":
                self.alerter.send_alert(
                    severity=Severity.HIGH,
                    title=f"Rule tuning required: {finding.get('rule_id', 'N/A')}",
                    details=finding,
                    agent_name=self.name,
                )
                self.report_to_supervisor({
                    "type": "tuning_recommendation",
                    **finding,
                })
                results["escalated"] += 1

        if results["stored"]:
            logger.info("Stored %d feedback docs, escalated %d", results["stored"], results["escalated"])
        return results


if __name__ == "__main__":
    agent = ReinforcementLearningAgent()
    agent.run_loop()
