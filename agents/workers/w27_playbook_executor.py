"""
SOC Worker Agent W27 — Playbook Executor
Executes predefined response playbooks based on alert type.
Each playbook is a sequence of action steps tracked in soc-playbook-runs.
"""

import logging
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("W27-PlaybookExecutor")

# ---------------------------------------------------------------------------
# Playbook definitions: alert_type → ordered list of response steps
# ---------------------------------------------------------------------------
PLAYBOOKS: Dict[str, List[Dict[str, Any]]] = {
    "ransomware_detected": [
        {"action": "isolate_host", "description": "Isolate compromised host from network"},
        {"action": "create_case", "description": "Open IR case for ransomware incident"},
        {"action": "gather_forensics", "description": "Collect memory dump and disk image"},
        {"action": "notify_ciso", "description": "Escalate to CISO via priority channel"},
    ],
    "c2_confirmed": [
        {"action": "block_ip", "description": "Block C2 IP at perimeter firewall"},
        {"action": "isolate_host", "description": "Isolate host communicating with C2"},
        {"action": "create_case", "description": "Open IR case for C2 communication"},
    ],
    "brute_force": [
        {"action": "disable_user", "description": "Disable targeted user account"},
        {"action": "create_case", "description": "Open case for brute-force attack"},
        {"action": "notify", "description": "Notify SOC analysts of brute-force event"},
    ],
    "data_exfil": [
        {"action": "isolate_host", "description": "Isolate host performing exfiltration"},
        {"action": "block_ip", "description": "Block destination IP at firewall"},
        {"action": "create_case", "description": "Open IR case for data exfiltration"},
        {"action": "notify_ciso", "description": "Escalate data breach to CISO"},
    ],
}

PLAYBOOK_INDEX = "soc-playbook-runs"
PENDING_INDEX = "soc-alerts"


class PlaybookExecutorAgent(BaseAgent):
    """Executes predefined response playbooks triggered by alert type."""

    def __init__(self) -> None:
        super().__init__(
            name="W27_PlaybookExecutor",
            description="Executes predefined response playbooks based on alert type",
            interval_seconds=30,
            supervisor_channel="soc:response-supervisor",
        )
        self._recent_run_ids: set = set()  # dedup within memory window

    # ------------------------------------------------------------------
    # Collect: fetch alerts queued for automated response
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        query = {
            "bool": {
                "must": [
                    {"terms": {"alert_type.keyword": list(PLAYBOOKS.keys())}},
                    {"term": {"playbook_status.keyword": "pending"}},
                ]
            }
        }
        try:
            events = self.os_client.get_events_since(
                index=PENDING_INDEX, minutes=2, query=query, size=50,
            )
            logger.info("Collected %d pending playbook triggers", len(events))
            return events
        except Exception as exc:
            logger.error("Failed to collect playbook triggers: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Analyze: match each alert to a playbook, dedup by run_id
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for alert in data:
            alert_type = alert.get("alert_type", "")
            if alert_type not in PLAYBOOKS:
                continue
            raw = f"{alert_type}:{alert.get('agent', {}).get('id', '')}:{alert.get('@timestamp', '')}"
            run_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
            if run_id in self._recent_run_ids:
                continue
            self._recent_run_ids.add(run_id)
            findings.append({
                "run_id": run_id,
                "alert_type": alert_type,
                "playbook_steps": PLAYBOOKS[alert_type],
                "source_alert": alert,
                "host": alert.get("agent", {}).get("name", "unknown"),
                "target_ip": alert.get("data", {}).get("srcip", ""),
            })
        # cap memory set
        if len(self._recent_run_ids) > 5000:
            self._recent_run_ids = set(list(self._recent_run_ids)[-2500:])
        return findings

    # ------------------------------------------------------------------
    # Decide: build ordered execution plan for every matched playbook
    # ------------------------------------------------------------------
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        for finding in findings:
            actions.append({
                "action": "execute_playbook",
                "run_id": finding["run_id"],
                "alert_type": finding["alert_type"],
                "steps": finding["playbook_steps"],
                "host": finding["host"],
                "target_ip": finding["target_ip"],
            })
        return actions

    # ------------------------------------------------------------------
    # Act: execute each step, log results to soc-playbook-runs
    # ------------------------------------------------------------------
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"playbooks_executed": 0, "steps_completed": 0, "steps_failed": 0}
        for action in actions:
            run_id = action["run_id"]
            step_results: List[Dict[str, Any]] = []
            overall_status = "completed"

            for idx, step in enumerate(action["steps"], start=1):
                ts = datetime.now(timezone.utc).isoformat()
                step_status, step_msg = self._execute_step(
                    step["action"], action["host"], action["target_ip"],
                )
                step_results.append({
                    "step_number": idx,
                    "action": step["action"],
                    "description": step["description"],
                    "status": step_status,
                    "message": step_msg,
                    "timestamp": ts,
                })
                if step_status == "success":
                    results["steps_completed"] += 1
                else:
                    results["steps_failed"] += 1
                    overall_status = "partial_failure"

            run_doc = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "run_id": run_id,
                "alert_type": action["alert_type"],
                "host": action["host"],
                "status": overall_status,
                "total_steps": len(action["steps"]),
                "steps": step_results,
            }
            try:
                self.os_client.index_document(PLAYBOOK_INDEX, run_doc, doc_id=run_id)
            except Exception as exc:
                logger.error("Failed to index playbook run %s: %s", run_id, exc)

            sev = Severity.HIGH if overall_status == "partial_failure" else Severity.MEDIUM
            self.alerter.send_alert(
                severity=sev,
                title=f"Playbook '{action['alert_type']}' {overall_status}",
                details={"run_id": run_id, "host": action["host"],
                         "steps_ok": results["steps_completed"],
                         "steps_fail": results["steps_failed"]},
                agent_name=self.name,
            )
            results["playbooks_executed"] += 1

        if results["playbooks_executed"]:
            logger.info("Executed %d playbooks (%d steps ok, %d failed)",
                        results["playbooks_executed"],
                        results["steps_completed"], results["steps_failed"])
        return results

    # ------------------------------------------------------------------
    # Step executors (simulate actions; real env would call APIs)
    # ------------------------------------------------------------------
    def _execute_step(self, action: str, host: str, target_ip: str) -> tuple:
        """Execute a single playbook step. Returns (status, message)."""
        try:
            if action == "block_ip":
                logger.info("Blocking IP %s at perimeter firewall", target_ip)
                self.report_to_supervisor({"type": "block_ip", "ip": target_ip})
                return ("success", f"Firewall block request sent for {target_ip}")

            elif action == "isolate_host":
                logger.info("Isolating host %s from network", host)
                self.report_to_supervisor({"type": "isolate_host", "host": host})
                return ("success", f"Isolation request sent for {host}")

            elif action == "disable_user":
                logger.info("Disabling user account on host %s", host)
                self.report_to_supervisor({"type": "disable_user", "host": host})
                return ("success", f"User disable request sent for {host}")

            elif action == "create_case":
                logger.info("Creating IR case for host %s", host)
                self.report_to_supervisor({"type": "create_case", "host": host})
                return ("success", f"Case created for {host}")

            elif action in ("notify", "notify_ciso"):
                logger.info("Sending notification: %s for host %s", action, host)
                return ("success", f"Notification sent ({action})")

            elif action == "gather_forensics":
                logger.info("Initiating forensics collection on %s", host)
                self.report_to_supervisor({"type": "gather_forensics", "host": host})
                return ("success", f"Forensics collection initiated on {host}")

            elif action == "enrich_ioc":
                logger.info("Enriching IOC %s via threat intel", target_ip)
                return ("success", f"IOC enrichment submitted for {target_ip}")

            else:
                return ("skipped", f"Unknown action type: {action}")

        except Exception as exc:
            logger.error("Step '%s' failed: %s", action, exc)
            return ("failed", str(exc))


if __name__ == "__main__":
    agent = PlaybookExecutorAgent()
    agent.run_loop()
