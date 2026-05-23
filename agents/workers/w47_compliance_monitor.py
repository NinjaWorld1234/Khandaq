"""
SOC Platform - Worker Agent W47: Compliance Monitor
وكيل مراقبة الامتثال

Checks system configurations against security baselines via Wazuh SCA:
- Password policy compliance (min length, complexity)
- Audit logging enabled
- Firewall rules configured
- SSH hardening (no root login, key-only auth)
- File permissions on sensitive files
- Encryption at rest status
- Patch compliance (pending updates)
- User account hygiene (inactive accounts)

Generates compliance score (0-100) per host.
Stores results in soc-compliance index with trend tracking.
Interval: 3600 seconds (hourly)
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w47_compliance_monitor")

# SCA rule IDs mapped to compliance checks (Wazuh CIS benchmark rule IDs)
_COMPLIANCE_CHECKS = {
    "password_policy": {
        "weight": 15,
        "rule_ids": ["28650", "28651", "28652"],  # minlen, complexity, history
        "description": "Password policy: minimum length, complexity, history",
    },
    "audit_logging": {
        "weight": 15,
        "rule_ids": ["28703", "28704", "28705"],  # auditd, syslog, log rotation
        "description": "Audit logging: auditd enabled, syslog configured",
    },
    "firewall_config": {
        "weight": 10,
        "rule_ids": ["28750", "28751"],  # iptables/nftables, default deny
        "description": "Firewall: rules configured, default deny policy",
    },
    "ssh_hardening": {
        "weight": 15,
        "rule_ids": ["28660", "28661", "28662", "28663"],  # root login, key auth, protocol, timeout
        "description": "SSH: no root login, key-only auth, protocol v2",
    },
    "file_permissions": {
        "weight": 10,
        "rule_ids": ["28680", "28681", "28682"],  # /etc/shadow, /etc/passwd, crontab
        "description": "File permissions: shadow, passwd, cron restricted",
    },
    "encryption_at_rest": {
        "weight": 10,
        "rule_ids": ["28720", "28721"],  # disk encryption, swap encryption
        "description": "Encryption at rest: disk and swap encrypted",
    },
    "patch_compliance": {
        "weight": 15,
        "rule_ids": ["28800", "28801"],  # pending security updates, kernel updates
        "description": "Patch compliance: no pending security/kernel updates",
    },
    "account_hygiene": {
        "weight": 10,
        "rule_ids": ["28670", "28671", "28672"],  # inactive accounts, default accounts, sudoers
        "description": "Account hygiene: no inactive/default accounts, sudoers reviewed",
    },
}

_TOTAL_WEIGHT = sum(c["weight"] for c in _COMPLIANCE_CHECKS.values())


class ComplianceMonitorAgent(BaseAgent):
    """
    Compliance Monitor (W47).
    Checks system configurations against security baselines using Wazuh SCA.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w47_compliance_monitor",
            description="Audits systems against security compliance baselines",
            interval_seconds=3600,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )

        # Thresholds
        self._critical_score: int = self._agent_config.get("critical_score", 50)
        self._warning_score: int = self._agent_config.get("warning_score", 75)

        # Previous compliance scores for trend detection
        self._previous_scores: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """Fetch Wazuh SCA results and relevant configuration assessment events."""
        try:
            # Collect SCA scan results from the last cycle
            sca_events = self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=65,  # Slightly over 1 hour to avoid gaps
                query={
                    "bool": {
                        "should": [
                            {"match": {"rule.groups": "sca"}},
                            {"match": {"rule.groups": "policy_monitoring"}},
                            {"match": {"rule.groups": "system_audit"}},
                            {"range": {"rule.id": {"gte": "19000", "lte": "19999"}}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                size=5000,
            )

            # Collect vulnerability / patch status events
            vuln_events = self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=65,
                query={"match": {"rule.groups": "vulnerability-detector"}},
                size=2000,
            )

            # Group events by host (agent name)
            hosts: Dict[str, List[Dict[str, Any]]] = {}
            for event in sca_events + vuln_events:
                host = event.get("agent", {}).get("name", "unknown")
                hosts.setdefault(host, []).append(event)

            logger.info("Collected compliance data from %d hosts", len(hosts))
            return hosts if hosts else None

        except Exception as exc:
            logger.error("Failed to collect compliance data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Evaluate compliance checks per host and compute scores."""
        findings: List[Dict[str, Any]] = []

        for host, events in data.items():
            check_results = self._evaluate_host(host, events)
            score = self._compute_score(check_results)

            # Determine severity based on score
            if score < self._critical_score:
                severity = Severity.CRITICAL
            elif score < self._warning_score:
                severity = Severity.HIGH
            elif score < 90:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            # Detect score trends
            previous = self._previous_scores.get(host)
            trend = "stable"
            if previous is not None:
                delta = score - previous
                if delta <= -10:
                    trend = "degrading"
                elif delta >= 10:
                    trend = "improving"

            failed_checks = [
                name for name, result in check_results.items()
                if result["status"] == "fail"
            ]

            findings.append({
                "host": host,
                "score": score,
                "severity": severity,
                "trend": trend,
                "previous_score": previous,
                "check_results": check_results,
                "failed_checks": failed_checks,
                "total_events": len(events),
                "description": (
                    f"Host '{host}' compliance score: {score}/100 "
                    f"({len(failed_checks)} failed checks, trend: {trend})"
                ),
            })

            # Update stored score for next cycle
            self._previous_scores[host] = score

        self._events_processed += sum(len(evts) for evts in data.values())
        return findings

    def _evaluate_host(
        self, host: str, events: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Evaluate each compliance check category for a single host."""
        # Collect all SCA rule IDs that passed on this host
        passed_rules: set = set()
        failed_rules: set = set()
        pending_patches = 0

        for event in events:
            rule_id = str(event.get("rule", {}).get("id", ""))
            sca_result = event.get("data", {}).get("sca", {}).get("check", {}).get("result", "")
            rule_level = int(event.get("rule", {}).get("level", 0))

            if sca_result == "passed" or rule_level <= 3:
                passed_rules.add(rule_id)
            else:
                failed_rules.add(rule_id)

            # Count pending vulnerability patches
            if event.get("rule", {}).get("groups", []) == ["vulnerability-detector"]:
                vuln_status = event.get("data", {}).get("vulnerability", {}).get("status", "")
                if vuln_status in ("Active", "active"):
                    pending_patches += 1

        results: Dict[str, Dict[str, Any]] = {}
        for check_name, check_cfg in _COMPLIANCE_CHECKS.items():
            expected_ids = set(check_cfg["rule_ids"])
            matched_pass = expected_ids & passed_rules
            matched_fail = expected_ids & failed_rules

            if check_name == "patch_compliance":
                # Special handling: fail if there are pending patches
                if pending_patches > 5:
                    status = "fail"
                    pct = max(0, 100 - pending_patches * 5)
                elif pending_patches > 0:
                    status = "partial"
                    pct = max(50, 100 - pending_patches * 10)
                else:
                    status = "pass"
                    pct = 100
            elif matched_fail:
                status = "fail"
                pct = int(len(matched_pass) / max(len(expected_ids), 1) * 100)
            elif matched_pass:
                status = "pass"
                pct = 100
            else:
                # No data — assume unknown/partial compliance
                status = "unknown"
                pct = 50

            results[check_name] = {
                "status": status,
                "pass_pct": pct,
                "weight": check_cfg["weight"],
                "description": check_cfg["description"],
                "pending_patches": pending_patches if check_name == "patch_compliance" else None,
            }

        return results

    def _compute_score(self, check_results: Dict[str, Dict[str, Any]]) -> float:
        """Compute a weighted compliance score (0-100)."""
        weighted_sum = 0.0
        for result in check_results.values():
            weighted_sum += (result["pass_pct"] / 100.0) * result["weight"]
        return round((weighted_sum / _TOTAL_WEIGHT) * 100, 1)

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Determine actions based on compliance findings."""
        actions: List[Dict[str, Any]] = []

        for finding in findings:
            # Always store compliance results
            actions.append({"type": "store_compliance", "finding": finding})

            # Alert only on non-compliant or degrading hosts
            if finding["score"] < self._warning_score or finding["trend"] == "degrading":
                actions.append({
                    "type": "alert",
                    "severity": finding["severity"],
                    "title": f"Compliance Alert: {finding['host']} ({finding['score']}/100)",
                    "details": {
                        "host": finding["host"],
                        "score": finding["score"],
                        "trend": finding["trend"],
                        "failed_checks": ", ".join(finding["failed_checks"]) or "none",
                        "previous_score": finding.get("previous_score", "N/A"),
                    },
                })

            # Escalate critical non-compliance
            if finding["severity"] >= Severity.HIGH:
                actions.append({"type": "escalate", "finding": finding})

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute compliance actions: store results, alert, escalate."""
        stored = 0
        alerts_sent = 0
        escalations = 0

        for action in actions:
            if action["type"] == "store_compliance":
                try:
                    finding = action["finding"]
                    # Serialize check_results for OpenSearch
                    serialized_checks = {}
                    for name, result in finding["check_results"].items():
                        serialized_checks[name] = {
                            "status": result["status"],
                            "pass_pct": result["pass_pct"],
                        }

                    self.os_client.index_document(
                        index="soc-compliance",
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name,
                            "host": finding["host"],
                            "score": finding["score"],
                            "trend": finding["trend"],
                            "previous_score": finding.get("previous_score"),
                            "severity": finding["severity"].name,
                            "failed_checks": finding["failed_checks"],
                            "check_results": serialized_checks,
                            "total_events": finding["total_events"],
                        },
                    )
                    stored += 1
                except Exception as exc:
                    logger.error("Failed to store compliance results: %s", exc)

            elif action["type"] == "alert":
                sent = self.alerter.send_alert(
                    severity=action["severity"],
                    title=action["title"],
                    details=action["details"],
                    agent_name=self.name,
                )
                if sent:
                    alerts_sent += 1
                    self._metrics.inc_alerts(action["severity"].name)

            elif action["type"] == "escalate":
                finding = action["finding"]
                self.report_to_supervisor({
                    "type": "compliance_escalation",
                    "host": finding["host"],
                    "score": finding["score"],
                    "failed_checks": finding["failed_checks"],
                    "trend": finding["trend"],
                })
                escalations += 1

        if stored:
            self.report_to_supervisor({
                "type": "compliance_summary",
                "hosts_evaluated": stored,
                "alerts_sent": alerts_sent,
                "escalations": escalations,
            })

        return {"hosts_evaluated": stored, "alerts_sent": alerts_sent, "escalations": escalations}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = ComplianceMonitorAgent()
    agent.run_loop()
