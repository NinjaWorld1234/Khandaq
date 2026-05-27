"""
SOC Platform - Worker Agent W26: Smart Decision Engine
محرك القرار الذكي

Receives CRITICAL and HIGH alerts and determines the appropriate response
level using a contextual decision matrix:

  ┌────────────┬─────────────────┬──────────────────────┐
  │ Severity   │ Critical Asset  │ Response             │
  ├────────────┼─────────────────┼──────────────────────┤
  │ CRITICAL   │ Yes             │ ISOLATE + page CISO  │
  │ CRITICAL   │ No              │ ISOLATE + notify SOC │
  │ HIGH       │ Yes (not DC)    │ INVESTIGATE, no iso  │
  │ HIGH       │ No              │ MONITOR + open case  │
  └────────────┴─────────────────┴──────────────────────┘

Additional factors:
  - Business hours check (08:00-18:00 local = work hours; outside = higher risk)
  - Historical incidents on the same host (repeat offenders get escalated)
  - Human-readable rationale generated for every decision

Interval: 30 seconds
Supervisor channel: soc:response-supervisor
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w26_smart_decision")

# ---------------------------------------------------------------------------
# Asset criticality registry
# ---------------------------------------------------------------------------

CRITICAL_ASSETS: Dict[str, Dict[str, Any]] = {
    # Domain Controllers – NEVER isolate
    "dc01": {"type": "domain_controller", "isolatable": False, "owner": "IT-Infrastructure"},
    "dc02": {"type": "domain_controller", "isolatable": False, "owner": "IT-Infrastructure"},
    "ad-primary": {"type": "domain_controller", "isolatable": False, "owner": "IT-Infrastructure"},
    # Database servers
    "db-prod-01": {"type": "database", "isolatable": True, "owner": "DBA-Team"},
    "db-prod-02": {"type": "database", "isolatable": True, "owner": "DBA-Team"},
    "sql-finance": {"type": "database", "isolatable": True, "owner": "Finance-IT"},
    # Executive machines
    "exec-ceo": {"type": "executive", "isolatable": True, "owner": "Executive-Office"},
    "exec-cfo": {"type": "executive", "isolatable": True, "owner": "Executive-Office"},
    "exec-cto": {"type": "executive", "isolatable": True, "owner": "Executive-Office"},
    # Core infrastructure
    "mail-gw-01": {"type": "mail_gateway", "isolatable": False, "owner": "IT-Infrastructure"},
    "vpn-gw-01": {"type": "vpn_gateway", "isolatable": False, "owner": "IT-Infrastructure"},
    "siem-01": {"type": "siem", "isolatable": False, "owner": "SOC-Team"},
    "ca-root": {"type": "certificate_authority", "isolatable": False, "owner": "IT-Security"},
}

# Business-hours config (UTC-based; adjust offset via agent config)
BUSINESS_HOUR_START = 8
BUSINESS_HOUR_END = 18

ALERT_INDEX = "soc-alerts"
DECISION_INDEX = "soc-decisions"
CASES_INDEX = "soc-cases"
INCIDENT_HISTORY_INDEX = "soc-incidents"


class SmartDecisionAgent(BaseAgent):
    """
    Smart Decision Engine (W26).
    Evaluates CRITICAL/HIGH alerts against asset criticality, business hours,
    and incident history to determine the optimal response level.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w26_smart_decision",
            description="Smart response-level decision engine for CRITICAL and HIGH alerts",
            interval_seconds=30,
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self._alert_index: str = self._agent_config.get(
            "alert_index", ALERT_INDEX)
        self._decision_index: str = self._agent_config.get(
            "decision_index", DECISION_INDEX)
        self._tz_offset_hours: int = self._agent_config.get(
            "tz_offset_hours", 0)
        self._processed_alert_ids: Set[str] = set()
        self._processed_cache_max = 5000
        self._total_decisions: int = 0

    # ------------------------------------------------------------------
    # Collect: fetch un-decided CRITICAL and HIGH alerts
    # ------------------------------------------------------------------

    def collect(self) -> Optional[List[Dict[str, Any]]]:
        """Pull recent CRITICAL/HIGH alerts that have not been decided on."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"terms": {"severity": ["CRITICAL", "HIGH"]}},
                        {"term": {"decision_made": False}},
                    ],
                }
            }
            alerts = self.os_client.get_events_since(
                index=self._alert_index,
                minutes=5,
                query=query,
                size=10000,
            )

            # Filter out already-processed alerts (in-memory dedup)
            new_alerts = [
                a for a in alerts if a.get(
                    "_id", a.get(
                        "id", "")) not in self._processed_alert_ids]

            if new_alerts:
                logger.info(
                    "Collected %d new CRITICAL/HIGH alerts for decision (%d filtered as duplicates)",
                    len(new_alerts),
                    len(alerts) -
                    len(new_alerts),
                )
            return new_alerts if new_alerts else None

        except Exception as exc:
            logger.error("Failed to collect alerts for decision: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze: gather context for each alert
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich each alert with asset criticality, business-hours, and history."""
        findings: list[dict[str, Any]] = []

        for alert in data:
            try:
                alert_id = alert.get("_id", alert.get("id", "unknown"))
                hostname = self._extract_hostname(alert)
                severity_str = alert.get(
                    "severity", alert.get(
                        "alert_severity", "HIGH")).upper()
                severity = Severity.CRITICAL if severity_str == "CRITICAL" else Severity.HIGH

                # Asset criticality lookup
                asset_info = self._lookup_asset(hostname)
                is_critical_asset = asset_info is not None
                asset_type = asset_info["type"] if asset_info else "standard"
                is_isolatable = asset_info["isolatable"] if asset_info else True
                asset_owner = asset_info["owner"] if asset_info else "IT-General"

                # Business hours check
                is_business_hours = self._is_business_hours()

                # Historical incident check
                prior_incidents = self._check_incident_history(hostname)
                is_repeat_offender = prior_incidents > 0

                findings.append({
                    "alert_id": alert_id,
                    "alert": alert,
                    "hostname": hostname,
                    "severity": severity,
                    "severity_str": severity_str,
                    "is_critical_asset": is_critical_asset,
                    "asset_type": asset_type,
                    "is_isolatable": is_isolatable,
                    "asset_owner": asset_owner,
                    "is_business_hours": is_business_hours,
                    "prior_incidents": prior_incidents,
                    "is_repeat_offender": is_repeat_offender,
                })
                self._events_processed += 1
                self._metrics.inc_events(1)
            except Exception as e:
                logger.warning("Error analyzing alert: %s", e)

        return findings

    # ------------------------------------------------------------------
    # Decide: apply the decision matrix
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply the decision matrix to determine response level."""
        actions: list[dict[str, Any]] = []

        for ctx in findings:
            try:
                severity = ctx["severity"]
                is_critical = ctx["is_critical_asset"]
                is_isolatable = ctx["is_isolatable"]
                is_after_hours = not ctx["is_business_hours"]
                is_repeat = ctx["is_repeat_offender"]

                response_level = "MONITOR"
                should_isolate = False
                notify_targets: list[str] = ["SOC-Team"]
                rationale_parts: list[str] = []
                case_priority = "medium"

                # --- Decision Matrix ---
                if severity == Severity.CRITICAL and is_critical:
                    response_level = "ISOLATE"
                    should_isolate = is_isolatable
                    notify_targets = ["CISO", "SOC-Team", ctx["asset_owner"]]
                    case_priority = "critical"
                    rationale_parts.append(
                        f"CRITICAL alert on critical asset ({ctx['asset_type']})"
                    )
                    if not is_isolatable:
                        response_level = "INVESTIGATE"
                        should_isolate = False
                        rationale_parts.append(
                            f"Asset type '{ctx['asset_type']}' is NOT isolatable — "
                            "investigating without isolation to preserve service availability")
                    else:
                        rationale_parts.append(
                            "Asset is isolatable — proceeding with network isolation"
                        )

                elif severity == Severity.CRITICAL and not is_critical:
                    response_level = "ISOLATE"
                    should_isolate = True
                    notify_targets = ["SOC-Team"]
                    case_priority = "high"
                    rationale_parts.append(
                        "CRITICAL alert on standard asset — isolating and notifying SOC"
                    )

                elif severity == Severity.HIGH and is_critical:
                    response_level = "INVESTIGATE"
                    should_isolate = False
                    notify_targets = ["SOC-Team", ctx["asset_owner"]]
                    case_priority = "high"
                    rationale_parts.append(
                        f"HIGH alert on critical asset ({ctx['asset_type']}) — "
                        "investigating without isolation to avoid service disruption")

                elif severity == Severity.HIGH and not is_critical:
                    response_level = "MONITOR"
                    should_isolate = False
                    notify_targets = ["SOC-Team"]
                    case_priority = "medium"
                    rationale_parts.append(
                        "HIGH alert on standard asset — monitoring and opening case"
                    )

                # After-hours escalation
                if is_after_hours:
                    case_priority = self._escalate_priority(case_priority)
                    rationale_parts.append(
                        "After-hours alert — priority escalated due to reduced staff coverage"
                    )

                # Repeat offender escalation
                if is_repeat:
                    case_priority = self._escalate_priority(case_priority)
                    rationale_parts.append(
                        f"Host has {ctx['prior_incidents']} prior incident(s) — "
                        "priority escalated as repeat offender"
                    )
                    if response_level == "MONITOR":
                        response_level = "INVESTIGATE"
                        rationale_parts.append(
                            "Upgrading from MONITOR to INVESTIGATE due to incident history"
                        )

                # Build human-readable rationale
                rationale = self._build_rationale(
                    ctx, response_level, rationale_parts)

                decision = {
                    "type": "decision",
                    "alert_id": ctx["alert_id"],
                    "hostname": ctx["hostname"],
                    "severity_str": ctx["severity_str"],
                    "response_level": response_level,
                    "should_isolate": should_isolate,
                    "notify_targets": notify_targets,
                    "case_priority": case_priority,
                    "rationale": rationale,
                    "rationale_parts": rationale_parts,
                    "context": {
                        "is_critical_asset": is_critical,
                        "asset_type": ctx["asset_type"],
                        "is_isolatable": is_isolatable,
                        "is_business_hours": ctx["is_business_hours"],
                        "prior_incidents": ctx["prior_incidents"],
                    },
                }
                actions.append(decision)
                logger.info(
                    "Decision for alert %s on %s: %s (isolate=%s, priority=%s)",
                    ctx["alert_id"], ctx["hostname"],
                    response_level, should_isolate, case_priority,
                )
            except Exception as e:
                logger.warning("Error deciding for alert: %s", e)

        return actions

    # ------------------------------------------------------------------
    # Act: execute decisions
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Store decisions, send alerts, and report to supervisor."""
        decisions_stored = 0
        notifications_sent = 0
        cases_created = 0

        for decision in actions:
            alert_id = decision["alert_id"]
            try:
                # 1. Store the decision record
                self.os_client.index_document(
                    self._decision_index,
                    document={
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent_name": self.name,
                        "alert_id": alert_id,
                        "hostname": decision["hostname"],
                        "severity": decision["severity_str"],
                        "response_level": decision["response_level"],
                        "should_isolate": decision["should_isolate"],
                        "notify_targets": decision["notify_targets"],
                        "case_priority": decision["case_priority"],
                        "rationale": decision["rationale"],
                        "context": decision["context"],
                    },
                )
                decisions_stored += 1
                self._total_decisions += 1

                # 2. Send notification alert
                alert_sev = (
                    Severity.CRITICAL if decision["response_level"] == "ISOLATE"
                    else Severity.HIGH if decision["response_level"] == "INVESTIGATE"
                    else Severity.MEDIUM
                )
                sent = self.alerter.send_alert(
                    severity=alert_sev,
                    title=f"Decision: {decision['response_level']} — {decision['hostname']}",
                    details={
                        "alert_id": alert_id,
                        "hostname": decision["hostname"],
                        "response_level": decision["response_level"],
                        "should_isolate": decision["should_isolate"],
                        "case_priority": decision["case_priority"],
                        "notify_targets": decision["notify_targets"],
                        "rationale": decision["rationale"],
                    },
                    agent_name=self.name,
                )
                if sent:
                    notifications_sent += 1
                    self._metrics.inc_alerts(alert_sev.name)

                # 3. Create a case for INVESTIGATE / MONITOR responses
                if decision["response_level"] in ("INVESTIGATE", "MONITOR"):
                    self.os_client.index_document(
                        CASES_INDEX,
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "status": "open",
                            "priority": decision["case_priority"],
                            "hostname": decision["hostname"],
                            "alert_id": alert_id,
                            "response_level": decision["response_level"],
                            "rationale": decision["rationale"],
                            "created_by": self.name,
                        },
                    )
                    cases_created += 1

                # Mark alert as processed (in-memory)
                self._processed_alert_ids.add(alert_id)

            except Exception as exc:
                logger.error(
                    "Failed to execute decision for alert %s: %s",
                    alert_id,
                    exc)

        # Prune in-memory cache
        if len(self._processed_alert_ids) > self._processed_cache_max:
            excess = len(self._processed_alert_ids) - self._processed_cache_max
            for _ in range(excess):
                self._processed_alert_ids.pop()

        summary = {
            "decisions_stored": decisions_stored,
            "notifications_sent": notifications_sent,
            "cases_created": cases_created,
            "total_decisions_cumulative": self._total_decisions,
        }

        if decisions_stored:
            self.report_to_supervisor({
                "type": "smart_decision_report",
                **summary,
            })
            logger.info("Decision cycle complete: %s", summary)

        return summary

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_hostname(alert: Dict[str, Any]) -> str:
        """Extract hostname from alert, trying multiple field paths."""
        hostname = (
            alert.get("hostname")
            or (alert.get("host") or {}).get("name")
            or (alert.get("agent") or {}).get("name")
            or (alert.get("source") or {}).get("hostname")
            or alert.get("computer_name")
            or "unknown-host"
        )
        return hostname.lower().strip()

    @staticmethod
    def _lookup_asset(hostname: str) -> Optional[Dict[str, Any]]:
        """Check if hostname is a critical asset."""
        return CRITICAL_ASSETS.get(hostname)

    def _is_business_hours(self) -> bool:
        """Check if current time is within business hours."""
        now = datetime.now(timezone.utc) + \
            timedelta(hours=self._tz_offset_hours)
        return BUSINESS_HOUR_START <= now.hour < BUSINESS_HOUR_END and now.weekday() < 5

    def _check_incident_history(self, hostname: str) -> int:
        """Query OpenSearch for prior incidents on this host in the last 30 days."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"term": {"hostname": hostname}},
                    ],
                }
            }
            incidents = self.os_client.get_events_since(
                index=INCIDENT_HISTORY_INDEX,
                minutes=43200,  # 30 days
                query=query,
                size=10000,
            )
            return len(incidents)
        except Exception:
            return 0

    @staticmethod
    def _escalate_priority(current: str) -> str:
        """Escalate a case priority one level up."""
        ladder = ["low", "medium", "high", "critical"]
        idx = ladder.index(current) if current in ladder else 1
        return ladder[min(idx + 1, len(ladder) - 1)]

    @staticmethod
    def _build_rationale(
        ctx: Dict[str, Any],
        response_level: str,
        parts: List[str],
    ) -> str:
        """Assemble a human-readable decision rationale."""
        lines = [
            "═══ Smart Decision Rationale ═══",
            f"Host:           {ctx['hostname']}",
            f"Alert ID:       {ctx['alert_id']}",
            f"Severity:       {ctx['severity_str']}",
            f"Asset Type:     {ctx['asset_type']}",
            f"Critical Asset: {'Yes' if ctx['is_critical_asset'] else 'No'}",
            f"Isolatable:     {'Yes' if ctx['is_isolatable'] else 'No'}",
            f"Business Hours: {'Yes' if ctx['is_business_hours'] else 'No (after-hours)'}",
            f"Prior Incidents:{ctx['prior_incidents']}",
            "────────────────────────────────",
            f"Decision:       {response_level}",
            "",
            "Reasoning:",
        ]
        for i, part in enumerate(parts, 1):
            lines.append(f"  {i}. {part}")
        lines.append("════════════════════════════════")
        return "\n".join(lines)


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
    agent = SmartDecisionAgent()
    agent.run_loop()
