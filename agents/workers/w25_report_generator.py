"""
SOC Platform - Worker Agent W25: Security Report Generator
وكيل توليد تقارير الأمن

Generates periodic security reports from aggregated OpenSearch data.
Each hourly cycle produces a daily summary covering the last 24 hours:
  - Total alerts broken down by severity
  - Top 10 most-triggered detection rules
  - Top 5 most-targeted hosts
  - New IOCs ingested
  - Open cases count
  - Trend comparison: alert count vs. the previous 24-hour window

Reports are stored in the soc-reports index for dashboards and auditing.

Interval: 3600 seconds (hourly)
Supervisor channel: soc:response-supervisor
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w25_report_generator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALERT_INDEX = "soc-alerts"
IOC_INDEX = "soc-iocs"
CASES_INDEX = "soc-cases"
REPORT_INDEX = "soc-reports"
REPORT_WINDOW_HOURS = 24


class ReportGeneratorAgent(BaseAgent):
    """
    Security Report Generator (W25).
    Queries OpenSearch aggregations over the last 24 hours and produces
    structured daily security reports with trend analysis.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w25_report_generator",
            description="Generates periodic security reports from aggregated SOC data",
            interval_seconds=3600,
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self._alert_index: str = self._agent_config.get("alert_index", ALERT_INDEX)
        self._ioc_index: str = self._agent_config.get("ioc_index", IOC_INDEX)
        self._cases_index: str = self._agent_config.get("cases_index", CASES_INDEX)
        self._report_index: str = self._agent_config.get("report_index", REPORT_INDEX)
        self._reports_generated: int = 0

    # ------------------------------------------------------------------
    # Collect: gather aggregated metrics from OpenSearch
    # ------------------------------------------------------------------

    def collect(self) -> Optional[Dict[str, Any]]:
        """Pull alert, IOC, and case aggregations for the report window."""
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=REPORT_WINDOW_HOURS)
        prev_start = window_start - timedelta(hours=REPORT_WINDOW_HOURS)

        try:
            raw: Dict[str, Any] = {
                "current_alerts": self._query_alerts(window_start, now),
                "previous_alerts": self._query_alerts(prev_start, window_start),
                "top_rules": self._query_top_rules(window_start, now, size=10),
                "top_hosts": self._query_top_hosts(window_start, now, size=5),
                "new_iocs": self._query_new_iocs(window_start, now),
                "open_cases": self._query_open_cases(),
                "window_start": window_start.isoformat(),
                "window_end": now.isoformat(),
            }
            logger.info(
                "Collected report data: %d current alerts, %d previous alerts",
                raw["current_alerts"].get("total", 0),
                raw["previous_alerts"].get("total", 0),
            )
            return raw
        except Exception as exc:
            logger.error("Failed to collect report data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze: compute trends and build report structure
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compute trends and assemble the report payload."""
        current = data["current_alerts"]
        previous = data["previous_alerts"]

        current_total = current.get("total", 0)
        previous_total = previous.get("total", 0)

        # Trend calculation
        if previous_total > 0:
            trend_pct = round(
                ((current_total - previous_total) / previous_total) * 100, 1
            )
        else:
            trend_pct = 100.0 if current_total > 0 else 0.0

        if trend_pct > 0:
            trend_direction = "increasing"
        elif trend_pct < 0:
            trend_direction = "decreasing"
        else:
            trend_direction = "stable"

        # Build severity breakdown
        severity_breakdown = current.get("by_severity", {})
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity_breakdown.setdefault(sev, 0)

        report: Dict[str, Any] = {
            "report_type": "daily_security_summary",
            "window_start": data["window_start"],
            "window_end": data["window_end"],
            "total_alerts": current_total,
            "severity_breakdown": severity_breakdown,
            "top_10_rules": data["top_rules"],
            "top_5_hosts": data["top_hosts"],
            "new_iocs_count": data["new_iocs"],
            "open_cases_count": data["open_cases"],
            "trend": {
                "direction": trend_direction,
                "percentage": trend_pct,
                "previous_total": previous_total,
                "current_total": current_total,
            },
            "risk_highlights": self._compute_risk_highlights(
                severity_breakdown, trend_pct, data["open_cases"]
            ),
        }

        self._events_processed += 1
        self._metrics.inc_events(1)
        logger.info(
            "Report analysis complete: %d alerts (%s %.1f%%), %d open cases",
            current_total, trend_direction, abs(trend_pct), data["open_cases"],
        )
        return report

    # ------------------------------------------------------------------
    # Decide: determine if report should be stored and if alerts needed
    # ------------------------------------------------------------------

    def decide(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Decide whether to store the report and generate alert."""
        actions: list[dict[str, Any]] = [
            {"type": "store_report", "report": report},
        ]

        # Alert on significant trend changes
        trend_pct = report["trend"]["percentage"]
        critical_count = report["severity_breakdown"].get("CRITICAL", 0)

        if trend_pct >= 50 and report["total_alerts"] > 10:
            actions.append({
                "type": "trend_alert",
                "severity": Severity.HIGH,
                "title": "Alert Volume Spike Detected",
                "details": {
                    "trend_percentage": trend_pct,
                    "current_total": report["total_alerts"],
                    "previous_total": report["trend"]["previous_total"],
                    "message": (
                        f"Alert volume increased by {trend_pct}% compared to "
                        f"previous {REPORT_WINDOW_HOURS}h window"
                    ),
                },
            })

        if critical_count >= 5:
            actions.append({
                "type": "trend_alert",
                "severity": Severity.CRITICAL,
                "title": "High Number of Critical Alerts",
                "details": {
                    "critical_count": critical_count,
                    "window_hours": REPORT_WINDOW_HOURS,
                    "message": (
                        f"{critical_count} CRITICAL alerts in the last "
                        f"{REPORT_WINDOW_HOURS} hours — immediate review recommended"
                    ),
                },
            })

        return actions

    # ------------------------------------------------------------------
    # Act: store report and send notifications
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Persist report to OpenSearch and send any trend alerts."""
        reports_stored = 0
        alerts_sent = 0

        for action in actions:
            try:
                if action["type"] == "store_report":
                    report = action["report"]
                    self.os_client.index_document(
                        self._report_index,
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name,
                            **report,
                        },
                    )
                    reports_stored += 1
                    self._reports_generated += 1
                    logger.info(
                        "Stored daily report #%d: %d alerts, trend=%s",
                        self._reports_generated,
                        report["total_alerts"],
                        report["trend"]["direction"],
                    )

                elif action["type"] == "trend_alert":
                    sent = self.alerter.send_alert(
                        severity=action["severity"],
                        title=action["title"],
                        details=action["details"],
                        agent_name=self.name,
                    )
                    if sent:
                        alerts_sent += 1
                        self._metrics.inc_alerts(action["severity"].name)

            except Exception as exc:
                logger.error("Failed report action %s: %s", action["type"], exc)

        # Report to supervisor
        if reports_stored:
            self.report_to_supervisor({
                "type": "report_generation_complete",
                "reports_stored": reports_stored,
                "alerts_sent": alerts_sent,
                "total_reports_generated": self._reports_generated,
            })

        return {"reports_stored": reports_stored, "alerts_sent": alerts_sent}

    # ------------------------------------------------------------------
    # OpenSearch query helpers
    # ------------------------------------------------------------------

    def _query_alerts(
        self, start: datetime, end: datetime
    ) -> Dict[str, Any]:
        """Get alert count + severity breakdown for a time window."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gte": start.isoformat(),
                            "lte": end.isoformat(),
                        }}},
                    ],
                }
            }
            alerts = self.os_client.get_events_since(
                index=self._alert_index,
                minutes=0,
                query=query,
                size=1,
            )
            # Build severity breakdown from full query
            all_alerts = self.os_client.get_events_since(
                index=self._alert_index,
                minutes=0,
                query=query,
                size=5000,
            )
            by_severity: Dict[str, int] = {}
            for alert in all_alerts:
                sev = alert.get("severity", alert.get("alert_severity", "UNKNOWN"))
                if isinstance(sev, str):
                    sev = sev.upper()
                by_severity[sev] = by_severity.get(sev, 0) + 1

            return {"total": len(all_alerts), "by_severity": by_severity}
        except Exception as exc:
            logger.error("Alert query failed: %s", exc)
            return {"total": 0, "by_severity": {}}

    def _query_top_rules(
        self, start: datetime, end: datetime, size: int = 10
    ) -> List[Dict[str, Any]]:
        """Get the top N triggered detection rules."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gte": start.isoformat(),
                            "lte": end.isoformat(),
                        }}},
                    ],
                }
            }
            alerts = self.os_client.get_events_since(
                index=self._alert_index,
                minutes=0,
                query=query,
                size=5000,
            )
            rule_counts: Dict[str, int] = {}
            for alert in alerts:
                rule = alert.get("rule_name", alert.get("title", "unknown"))
                rule_counts[rule] = rule_counts.get(rule, 0) + 1

            sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
            return [
                {"rule_name": name, "count": count}
                for name, count in sorted_rules[:size]
            ]
        except Exception as exc:
            logger.error("Top rules query failed: %s", exc)
            return []

    def _query_top_hosts(
        self, start: datetime, end: datetime, size: int = 5
    ) -> List[Dict[str, Any]]:
        """Get the top N most-targeted hosts."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {
                            "gte": start.isoformat(),
                            "lte": end.isoformat(),
                        }}},
                    ],
                }
            }
            alerts = self.os_client.get_events_since(
                index=self._alert_index,
                minutes=0,
                query=query,
                size=5000,
            )
            host_counts: Dict[str, int] = {}
            for alert in alerts:
                host = (
                    alert.get("host", {}).get("name")
                    or alert.get("agent_name")
                    or alert.get("hostname", "unknown")
                )
                host_counts[host] = host_counts.get(host, 0) + 1

            sorted_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)
            return [
                {"hostname": name, "alert_count": count}
                for name, count in sorted_hosts[:size]
            ]
        except Exception as exc:
            logger.error("Top hosts query failed: %s", exc)
            return []

    def _query_new_iocs(self, start: datetime, end: datetime) -> int:
        """Count IOCs created in the time window."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"range": {"created_at": {
                            "gte": start.isoformat(),
                            "lte": end.isoformat(),
                        }}},
                    ],
                }
            }
            iocs = self.os_client.get_events_since(
                index=self._ioc_index,
                minutes=0,
                query=query,
                size=1,
            )
            # Use length as count proxy
            all_iocs = self.os_client.get_events_since(
                index=self._ioc_index,
                minutes=0,
                query=query,
                size=5000,
            )
            return len(all_iocs)
        except Exception as exc:
            logger.error("New IOCs query failed: %s", exc)
            return 0

    def _query_open_cases(self) -> int:
        """Count open/active cases."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"term": {"status": "open"}},
                    ],
                }
            }
            cases = self.os_client.get_events_since(
                index=self._cases_index,
                minutes=0,
                query=query,
                size=5000,
            )
            return len(cases)
        except Exception as exc:
            logger.error("Open cases query failed: %s", exc)
            return 0

    # ------------------------------------------------------------------
    # Risk highlights
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_highlights(
        severity_breakdown: Dict[str, int],
        trend_pct: float,
        open_cases: int,
    ) -> List[str]:
        """Generate human-readable risk highlight bullets."""
        highlights: list[str] = []
        crit = severity_breakdown.get("CRITICAL", 0)
        high = severity_breakdown.get("HIGH", 0)

        if crit > 0:
            highlights.append(f"⚠ {crit} CRITICAL alert(s) require immediate attention")
        if high > 5:
            highlights.append(f"⚠ {high} HIGH-severity alerts detected — review recommended")
        if trend_pct >= 50:
            highlights.append(
                f"📈 Alert volume increased by {trend_pct}% vs. previous period"
            )
        if trend_pct <= -30:
            highlights.append(
                f"📉 Alert volume decreased by {abs(trend_pct)}% — possible detection gap?"
            )
        if open_cases > 20:
            highlights.append(
                f"📋 {open_cases} open cases — consider prioritizing case closure"
            )
        if not highlights:
            highlights.append("✅ No significant risk indicators in this period")

        return highlights


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
    agent = ReportGeneratorAgent()
    agent.run_loop()
