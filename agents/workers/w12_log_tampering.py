"""
SOC Platform - Worker Agent W12: Log Tampering Detection
وكيل كشف العبث بالسجلات

Detects log suppression and tampering by monitoring event counts per source host:
- Builds a 7-day baseline of average events/hour per host
- CRITICAL alert: host drops from ~500 events/hr to 0 (100% drop)
- HIGH alert: host drops >70% below baseline
- Uses OpenSearch date histogram and terms aggregations

Interval: 300 seconds (5 minutes)
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w12_log_tampering")


class LogTamperingAgent(BaseAgent):
    """
    Log Tampering Detection Agent (W12).
    وكيل كشف العبث بالسجلات

    Compares current event rates per host against a 7-day baseline.
    A sudden drop in events could indicate log suppression, agent failure,
    or an attacker covering their tracks.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w12_log_tampering",
            description="Log Tampering Detection - monitors event volume per host for anomalies",
            interval_seconds=300,  # 5 minutes
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )
        # Thresholds from config
        thresholds = self.config.thresholds
        self._critical_drop_pct: float = thresholds.log_drop_critical_pct  # 100%
        self._high_drop_pct: float = thresholds.log_drop_high_pct          # 70%
        self._baseline_days: int = thresholds.log_baseline_days             # 7 days

        # Source index pattern for all logs
        self._log_index = self._agent_config.get("log_index", "wazuh-alerts-*")

        # Hostname field in the index
        self._host_field = self._agent_config.get("host_field", "agent.name")

        # Minimum baseline events/hour to consider (ignore very quiet hosts)
        self._min_baseline_events_hr = self._agent_config.get(
            "min_baseline_events_hr", 10
        )

        # Whitelist of hosts to skip (e.g. test machines)
        self._host_whitelist: set[str] = set(
            self._agent_config.get("host_whitelist", [])
        )

        # Cache of baselines: host -> avg_events_per_hour
        self._baselines: dict[str, float] = {}
        self._baseline_last_updated: float = 0.0
        self._baseline_refresh_interval = 3600  # Refresh baseline every hour

    # ------------------------------------------------------------------
    # Collect: get current event counts and baseline / جمع البيانات
    # ------------------------------------------------------------------

    def collect(self) -> Optional[dict[str, Any]]:
        """
        Collect current event counts per host and update baselines.

        Returns:
            Dict with 'current_counts' and 'baselines', or None on failure.
        """
        try:
            # Refresh baselines periodically
            now = time.time()
            if now - self._baseline_last_updated > self._baseline_refresh_interval:
                self._update_baselines()

            # Get current event count per host for the last interval
            current_counts = self._get_current_counts()

            if not current_counts and not self._baselines:
                logger.debug("No data available yet — skipping cycle.")
                return None

            return {
                "current_counts": current_counts,
                "baselines": dict(self._baselines),
            }
        except Exception as exc:
            logger.error("Failed to collect log volume data: %s", exc)
            return None

    def _update_baselines(self) -> None:
        """
        Build baseline of average events/hour per host over the last N days.
        Uses OpenSearch date_histogram + terms aggregation.
        """
        baseline_minutes = self._baseline_days * 24 * 60

        aggs = {
            "hosts": {
                "terms": {
                    "field": f"{self._host_field}.keyword"
                    if not self._host_field.endswith(".keyword")
                    else self._host_field,
                    "size": 10000,
                },
                "aggs": {
                    "hourly_buckets": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1h",
                        },
                    },
                },
            },
        }

        query = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{baseline_minutes}m",
                    "lte": "now",
                }
            }
        }

        try:
            result = self.os_client.aggregate(
                index=self._log_index,
                aggs=aggs,
                query=query,
            )

            host_buckets = (result.get("hosts") or {}).get("buckets", [])
            new_baselines: dict[str, float] = {}

            for host_bucket in host_buckets:
                hostname = host_bucket["key"]
                if hostname in self._host_whitelist:
                    continue

                hourly_buckets = (host_bucket.get("hourly_buckets") or {}).get("buckets", [])
                if not hourly_buckets:
                    continue

                # Calculate true average events per hour across the entire baseline window
                total_events = sum(b.get("doc_count", 0) for b in hourly_buckets)
                num_hours = self._baseline_days * 24
                avg_per_hour = total_events / num_hours if num_hours > 0 else 0

                # Only track hosts with meaningful event volume, OR hosts we were ALREADY tracking
                # This prevents "slow taper" evasion where attackers reduce volume gradually to drop off the baseline
                if avg_per_hour >= self._min_baseline_events_hr or hostname in self._baselines:
                    new_baselines[hostname] = avg_per_hour

            self._baselines = new_baselines
            self._baseline_last_updated = time.time()
            logger.info(
                "Updated baselines for %d hosts (baseline_days=%d)",
                len(new_baselines), self._baseline_days,
            )

        except Exception as exc:
            logger.error("Failed to update baselines: %s", exc)

    def _get_current_counts(self) -> dict[str, int]:
        """
        Get event count per host for the last check interval.
        Returns dict of hostname -> event_count.
        """
        # Convert interval to hours for rate comparison
        interval_minutes = self.interval_seconds // 60

        aggs = {
            "hosts": {
                "terms": {
                    "field": f"{self._host_field}.keyword"
                    if not self._host_field.endswith(".keyword")
                    else self._host_field,
                    "size": 10000,
                },
            },
        }

        query = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{interval_minutes}m",
                    "lte": "now",
                }
            }
        }

        try:
            result = self.os_client.aggregate(
                index=self._log_index,
                aggs=aggs,
                query=query,
            )
            host_buckets = (result.get("hosts") or {}).get("buckets", [])
            return {b["key"]: b["doc_count"] for b in host_buckets}
        except Exception as exc:
            logger.error("Failed to get current event counts: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Analyze: detect anomalies / تحليل: كشف الحالات الشاذة
    # ------------------------------------------------------------------

    def analyze(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Compare current event rates against baselines.

        Args:
            data: Dict with 'current_counts' and 'baselines'.

        Returns:
            List of finding dicts for anomalous hosts.
        """
        current = data["current_counts"]
        baselines = data["baselines"]
        findings: list[dict[str, Any]] = []

        # Scale current counts to events/hour for comparison
        interval_hours = self.interval_seconds / 3600.0

        for hostname, baseline_avg in baselines.items():
            try:
                if hostname in self._host_whitelist:
                    continue

                current_count = current.get(hostname, 0)
                current_rate = current_count / interval_hours if interval_hours > 0 else 0

                # Calculate percentage drop from baseline
                if baseline_avg > 0:
                    drop_pct = ((baseline_avg - current_rate) / baseline_avg) * 100
                else:
                    continue  # No meaningful baseline

                if drop_pct >= self._critical_drop_pct:
                    # 100% drop: host went completely silent
                    findings.append({
                        "hostname": hostname,
                        "severity": "CRITICAL",
                        "drop_pct": drop_pct,
                        "baseline_avg_per_hr": round(baseline_avg, 1),
                        "current_rate_per_hr": round(current_rate, 1),
                        "current_count": current_count,
                        "description": (
                            f"Host '{hostname}' has gone SILENT. "
                            f"Expected ~{baseline_avg:.0f} events/hr, got {current_rate:.0f}. "
                            "Possible log tampering or agent failure."
                        ),
                    })
                elif drop_pct >= self._high_drop_pct:
                    # >70% drop: significant reduction
                    findings.append({
                        "hostname": hostname,
                        "severity": "HIGH",
                        "drop_pct": drop_pct,
                        "baseline_avg_per_hr": round(baseline_avg, 1),
                        "current_rate_per_hr": round(current_rate, 1),
                        "current_count": current_count,
                        "description": (
                            f"Host '{hostname}' event volume dropped {drop_pct:.0f}%. "
                            f"Expected ~{baseline_avg:.0f} events/hr, got {current_rate:.0f}. "
                            "Investigate possible log suppression."
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating log tampering rules for %s: %s", hostname, e)

        self._events_processed += len(baselines)
        self._metrics.inc_events(len(baselines))

        if findings:
            logger.warning(
                "Detected %d log volume anomalies across %d monitored hosts",
                len(findings), len(baselines),
            )

        return findings

    # ------------------------------------------------------------------
    # Decide: determine actions / قرار: تحديد الإجراءات
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Decide on actions based on log volume anomalies.

        Args:
            findings: List of anomalous host findings.

        Returns:
            List of action dicts.
        """
        actions: list[dict[str, Any]] = []

        for finding in findings:
            sev_str = finding["severity"]
            severity = Severity.CRITICAL if sev_str == "CRITICAL" else Severity.HIGH

            actions.append({
                "type": "alert",
                "severity": severity,
                "title": f"Log Volume Anomaly: {finding['hostname']}",
                "details": {
                    "hostname": finding["hostname"],
                    "drop_percentage": f"{finding['drop_pct']:.1f}%",
                    "baseline_events_per_hour": finding["baseline_avg_per_hr"],
                    "current_events_per_hour": finding["current_rate_per_hr"],
                    "description": finding["description"],
                },
            })

            # For CRITICAL drops, also log to a dedicated index for investigation
            if severity == Severity.CRITICAL:
                actions.append({
                    "type": "log_incident",
                    "finding": finding,
                })

        return actions

    # ------------------------------------------------------------------
    # Act: execute actions / تنفيذ الإجراءات
    # ------------------------------------------------------------------

    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Execute decided actions.

        Args:
            actions: List of action dicts.

        Returns:
            Summary of actions taken.
        """
        alerts_sent = 0
        incidents_logged = 0

        for action in actions:
            if action["type"] == "alert":
                sent = self.alerter.send_alert(
                    severity=action["severity"],
                    title=action["title"],
                    details=action["details"],
                    agent_name=self.name,
                )
                if sent:
                    alerts_sent += 1
                    self._metrics.inc_alerts(action["severity"].name)

            elif action["type"] == "log_incident":
                try:
                    self.os_client.index_document(
                        index="soc-log-tampering-incidents",
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name,
                            **action["finding"],
                        },
                    )
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log incident: %s", exc)

        if alerts_sent > 0:
            self.report_to_supervisor({
                "type": "log_tampering_report",
                "alerts_sent": alerts_sent,
                "incidents_logged": incidents_logged,
            })

        return {
            "alerts_sent": alerts_sent,
            "incidents_logged": incidents_logged,
        }


# ---------------------------------------------------------------------------
# Entry point for standalone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = LogTamperingAgent()
    agent.run_loop()
