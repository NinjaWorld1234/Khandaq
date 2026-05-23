"""
SOC Platform - Worker Agent W23: Auto Case Creation
وكيل إنشاء الحالات الآلي

Monitors HIGH and CRITICAL alerts from OpenSearch (soc-alerts-* index).
Creates investigation cases with:
- Unique case ID, severity mapping, affected host, alert summary
- Deduplication: no duplicate case for same host + alert type within 4 hours
- Grouping: related alerts on the same host within 30-minute window → same case
- Cases stored in soc-cases with: case_id, status, severity, alerts list, timeline

Interval: 60 seconds
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w23_auto_case")

_DEDUP_WINDOW_HOURS = 4
_GROUP_WINDOW_MINUTES = 30
_CASES_INDEX = "soc-cases"
_ALERTS_INDEX = "soc-alerts-*"


class AutoCaseAgent(BaseAgent):
    """Automatically creates and groups investigation cases from high-severity alerts."""

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w23_auto_case",
            description="Auto-creates investigation cases from HIGH/CRITICAL alerts",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self._recent_case_keys: Dict[str, float] = {}  # dedup key → creation timestamp

    # ── Collect ─────────────────────────────────────────────────────
    def collect(self) -> Optional[Dict[str, Any]]:
        """Fetch HIGH and CRITICAL alerts from the last 5 minutes."""
        try:
            query = {
                "bool": {
                    "should": [
                        {"match": {"severity": "HIGH"}},
                        {"match": {"severity": "CRITICAL"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            alerts = self.os_client.get_events_since(
                index=_ALERTS_INDEX, minutes=5, query=query, size=500,
            )
            return {"alerts": alerts}
        except Exception as exc:
            logger.error("Failed to collect alerts for case creation: %s", exc)
            return None

    # ── Analyze ─────────────────────────────────────────────────────
    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Group alerts by host and check for deduplication."""
        alerts = data.get("alerts", [])
        if not alerts:
            return []

        # Group by host within 30-minute windows
        host_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for alert in alerts:
            host = (
                alert.get("agent", {}).get("name")
                or alert.get("details", {}).get("host")
                or alert.get("host", "unknown")
            )
            host_groups[host].append(alert)

        self._events_processed += len(alerts)
        findings: List[Dict[str, Any]] = []

        for host, host_alerts in host_groups.items():
            # Determine the dominant alert type for deduplication
            alert_types: Dict[str, int] = defaultdict(int)
            for a in host_alerts:
                a_type = a.get("title", a.get("rule", {}).get("description", "unknown"))
                alert_types[a_type] += 1
            dominant_type = max(alert_types, key=alert_types.get)  # type: ignore[arg-type]

            dedup_key = self._make_dedup_key(host, dominant_type)
            if self._is_duplicate(dedup_key):
                logger.debug("Duplicate case suppressed: host=%s type=%s", host, dominant_type)
                continue

            # Find max severity across grouped alerts
            max_sev = max(
                (self._parse_severity(a.get("severity", "MEDIUM")) for a in host_alerts),
                default=Severity.HIGH,
            )

            findings.append({
                "host": host,
                "alert_type": dominant_type,
                "severity": max_sev,
                "alert_count": len(host_alerts),
                "alerts": host_alerts[:20],  # cap sample
                "dedup_key": dedup_key,
            })

        if findings:
            logger.info("Identified %d new case candidates", len(findings))
        return findings

    # ── Decide ──────────────────────────────────────────────────────
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create a case action for each finding, check if existing open case exists."""
        actions: List[Dict[str, Any]] = []
        for finding in findings:
            existing = self._find_existing_case(finding["host"])
            if existing:
                actions.append({
                    "type": "update_case",
                    "case_id": existing,
                    "new_alerts": finding["alerts"],
                    "host": finding["host"],
                })
            else:
                case_id = self._generate_case_id(finding["host"])
                actions.append({
                    "type": "create_case",
                    "case_id": case_id,
                    "host": finding["host"],
                    "severity": finding["severity"],
                    "alert_type": finding["alert_type"],
                    "alert_count": finding["alert_count"],
                    "alerts": finding["alerts"],
                    "dedup_key": finding["dedup_key"],
                })
        return actions

    # ── Act ──────────────────────────────────────────────────────────
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create or update cases in OpenSearch."""
        created = 0
        updated = 0
        now = datetime.now(timezone.utc).isoformat()

        for action in actions:
            try:
                if action["type"] == "create_case":
                    alert_summaries = [
                        {
                            "title": a.get("title", "N/A"),
                            "severity": a.get("severity", "N/A"),
                            "timestamp": a.get("@timestamp", a.get("timestamp", now)),
                        }
                        for a in action["alerts"]
                    ]
                    case_doc = {
                        "@timestamp": now,
                        "case_id": action["case_id"],
                        "status": "open",
                        "severity": action["severity"].name,
                        "host": action["host"],
                        "alert_type": action["alert_type"],
                        "alert_count": action["alert_count"],
                        "alerts": alert_summaries,
                        "timeline": [{"event": "case_created", "timestamp": now}],
                        "assigned_to": "unassigned",
                        "created_by": self.name,
                    }
                    self.os_client.index_document(
                        index=_CASES_INDEX, document=case_doc, doc_id=action["case_id"],
                    )
                    self._recent_case_keys[action["dedup_key"]] = time.time()
                    created += 1
                    logger.info("Created case %s for host %s", action["case_id"], action["host"])

                elif action["type"] == "update_case":
                    new_summaries = [
                        {
                            "title": a.get("title", "N/A"),
                            "severity": a.get("severity", "N/A"),
                            "timestamp": a.get("@timestamp", a.get("timestamp", now)),
                        }
                        for a in action["new_alerts"]
                    ]
                    update_body = {
                        "script": {
                            "source": (
                                "ctx._source.alert_count += params.count; "
                                "ctx._source.alerts.addAll(params.alerts); "
                                "ctx._source.timeline.add(params.event);"
                            ),
                            "params": {
                                "count": len(action["new_alerts"]),
                                "alerts": new_summaries,
                                "event": {"event": "alerts_added", "timestamp": now,
                                          "count": len(action["new_alerts"])},
                            },
                        }
                    }
                    self.os_client.client.update(
                        index=_CASES_INDEX, id=action["case_id"], body=update_body,
                    )
                    updated += 1
                    logger.info("Updated case %s with %d new alerts", action["case_id"],
                                len(action["new_alerts"]))

            except Exception as exc:
                logger.error("Case action failed: %s", exc)

        self._prune_dedup_cache()

        if created or updated:
            self.report_to_supervisor({
                "type": "case_report",
                "cases_created": created,
                "cases_updated": updated,
            })

        return {"cases_created": created, "cases_updated": updated}

    # ── Helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _generate_case_id(host: str) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        host_hash = hashlib.md5(host.encode()).hexdigest()[:6]
        return f"CASE-{ts}-{host_hash}"

    @staticmethod
    def _make_dedup_key(host: str, alert_type: str) -> str:
        raw = f"{host}:{alert_type}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _is_duplicate(self, dedup_key: str) -> bool:
        ts = self._recent_case_keys.get(dedup_key)
        if ts is None:
            return False
        return (time.time() - ts) < _DEDUP_WINDOW_HOURS * 3600

    def _find_existing_case(self, host: str) -> Optional[str]:
        """Look for an open case for this host created within the grouping window."""
        try:
            body = {
                "query": {"bool": {"must": [
                    {"term": {"host.keyword": host}},
                    {"term": {"status.keyword": "open"}},
                    {"range": {"@timestamp": {"gte": f"now-{_GROUP_WINDOW_MINUTES}m"}}},
                ]}},
                "sort": [{"@timestamp": {"order": "desc"}}],
            }
            resp = self.os_client.search(index=_CASES_INDEX, body=body, size=1)
            hits = resp.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"]["case_id"]
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_severity(sev_str: str) -> Severity:
        try:
            return Severity[sev_str.upper()]
        except KeyError:
            return Severity.MEDIUM

    def _prune_dedup_cache(self) -> None:
        cutoff = time.time() - _DEDUP_WINDOW_HOURS * 3600 * 2
        self._recent_case_keys = {
            k: v for k, v in self._recent_case_keys.items() if v > cutoff
        }


# ── Entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = AutoCaseAgent()
    agent.run_loop()
