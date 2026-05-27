"""
SOC Platform - Worker Agent W24: Forensics Evidence Gatherer
وكيل جمع الأدلة الجنائية

When a CRITICAL alert fires, automatically gathers forensic data:
- Process tree (parent-child chain)
- Network connections timeline
- File modifications
- User login history
- DNS queries from the affected host

Packages all evidence into a forensics report stored in soc-forensics index.
Each report has: case_id link, host, timeline, evidence items, chain of custody.
Interval: 120 seconds
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w24_forensics_gather")

_FORENSICS_INDEX = "soc-forensics"
_ALERTS_INDEX = "soc-alerts-*"
_WAZUH_INDEX = "wazuh-alerts-*"
_ZEEK_INDEX = "zeek-*"
_EVIDENCE_WINDOW_HOURS = 24


class ForensicsGatherAgent(BaseAgent):
    """Automatically gathers forensic evidence when CRITICAL alerts fire."""

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w24_forensics_gather",
            description="Gathers forensic evidence for CRITICAL alerts automatically",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self._processed_alert_ids: Set[str] = set()
        self._max_cache = 5_000

    # ── Collect ─────────────────────────────────────────────────────
    def collect(self) -> Optional[Dict[str, Any]]:
        """Fetch CRITICAL alerts from the last 5 minutes."""
        try:
            query = {"match": {"severity": "CRITICAL"}}
            alerts = self.os_client.get_events_since(
                index=_ALERTS_INDEX, minutes=5, query=query, size=10000,
            )
            # Deduplicate against already-processed alerts
            new_alerts = []
            for alert in alerts:
                try:
                    alert_id = alert.get("_id", hashlib.sha256(
                        str(alert.get("@timestamp", "") + alert.get("title", "")).encode()
                    ).hexdigest()[:12])
                    if alert_id not in self._processed_alert_ids:
                        alert["_dedup_id"] = alert_id
                        new_alerts.append(alert)
                except Exception as e:
                    logger.warning("Error processing alert deduplication: %s", e)
            return {"critical_alerts": new_alerts}
        except Exception as exc:
            logger.error("Forensics collect failed: %s", exc)
            return None

    # ── Analyze ─────────────────────────────────────────────────────
    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """For each CRITICAL alert, gather all evidence from the affected host."""
        findings: List[Dict[str, Any]] = []
        alerts = data.get("critical_alerts", [])
        if not alerts:
            return findings

        for alert in alerts:
            try:
                host = (
                    (alert.get("agent") or {}).get("name")
                    or (alert.get("details") or {}).get("host")
                    or alert.get("host", "unknown")
                )
                case_id = alert.get("case_id", "UNLINKED")
                window_min = _EVIDENCE_WINDOW_HOURS * 60

                evidence: Dict[str, Any] = {
                    "process_tree": self._gather_process_tree(host, window_min),
                    "network_connections": self._gather_network_connections(host, window_min),
                    "file_modifications": self._gather_file_modifications(host, window_min),
                    "login_history": self._gather_login_history(host, window_min),
                    "dns_queries": self._gather_dns_queries(host, window_min),
                }

                total_items = sum(len(v) for v in evidence.values() if isinstance(v, list))
                self._events_processed += total_items
                self._metrics.inc_events(total_items)

                findings.append({
                    "host": host,
                    "case_id": case_id,
                    "alert": alert,
                    "evidence": evidence,
                    "evidence_count": total_items,
                })
            except Exception as e:
                logger.warning("Error gathering evidence for alert: %s", e)

        if findings:
            logger.info("Gathered forensic evidence for %d hosts", len(findings))
        return findings

    def _gather_process_tree(self, host: str, window_min: int) -> List[Dict[str, Any]]:
        """Collect Sysmon process creation events (Event ID 1) for parent-child chain."""
        try:
            query = {"bool": {"must": [
                {"match": {"agent.name": host}},
                {"match": {"data.win.system.eventID": "1"}},
            ]}}
            events = self.os_client.get_events_since(
                index=_WAZUH_INDEX, minutes=window_min, query=query, size=10000,
            )
            results = []
            for e in events:
                ed = ((e.get("data") or {}).get("win") or {}).get("eventdata") or {}
                results.append({
                    "timestamp": e.get("@timestamp"),
                    "image": ed.get("image"),
                    "parent_image": ed.get("parentImage"),
                    "command_line": ed.get("commandLine"),
                    "pid": ed.get("processId"),
                    "ppid": ed.get("parentProcessId"),
                    "user": ed.get("user"),
                })
            return results
        except Exception as exc:
            logger.error("Process tree gather failed for %s: %s", host, exc)
            return []

    def _gather_network_connections(self, host: str, window_min: int) -> List[Dict[str, Any]]:
        """Collect Sysmon network events (Event ID 3) and Zeek conn logs."""
        results: List[Dict[str, Any]] = []
        try:
            query = {"bool": {"must": [
                {"match": {"agent.name": host}},
                {"match": {"data.win.system.eventID": "3"}},
            ]}}
            events = self.os_client.get_events_since(
                index=_WAZUH_INDEX, minutes=window_min, query=query, size=10000,
            )
            for e in events:
                ed = ((e.get("data") or {}).get("win") or {}).get("eventdata") or {}
                results.append({
                    "timestamp": e.get("@timestamp"),
                    "source": "sysmon",
                    "src_ip": ed.get("sourceIp"),
                    "src_port": ed.get("sourcePort"),
                    "dst_ip": ed.get("destinationIp"),
                    "dst_port": ed.get("destinationPort"),
                    "image": ed.get("image"),
                })
        except Exception as exc:
            logger.error("Network conn gather (Sysmon) failed for %s: %s", host, exc)

        try:
            zeek_query = {"bool": {"should": [
                {"match": {"id.orig_h": host}},
                {"match": {"host.keyword": host}},
            ], "minimum_should_match": 1}}
            zeek_events = self.os_client.get_events_since(
                index=_ZEEK_INDEX, minutes=window_min, query=zeek_query, size=10000,
            )
            for e in zeek_events:
                results.append({
                    "timestamp": e.get("@timestamp", e.get("ts")),
                    "source": "zeek",
                    "src_ip": e.get("id.orig_h"),
                    "src_port": e.get("id.orig_p"),
                    "dst_ip": e.get("id.resp_h"),
                    "dst_port": e.get("id.resp_p"),
                    "proto": e.get("proto"),
                })
        except Exception as exc:
            logger.error("Network conn gather (Zeek) failed for %s: %s", host, exc)
        return results

    def _gather_file_modifications(self, host: str, window_min: int) -> List[Dict[str, Any]]:
        """Collect Sysmon file creation events (Event ID 11)."""
        try:
            query = {"bool": {"must": [
                {"match": {"agent.name": host}},
                {"match": {"data.win.system.eventID": "11"}},
            ]}}
            events = self.os_client.get_events_since(
                index=_WAZUH_INDEX, minutes=window_min, query=query, size=10000,
            )
            results = []
            for e in events:
                ed = ((e.get("data") or {}).get("win") or {}).get("eventdata") or {}
                results.append({
                    "timestamp": e.get("@timestamp"),
                    "target_filename": ed.get("targetFilename"),
                    "image": ed.get("image"),
                })
            return results
        except Exception as exc:
            logger.error("File modification gather failed for %s: %s", host, exc)
            return []

    def _gather_login_history(self, host: str, window_min: int) -> List[Dict[str, Any]]:
        """Collect Windows logon events (4624 success, 4625 failure)."""
        try:
            query = {"bool": {"must": [
                {"match": {"agent.name": host}},
            ], "should": [
                {"match": {"data.win.system.eventID": "4624"}},
                {"match": {"data.win.system.eventID": "4625"}},
            ], "minimum_should_match": 1}}
            events = self.os_client.get_events_since(
                index=_WAZUH_INDEX, minutes=window_min, query=query, size=10000,
            )
            results = []
            for e in events:
                sys = ((e.get("data") or {}).get("win") or {}).get("system") or {}
                ed = ((e.get("data") or {}).get("win") or {}).get("eventdata") or {}
                results.append({
                    "timestamp": e.get("@timestamp"),
                    "event_id": sys.get("eventID"),
                    "user": (e.get("data") or {}).get("dstuser"),
                    "src_ip": (e.get("data") or {}).get("srcip"),
                    "logon_type": ed.get("logonType"),
                })
            return results
        except Exception as exc:
            logger.error("Login history gather failed for %s: %s", host, exc)
            return []

    def _gather_dns_queries(self, host: str, window_min: int) -> List[Dict[str, Any]]:
        """Collect Sysmon DNS events (Event ID 22) and Zeek DNS logs."""
        results: List[Dict[str, Any]] = []
        try:
            query = {"bool": {"must": [
                {"match": {"agent.name": host}},
                {"match": {"data.win.system.eventID": "22"}},
            ]}}
            events = self.os_client.get_events_since(
                index=_WAZUH_INDEX, minutes=window_min, query=query, size=10000,
            )
            for e in events:
                ed = ((e.get("data") or {}).get("win") or {}).get("eventdata") or {}
                results.append({
                    "timestamp": e.get("@timestamp"),
                    "source": "sysmon",
                    "query_name": ed.get("queryName"),
                    "query_result": ed.get("queryResults"),
                })
        except Exception as exc:
            logger.error("DNS gather (Sysmon) failed for %s: %s", host, exc)
        return results

    # ── Decide ──────────────────────────────────────────────────────
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create store-report actions for each forensics package."""
        return [{"type": "store_report", "finding": f} for f in findings]

    # ── Act ──────────────────────────────────────────────────────────
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Store forensics reports in OpenSearch and notify supervisor."""
        stored = 0
        now = datetime.now(timezone.utc).isoformat()

        for action in actions:
            try:
                finding = action["finding"]
                report_id = hashlib.sha256(
                    f"{finding['host']}:{now}".encode()
                ).hexdigest()[:16]

                report = {
                    "@timestamp": now,
                    "report_id": report_id,
                    "case_id": finding["case_id"],
                    "host": finding["host"],
                    "evidence_count": finding["evidence_count"],
                    "evidence": finding["evidence"],
                    "chain_of_custody": {
                        "collected_by": self.name,
                        "collected_at": now,
                        "method": "automated_opensearch_query",
                        "integrity_hash": hashlib.sha256(
                            str(finding["evidence"]).encode()
                        ).hexdigest(),
                    },
                    "trigger_alert": {
                        "title": finding["alert"].get("title", "N/A"),
                        "severity": finding["alert"].get("severity", "CRITICAL"),
                        "timestamp": finding["alert"].get("@timestamp", now),
                    },
                }
                try:
                    self.os_client.index_document(
                        index=_FORENSICS_INDEX, document=report, doc_id=report_id,
                    )
                    stored += 1
                    dedup_id = finding["alert"].get("_dedup_id")
                    if dedup_id:
                        self._processed_alert_ids.add(dedup_id)
                    logger.info("Stored forensics report %s for host %s (%d items)",
                                report_id, finding["host"], finding["evidence_count"])
                except Exception as exc:
                    logger.error("Failed to store forensics report: %s", exc)
            except Exception as e:
                logger.warning("Error acting on action: %s", e)

        # Prune cache
        if len(self._processed_alert_ids) > self._max_cache:
            excess = len(self._processed_alert_ids) - self._max_cache // 2
            for _ in range(excess):
                self._processed_alert_ids.pop()

        if stored:
            self.report_to_supervisor({
                "type": "forensics_report",
                "reports_stored": stored,
            })

        return {"reports_stored": stored}


# ── Entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = ForensicsGatherAgent()
    agent.run_loop()
