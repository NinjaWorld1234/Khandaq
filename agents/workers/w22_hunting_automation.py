"""
SOC Platform - Worker Agent W22: Threat Hunting Automation
وكيل أتمتة صيد التهديدات

Runs predefined hunt queries against OpenSearch on a schedule:
- Processes running from unusual paths
- Outbound connections to rare destinations (<3 times in 30 days)
- PowerShell with encoded commands (-enc, -encodedcommand)
- Scheduled tasks created recently
- Services installed recently
- DNS queries to newly registered domains

Each hunt has: name, query, severity, MITRE ATT&CK technique ID.
Results stored in soc-hunt-results index.
Interval: 600 seconds
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w22_hunting_automation")

# ── Hunt definitions ────────────────────────────────────────────────
HUNT_QUERIES: List[Dict[str, Any]] = [
    {
        "name": "Processes from Unusual Paths",
        "severity": Severity.HIGH,
        "mitre": "T1036.005",
        "index": "wazuh-alerts-*",
        "minutes": 60,
        "query": {"bool": {"must": [
            {"exists": {"field": "data.win.eventdata.image"}},
        ], "must_not": [
            {"wildcard": {"data.win.eventdata.image.keyword": "C:\\Windows\\*"}},
            {"wildcard": {"data.win.eventdata.image.keyword": "C:\\Program Files\\*"}},
            {"wildcard": {"data.win.eventdata.image.keyword": "C:\\Program Files (x86)\\*"}},
        ]}},
    },
    {
        "name": "Encoded PowerShell Commands",
        "severity": Severity.HIGH,
        "mitre": "T1059.001",
        "index": "wazuh-alerts-*",
        "minutes": 60,
        "query": {"bool": {"must": [
            {"wildcard": {"data.win.eventdata.image.keyword": "*powershell*"}},
        ], "should": [
            {"match_phrase": {"data.win.eventdata.commandLine": "-enc"}},
            {"match_phrase": {"data.win.eventdata.commandLine": "-encodedcommand"}},
            {"match_phrase": {"data.win.eventdata.commandLine": "-EncodedCommand"}},
        ], "minimum_should_match": 1}},
    },
    {
        "name": "Recently Created Scheduled Tasks",
        "severity": Severity.MEDIUM,
        "mitre": "T1053.005",
        "index": "wazuh-alerts-*",
        "minutes": 60,
        "query": {"bool": {"must": [
            {"match": {"data.win.system.eventID": "4698"}},
        ]}},
    },
    {
        "name": "Recently Installed Services",
        "severity": Severity.MEDIUM,
        "mitre": "T1543.003",
        "index": "wazuh-alerts-*",
        "minutes": 60,
        "query": {"bool": {"must": [
            {"match": {"data.win.system.eventID": "7045"}},
        ]}},
    },
    {
        "name": "DNS Queries to Newly Registered Domains",
        "severity": Severity.MEDIUM,
        "mitre": "T1583.001",
        "index": "zeek-*",
        "minutes": 60,
        "query": {"bool": {"must": [
            {"exists": {"field": "query"}},
        ], "should": [
            {"wildcard": {"query.keyword": "*.xyz"}},
            {"wildcard": {"query.keyword": "*.top"}},
            {"wildcard": {"query.keyword": "*.buzz"}},
            {"wildcard": {"query.keyword": "*.tk"}},
            {"wildcard": {"query.keyword": "*.ml"}},
            {"wildcard": {"query.keyword": "*.ga"}},
            {"wildcard": {"query.keyword": "*.cf"}},
        ], "minimum_should_match": 1}},
    },
]

# Rare-outbound hunt is done via aggregation, defined separately
RARE_OUTBOUND_HUNT = {
    "name": "Outbound Connections to Rare Destinations",
    "severity": Severity.HIGH,
    "mitre": "T1071.001",
    "index": "zeek-*",
    "threshold": 3,
}


class HuntingAutomationAgent(BaseAgent):
    """Proactive threat hunting agent that runs scheduled hunt queries."""

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w22_hunting_automation",
            description="Runs predefined threat hunting queries on a schedule",
            interval_seconds=600,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self._hunt_results_index = "soc-hunt-results"
        self._processed_ids: set[str] = set()
        self._max_cache = 10_000

    # ── Collect ─────────────────────────────────────────────────────
    def collect(self) -> Optional[Dict[str, Any]]:
        """Execute every hunt query and the rare-outbound aggregation."""
        try:
            raw_results: List[Dict[str, Any]] = []
            for hunt in HUNT_QUERIES:
                try:
                    events = self.os_client.get_events_since(
                        index=hunt["index"],
                        minutes=hunt["minutes"],
                        query=hunt["query"],
                        size=10000,
                    )
                    if events:
                        raw_results.append({**hunt, "hits": events})
                except Exception as e:
                    logger.warning("Error running hunt: %s", e)

            # Rare outbound: aggregate destination IPs seen < threshold times in 30 days
            rare = self._query_rare_outbound()
            if rare:
                raw_results.append({**RARE_OUTBOUND_HUNT, "hits": rare})

            return {"hunts": raw_results}
        except Exception as exc:
            logger.error("Hunting collect failed: %s", exc)
            return None

    def _query_rare_outbound(self) -> List[Dict[str, Any]]:
        """Find destination IPs contacted fewer than 3 times in 30 days."""
        aggs = {
            "dest_ips": {
                "terms": {"field": "id.resp_h.keyword", "size": 1000, "min_doc_count": 1},
            }
        }
        query = {"range": {"@timestamp": {"gte": "now-30d"}}}
        try:
            result = self.os_client.aggregate(
                index=RARE_OUTBOUND_HUNT["index"], aggs=aggs, query=query,
            )
            buckets = (result.get("dest_ips") or {}).get("buckets", [])
            threshold = RARE_OUTBOUND_HUNT["threshold"]
            return [
                {"dest_ip": b["key"], "count": b["doc_count"]}
                for b in buckets
                if b["doc_count"] < threshold and not b["key"].startswith(("10.", "192.168.", "172."))
            ]
        except Exception as exc:
            logger.error("Rare outbound aggregation failed: %s", exc)
            return []

    # ── Analyze ─────────────────────────────────────────────────────
    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert raw hunt hits into structured findings."""
        findings: List[Dict[str, Any]] = []
        for hunt_result in data.get("hunts", []):
            try:
                name = hunt_result["name"]
                hits = hunt_result["hits"]
                severity = hunt_result["severity"]
                mitre = hunt_result["mitre"]
                hit_count = len(hits)

                findings.append({
                    "hunt_name": name,
                    "severity": severity,
                    "mitre_technique": mitre,
                    "hit_count": hit_count,
                    "sample_hits": hits[:10],
                    "description": f"Hunt '{name}' returned {hit_count} result(s) [MITRE {mitre}]",
                })
            except Exception as e:
                logger.warning("Error analyzing hunt result: %s", e)

        self._events_processed += sum(f["hit_count"] for f in findings)
        if findings:
            logger.warning("Hunting cycle found %d active hunts with results", len(findings))
        return findings

    # ── Decide ──────────────────────────────────────────────────────
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate alert and index actions for each finding."""
        actions: List[Dict[str, Any]] = []
        for finding in findings:
            try:
                actions.append({"type": "store_result", "finding": finding})
                if finding["severity"] >= Severity.HIGH:
                    actions.append({
                        "type": "alert",
                        "severity": finding["severity"],
                        "title": f"Hunt Hit: {finding['hunt_name']}",
                        "details": {
                            "hunt_name": finding["hunt_name"],
                            "mitre": finding["mitre_technique"],
                            "hit_count": finding["hit_count"],
                            "description": finding["description"],
                        },
                    })
            except Exception as e:
                logger.warning("Error deciding action: %s", e)
        return actions

    # ── Act ──────────────────────────────────────────────────────────
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Store hunt results and send alerts."""
        stored = 0
        alerted = 0
        now = datetime.now(timezone.utc).isoformat()

        for action in actions:
            try:
                if action["type"] == "store_result":
                    finding = action["finding"]
                    try:
                        self.os_client.index_document(
                            index=self._hunt_results_index,
                            document={
                                "@timestamp": now,
                                "hunt_name": finding["hunt_name"],
                                "mitre_technique": finding["mitre_technique"],
                                "severity": finding["severity"].name,
                                "hit_count": finding["hit_count"],
                                "sample_hits": finding["sample_hits"],
                                "agent_name": self.name,
                            },
                        )
                        stored += 1
                    except Exception as exc:
                        logger.error("Failed to store hunt result: %s", exc)

                elif action["type"] == "alert":
                    sent = self.alerter.send_alert(
                        severity=action["severity"],
                        title=action["title"],
                        details=action["details"],
                        agent_name=self.name,
                    )
                    if sent:
                        alerted += 1
                        severity_name = action["severity"].name if hasattr(action["severity"], "name") else str(action["severity"])
                        self._metrics.inc_alerts(severity_name)
                        # Forward to supervisor for escalation
                        self.report_to_supervisor({
                            "type": "hunt_hit_alert",
                            "severity": severity_name,
                            "details": action["details"]
                        })
            except Exception as e:
                logger.warning("Error acting on action: %s", e)

        if stored or alerted:
            self.report_to_supervisor({
                "type": "hunting_report",
                "results_stored": stored,
                "alerts_sent": alerted,
            })

        return {"results_stored": stored, "alerts_sent": alerted}


# ── Entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = HuntingAutomationAgent()
    agent.run_loop()
