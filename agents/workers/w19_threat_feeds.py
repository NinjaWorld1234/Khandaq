"""
SOC Platform - Worker Agent W19: Threat Feed Automation
وكيل أتمتة تغذية التهديدات

Queries MISP-compatible threat feed data from OpenSearch (misp-iocs-*)
for new IOCs added in the last cycle. Categorizes IOCs as IP, domain,
file hash (MD5/SHA1/SHA256), or URL. Stores each IOC in soc-iocs with
metadata (source, confidence, TLP, tags). Tracks distribution status
and generates summary statistics.

Interval: 300 seconds
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w19_threat_feeds")

# IOC type detection patterns
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def classify_ioc(value: str) -> str:
    """Classify an IOC value into its type category."""
    value = value.strip()
    if _IPV4_RE.match(value):
        return "ip"
    if _URL_RE.match(value):
        return "url"
    if _SHA256_RE.match(value):
        return "sha256"
    if _SHA1_RE.match(value):
        return "sha1"
    if _MD5_RE.match(value):
        return "md5"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


class ThreatFeedAgent(BaseAgent):
    """
    Threat Feed Automation Agent (W19).
    Ingests MISP IOCs from OpenSearch, normalises, deduplicates, stores
    them in soc-iocs, and tracks distribution to blocklists.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w19_threat_feeds",
            description="Automates MISP feed ingestion, IOC categorisation and distribution",
            interval_seconds=300,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self._misp_index = self._agent_config.get("misp_index", "misp-iocs-*")
        self._ioc_index = self._agent_config.get("ioc_index", "soc-iocs")
        self._scan_window_min: int = self._agent_config.get("scan_window_min", 6)
        self._known_ioc_hashes: set[str] = set()  # dedup cache (hash of value)
        self._stats: dict[str, int] = {"ip": 0, "domain": 0, "hash": 0, "url": 0, "unknown": 0}

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[list[dict[str, Any]]]:
        """Query MISP IOC feed index for recently ingested indicators."""
        try:
            query = {"bool": {"must": [
                {"range": {"@timestamp": {"gte": f"now-{self._scan_window_min}m"}}},
            ]}}
            events = self.os_client.get_events_since(
                index=self._misp_index,
                minutes=self._scan_window_min,
                query=query,
                size=1000,
            )
            logger.info("Collected %d new MISP IOC events", len(events))
            return events
        except Exception as exc:
            logger.error("Failed to collect MISP feed data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse, classify, and deduplicate IOCs from MISP events."""
        findings: list[dict[str, Any]] = []
        cycle_stats: dict[str, int] = {"ip": 0, "domain": 0, "hash": 0, "url": 0, "unknown": 0}

        for event in data:
            # MISP attribute fields
            ioc_value = event.get("value", event.get("Attribute", {}).get("value", ""))
            if not ioc_value:
                continue

            # Deduplicate within memory
            ioc_hash = hashlib.sha256(ioc_value.encode()).hexdigest()[:16]
            if ioc_hash in self._known_ioc_hashes:
                continue
            self._known_ioc_hashes.add(ioc_hash)

            ioc_type = classify_ioc(ioc_value)
            confidence = event.get("confidence", event.get("Tag", {}).get("confidence", 50))
            try:
                confidence = int(confidence)
            except (ValueError, TypeError):
                confidence = 50

            tlp = event.get("tlp", event.get("Tag", {}).get("tlp", "amber"))
            source = event.get("source", event.get("Event", {}).get("Orgc", {}).get("name", "misp-feed"))
            tags = event.get("tags", event.get("Tag", {}).get("name", ""))
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]

            stat_key = ioc_type if ioc_type in ("ip", "domain", "url") else (
                "hash" if ioc_type in ("md5", "sha1", "sha256") else "unknown"
            )
            cycle_stats[stat_key] += 1

            findings.append({
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "confidence": confidence,
                "tlp": tlp,
                "source": source,
                "tags": tags,
                "ioc_hash": ioc_hash,
                "original_event_id": event.get("_id", ""),
            })

        # Accumulate lifetime stats
        for k, v in cycle_stats.items():
            self._stats[k] += v

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        logger.info("Analyzed IOCs this cycle: %s", cycle_stats)
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Create store and distribute actions for each new IOC."""
        actions: list[dict[str, Any]] = []
        for finding in findings:
            actions.append({"type": "store_ioc", "ioc": finding})
            # High-confidence IOCs should be distributed to blocklists
            if finding["confidence"] >= 70 and finding["ioc_type"] in ("ip", "domain", "url"):
                actions.append({"type": "distribute_ioc", "ioc": finding})
        # Summary report action
        if findings:
            actions.append({"type": "report_summary", "count": len(findings)})
        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """Store IOCs in OpenSearch, mark distribution, report stats."""
        stored = 0
        distributed = 0

        for action in actions:
            if action["type"] == "store_ioc":
                try:
                    ioc = action["ioc"]
                    self.os_client.index_document(self._ioc_index, document={
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "ioc_value": ioc["ioc_value"],
                        "ioc_type": ioc["ioc_type"],
                        "confidence": ioc["confidence"],
                        "tlp": ioc["tlp"],
                        "source": ioc["source"],
                        "tags": ioc["tags"],
                        "status": "active",
                        "enriched": False,
                        "distributed": False,
                        "hit_count": 0,
                        "last_seen": None,
                        "created_by": self.name,
                    })
                    stored += 1
                except Exception as exc:
                    logger.error("Failed to store IOC %s: %s",
                                 action["ioc"].get("ioc_value", "?"), exc)

            elif action["type"] == "distribute_ioc":
                try:
                    ioc = action["ioc"]
                    # Publish IOC to Redis for downstream blocklist agents
                    self.redis_bus.publish("soc:ioc-blocklist", {
                        "ioc_value": ioc["ioc_value"],
                        "ioc_type": ioc["ioc_type"],
                        "action": "block",
                        "source": ioc["source"],
                    })
                    distributed += 1
                except Exception as exc:
                    logger.error("Failed to distribute IOC: %s", exc)

            elif action["type"] == "report_summary":
                self.report_to_supervisor({
                    "type": "threat_feed_report",
                    "new_iocs": action["count"],
                    "stored": stored,
                    "distributed": distributed,
                    "lifetime_stats": dict(self._stats),
                })

        # Prune dedup cache if too large (keep last ~5000)
        if len(self._known_ioc_hashes) > 10000:
            excess = len(self._known_ioc_hashes) - 5000
            for _ in range(excess):
                self._known_ioc_hashes.pop()

        logger.info("Threat feed cycle: stored=%d, distributed=%d", stored, distributed)
        return {"iocs_stored": stored, "iocs_distributed": distributed}


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
    agent = ThreatFeedAgent()
    agent.run_loop()
