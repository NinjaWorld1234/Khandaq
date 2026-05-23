"""
SOC Platform - Worker Agent W20: IOC Lifecycle / Aging Manager
وكيل إدارة دورة حياة مؤشرات الاختراق

Manages the full lifecycle of Indicators of Compromise (IOCs) stored in the
soc-iocs index.  Responsibilities:
  - Age out stale IOCs: >90 days with no hits → mark expired
  - Track hit rates per IOC and compute decay scores
  - Re-prioritize: IOCs with recent hits get extended TTL
  - Cleanup: remove expired IOCs from active blocklists
  - Report statistics to the detection supervisor

Interval: 3600 seconds (hourly)
Supervisor channel: soc:detection-supervisor
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w20_ioc_aging")

# ---------------------------------------------------------------------------
# Aging policy constants
# ---------------------------------------------------------------------------

IOC_MAX_AGE_DAYS = 90           # Days with zero hits before expiry
IOC_EXTENSION_DAYS = 30         # TTL extension when an IOC gets recent hits
IOC_RECENT_HIT_WINDOW_DAYS = 14 # "Recent" means a hit within this window
BATCH_SIZE = 500                # OpenSearch scroll batch size
BLOCKLIST_INDEX = "soc-blocklist"
IOC_INDEX = "soc-iocs"

# Decay tiers – used to re-score IOCs based on last-hit recency
DECAY_TIERS: list[dict[str, Any]] = [
    {"max_days": 7,  "score": 1.0,  "label": "hot"},
    {"max_days": 30, "score": 0.7,  "label": "warm"},
    {"max_days": 60, "score": 0.4,  "label": "cool"},
    {"max_days": 90, "score": 0.1,  "label": "cold"},
]


class IOCAgingAgent(BaseAgent):
    """
    IOC Lifecycle / Aging Manager (W20).
    Periodically reviews IOCs, decays stale ones, extends active ones,
    and cleans up expired entries from active blocklists.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w20_ioc_aging",
            description="Manages IOC lifecycle, decaying stale indicators and extending active ones",
            interval_seconds=3600,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self._ioc_index: str = self._agent_config.get("ioc_index", IOC_INDEX)
        self._blocklist_index: str = self._agent_config.get("blocklist_index", BLOCKLIST_INDEX)
        self._max_age_days: int = self._agent_config.get("max_age_days", IOC_MAX_AGE_DAYS)
        # Cumulative stats across cycles
        self._total_expired: int = 0
        self._total_extended: int = 0
        self._total_cleaned: int = 0

    # ------------------------------------------------------------------
    # Collect: fetch all active IOCs from the soc-iocs index
    # ------------------------------------------------------------------

    def collect(self) -> Optional[List[Dict[str, Any]]]:
        """Retrieve all IOCs marked as status=active from OpenSearch."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "must": [
                        {"term": {"status": "active"}},
                    ],
                }
            }
            iocs = self.os_client.get_events_since(
                index=self._ioc_index,
                minutes=0,  # no time filter – we want all active IOCs
                query=query,
                size=BATCH_SIZE,
            )
            logger.info("Collected %d active IOCs for aging review", len(iocs))
            return iocs if iocs else None
        except Exception as exc:
            logger.error("Failed to collect active IOCs: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze: classify each IOC into aging buckets
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate each IOC against aging policy and compute decay scores."""
        now = datetime.now(timezone.utc)
        findings: list[dict[str, Any]] = []

        for ioc in data:
            ioc_id = ioc.get("_id", ioc.get("id", "unknown"))
            ioc_value = ioc.get("value", "N/A")
            ioc_type = ioc.get("type", "unknown")
            created_str = ioc.get("created_at", ioc.get("@timestamp", ""))
            last_hit_str = ioc.get("last_hit", "")
            hit_count = ioc.get("hit_count", 0)
            current_ttl_str = ioc.get("expires_at", "")

            # Parse dates
            created_at = self._parse_iso(created_str)
            last_hit = self._parse_iso(last_hit_str) if last_hit_str else None
            expires_at = self._parse_iso(current_ttl_str) if current_ttl_str else None

            if created_at is None:
                logger.warning("IOC %s has no valid created_at, skipping", ioc_id)
                continue

            age_days = (now - created_at).days
            days_since_hit = (now - last_hit).days if last_hit else age_days

            # Compute decay score
            decay_score = 0.0
            decay_label = "expired"
            for tier in DECAY_TIERS:
                if days_since_hit <= tier["max_days"]:
                    decay_score = tier["score"]
                    decay_label = tier["label"]
                    break

            # Determine action
            action = "none"
            if days_since_hit <= IOC_RECENT_HIT_WINDOW_DAYS and hit_count > 0:
                action = "extend"
            elif days_since_hit >= self._max_age_days:
                action = "expire"
            elif expires_at and now >= expires_at:
                action = "expire"

            findings.append({
                "ioc_id": ioc_id,
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "age_days": age_days,
                "days_since_hit": days_since_hit,
                "hit_count": hit_count,
                "decay_score": decay_score,
                "decay_label": decay_label,
                "action": action,
                "created_at": created_str,
                "last_hit": last_hit_str,
            })

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))

        # Log summary
        action_counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            action_counts[f["action"]] += 1
        logger.info(
            "IOC aging analysis: %d total — extend=%d, expire=%d, none=%d",
            len(findings),
            action_counts.get("extend", 0),
            action_counts.get("expire", 0),
            action_counts.get("none", 0),
        )
        return findings

    # ------------------------------------------------------------------
    # Decide: build update / cleanup actions
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create concrete update actions for each IOC based on analysis."""
        actions: list[dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for finding in findings:
            if finding["action"] == "expire":
                # Mark the IOC as expired in the index
                actions.append({
                    "type": "mark_expired",
                    "ioc_id": finding["ioc_id"],
                    "ioc_value": finding["ioc_value"],
                    "ioc_type": finding["ioc_type"],
                    "reason": (
                        f"No hits for {finding['days_since_hit']} days "
                        f"(threshold: {self._max_age_days}d)"
                    ),
                    "decay_score": finding["decay_score"],
                    "timestamp": now_iso,
                })
                # Also remove from active blocklist
                actions.append({
                    "type": "remove_blocklist",
                    "ioc_id": finding["ioc_id"],
                    "ioc_value": finding["ioc_value"],
                    "ioc_type": finding["ioc_type"],
                })

            elif finding["action"] == "extend":
                new_expiry = (
                    datetime.now(timezone.utc)
                    + timedelta(days=IOC_EXTENSION_DAYS)
                ).isoformat()
                actions.append({
                    "type": "extend_ttl",
                    "ioc_id": finding["ioc_id"],
                    "ioc_value": finding["ioc_value"],
                    "ioc_type": finding["ioc_type"],
                    "new_expires_at": new_expiry,
                    "decay_score": finding["decay_score"],
                    "hit_count": finding["hit_count"],
                    "timestamp": now_iso,
                })

            # Always update the decay score in-place
            if finding["action"] != "none":
                actions.append({
                    "type": "update_decay",
                    "ioc_id": finding["ioc_id"],
                    "decay_score": finding["decay_score"],
                    "decay_label": finding["decay_label"],
                    "timestamp": now_iso,
                })

        return actions

    # ------------------------------------------------------------------
    # Act: execute updates, cleanup, and report
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute all aging actions against OpenSearch."""
        expired_count = 0
        extended_count = 0
        cleaned_count = 0
        decay_updated = 0
        errors = 0

        for action in actions:
            try:
                if action["type"] == "mark_expired":
                    self.os_client.index_document(
                        self._ioc_index,
                        document={
                            "ioc_id": action["ioc_id"],
                            "status": "expired",
                            "expired_at": action["timestamp"],
                            "expiry_reason": action["reason"],
                            "decay_score": action["decay_score"],
                        },
                        doc_id=action["ioc_id"],
                    )
                    expired_count += 1

                elif action["type"] == "remove_blocklist":
                    self.os_client.index_document(
                        self._blocklist_index,
                        document={
                            "ioc_value": action["ioc_value"],
                            "ioc_type": action["ioc_type"],
                            "removed": True,
                            "removed_at": datetime.now(timezone.utc).isoformat(),
                            "reason": "IOC expired via aging policy",
                        },
                        doc_id=f"bl-{action['ioc_id']}",
                    )
                    cleaned_count += 1

                elif action["type"] == "extend_ttl":
                    self.os_client.index_document(
                        self._ioc_index,
                        document={
                            "ioc_id": action["ioc_id"],
                            "expires_at": action["new_expires_at"],
                            "decay_score": action["decay_score"],
                            "ttl_extended_at": action["timestamp"],
                            "status": "active",
                        },
                        doc_id=action["ioc_id"],
                    )
                    extended_count += 1

                elif action["type"] == "update_decay":
                    self.os_client.index_document(
                        self._ioc_index,
                        document={
                            "ioc_id": action["ioc_id"],
                            "decay_score": action["decay_score"],
                            "decay_label": action["decay_label"],
                            "decay_updated_at": action["timestamp"],
                        },
                        doc_id=action["ioc_id"],
                    )
                    decay_updated += 1

            except Exception as exc:
                errors += 1
                logger.error("Failed to execute action %s for IOC %s: %s",
                             action["type"], action.get("ioc_id"), exc)

        # Update cumulative counters
        self._total_expired += expired_count
        self._total_extended += extended_count
        self._total_cleaned += cleaned_count

        # Log audit record
        summary = {
            "expired": expired_count,
            "extended": extended_count,
            "blocklist_cleaned": cleaned_count,
            "decay_updated": decay_updated,
            "errors": errors,
        }
        logger.info("IOC aging cycle complete: %s", summary)

        # Store audit trail
        try:
            self.os_client.index_document("soc-ioc-aging-log", document={
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_name": self.name,
                **summary,
                "cumulative_expired": self._total_expired,
                "cumulative_extended": self._total_extended,
                "cumulative_cleaned": self._total_cleaned,
            })
        except Exception as exc:
            logger.error("Failed to write aging audit log: %s", exc)

        # Alert if large expiry batch (could indicate stale threat-intel feed)
        if expired_count >= 50:
            self.alerter.send_alert(
                severity=Severity.MEDIUM,
                title="Large IOC Expiry Batch Detected",
                details={
                    "expired_count": expired_count,
                    "message": (
                        f"{expired_count} IOCs expired in a single cycle — "
                        "verify threat-intel feed freshness"
                    ),
                },
                agent_name=self.name,
            )
            self._metrics.inc_alerts(Severity.MEDIUM.name)

        # Report to supervisor
        if expired_count or extended_count or cleaned_count:
            self.report_to_supervisor({
                "type": "ioc_aging_report",
                **summary,
                "cumulative_expired": self._total_expired,
                "cumulative_extended": self._total_extended,
                "cumulative_cleaned": self._total_cleaned,
            })

        return summary

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_iso(date_str: str) -> Optional[datetime]:
        """Safely parse an ISO-8601 date string."""
        if not date_str:
            return None
        try:
            # Handle both 'Z' suffix and '+00:00'
            cleaned = date_str.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
        except (ValueError, TypeError):
            return None


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
    agent = IOCAgingAgent()
    agent.run_loop()
