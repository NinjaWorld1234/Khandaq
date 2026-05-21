"""
SOC Platform - Worker Agent W37: Smart Brute Force Detection
وكيل كشف هجمات القوة العمياء الذكي

Detects multiple brute-force patterns from Windows Event ID 4625 (logon failure):
- Fast Brute Force:    >10 failures from same IP in 5 min
- Slow/Low-and-Slow:   >20 failures from same IP in 24 hours
- Distributed Attack:  >5 unique IPs targeting same account in 1 hour
- Password Spray:      Same password tried on >10 accounts in 1 hour

Actions: alert + optionally block IP via Wazuh active response.
Maintains state in OpenSearch (per-IP counters).

Interval: 60 seconds
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.wazuh_client import WazuhClient

logger = logging.getLogger("soc.agent.w37_brute_force")

# Windows Event ID for logon failure
_EVENT_ID_LOGON_FAILURE = "4625"


class BruteForceAgent(BaseAgent):
    """
    Smart Brute Force Detection Agent (W37).
    وكيل كشف هجمات القوة العمياء الذكي

    Queries OpenSearch for Windows logon failure events (Event ID 4625)
    and detects four attack patterns: fast brute force, slow brute force,
    distributed attack, and password spray.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w37_brute_force",
            description="Smart Brute Force Detection - detects fast, slow, distributed, and spray attacks",
            interval_seconds=60,
            config=config,
        )

        # Thresholds from config
        t = self.config.thresholds
        self._fast_threshold: int = t.brute_force_fast_threshold          # 10
        self._fast_window_min: int = t.brute_force_fast_window_min        # 5
        self._slow_threshold: int = t.brute_force_slow_threshold          # 20
        self._slow_window_hours: int = t.brute_force_slow_window_hours    # 24
        self._distributed_ips: int = t.brute_force_distributed_ips        # 5
        self._distributed_window_min: int = t.brute_force_distributed_window_min  # 60
        self._spray_accounts: int = t.brute_force_spray_accounts          # 10
        self._spray_window_min: int = t.brute_force_spray_window_min      # 60

        # Agent-specific config
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")
        self._auto_block = self._agent_config.get("auto_block", False)
        self._block_duration_min = self._agent_config.get("block_duration_min", 60)

        # Field mappings (Wazuh alert schema)
        self._src_ip_field = self._agent_config.get("src_ip_field", "data.srcip")
        self._target_user_field = self._agent_config.get(
            "target_user_field", "data.dstuser"
        )
        self._event_id_field = self._agent_config.get(
            "event_id_field", "data.id"
        )

        # IP whitelist (internal scanners, known safe sources)
        self._ip_whitelist: set[str] = set(
            self._agent_config.get("ip_whitelist", [])
        )

        # Wazuh client for active response
        self._wazuh: Optional[WazuhClient] = None

        # State: track already-alerted combinations to reduce noise
        self._alerted_cache: dict[str, float] = {}
        self._alert_cooldown = 600  # Don't re-alert same pattern for 10 min

    @property
    def wazuh(self) -> WazuhClient:
        """Lazy-initialize Wazuh client."""
        if self._wazuh is None:
            self._wazuh = WazuhClient(self.config)
        return self._wazuh

    # ------------------------------------------------------------------
    # Collect: query logon failure events / جمع: استعلام أحداث فشل الدخول
    # ------------------------------------------------------------------

    def collect(self) -> Optional[dict[str, Any]]:
        """
        Collect Windows logon failure events from multiple time windows.

        Returns:
            Dict with events from each time window, or None on failure.
        """
        try:
            # Fast window (5 min)
            fast_events = self._query_logon_failures(self._fast_window_min)

            # Slow window (24 hours) — use aggregation to avoid pulling too many docs
            slow_agg = self._query_logon_failures_aggregated(
                self._slow_window_hours * 60
            )

            # Distributed window (1 hour)
            distributed_agg = self._query_distributed_aggregated(
                self._distributed_window_min
            )

            # Password spray window (1 hour)
            spray_agg = self._query_spray_aggregated(self._spray_window_min)

            return {
                "fast_events": fast_events,
                "slow_agg": slow_agg,
                "distributed_agg": distributed_agg,
                "spray_agg": spray_agg,
            }
        except Exception as exc:
            logger.error("Failed to collect brute force data: %s", exc)
            return None

    def _build_logon_failure_query(self) -> dict[str, Any]:
        """Build the base query for Windows logon failure events."""
        return {
            "bool": {
                "must": [
                    {"match": {self._event_id_field: _EVENT_ID_LOGON_FAILURE}},
                ],
            }
        }

    def _query_logon_failures(self, window_minutes: int) -> list[dict[str, Any]]:
        """Query raw logon failure events for the given time window."""
        return self.os_client.get_events_since(
            index=self._alert_index,
            minutes=window_minutes,
            query=self._build_logon_failure_query(),
            size=5000,
        )

    def _query_logon_failures_aggregated(
        self, window_minutes: int
    ) -> dict[str, int]:
        """
        Aggregate logon failures by source IP over the given window.
        Returns dict of IP -> failure_count.
        """
        src_field_kw = (
            f"{self._src_ip_field}.keyword"
            if not self._src_ip_field.endswith(".keyword")
            else self._src_ip_field
        )

        aggs = {
            "by_source_ip": {
                "terms": {"field": src_field_kw, "size": 500},
            },
        }

        query = {
            "bool": {
                "must": [
                    {"match": {self._event_id_field: _EVENT_ID_LOGON_FAILURE}},
                    {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                ],
            }
        }

        result = self.os_client.aggregate(
            index=self._alert_index, aggs=aggs, query=query
        )
        buckets = result.get("by_source_ip", {}).get("buckets", [])
        return {b["key"]: b["doc_count"] for b in buckets}

    def _query_distributed_aggregated(
        self, window_minutes: int
    ) -> dict[str, list[str]]:
        """
        Aggregate: for each target account, list the unique source IPs.
        Returns dict of account -> [ip1, ip2, ...].
        """
        user_field_kw = (
            f"{self._target_user_field}.keyword"
            if not self._target_user_field.endswith(".keyword")
            else self._target_user_field
        )
        src_field_kw = (
            f"{self._src_ip_field}.keyword"
            if not self._src_ip_field.endswith(".keyword")
            else self._src_ip_field
        )

        aggs = {
            "by_target_user": {
                "terms": {"field": user_field_kw, "size": 200},
                "aggs": {
                    "unique_sources": {
                        "terms": {"field": src_field_kw, "size": 100},
                    },
                },
            },
        }

        query = {
            "bool": {
                "must": [
                    {"match": {self._event_id_field: _EVENT_ID_LOGON_FAILURE}},
                    {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                ],
            }
        }

        result = self.os_client.aggregate(
            index=self._alert_index, aggs=aggs, query=query
        )
        user_buckets = result.get("by_target_user", {}).get("buckets", [])
        output: dict[str, list[str]] = {}
        for ub in user_buckets:
            account = ub["key"]
            ips = [sb["key"] for sb in ub.get("unique_sources", {}).get("buckets", [])]
            output[account] = ips
        return output

    def _query_spray_aggregated(
        self, window_minutes: int
    ) -> dict[str, list[str]]:
        """
        Aggregate: for each source IP, list the unique target accounts.
        Used to detect password spray (one password tried across many accounts).
        Returns dict of source_ip -> [account1, account2, ...].
        """
        src_field_kw = (
            f"{self._src_ip_field}.keyword"
            if not self._src_ip_field.endswith(".keyword")
            else self._src_ip_field
        )
        user_field_kw = (
            f"{self._target_user_field}.keyword"
            if not self._target_user_field.endswith(".keyword")
            else self._target_user_field
        )

        aggs = {
            "by_source_ip": {
                "terms": {"field": src_field_kw, "size": 200},
                "aggs": {
                    "unique_targets": {
                        "terms": {"field": user_field_kw, "size": 200},
                    },
                },
            },
        }

        query = {
            "bool": {
                "must": [
                    {"match": {self._event_id_field: _EVENT_ID_LOGON_FAILURE}},
                    {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                ],
            }
        }

        result = self.os_client.aggregate(
            index=self._alert_index, aggs=aggs, query=query
        )
        ip_buckets = result.get("by_source_ip", {}).get("buckets", [])
        output: dict[str, list[str]] = {}
        for ib in ip_buckets:
            src_ip = ib["key"]
            accounts = [
                tb["key"]
                for tb in ib.get("unique_targets", {}).get("buckets", [])
            ]
            output[src_ip] = accounts
        return output

    # ------------------------------------------------------------------
    # Analyze: detect attack patterns / تحليل: كشف أنماط الهجوم
    # ------------------------------------------------------------------

    def analyze(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Analyze collected data for all brute force patterns.

        Args:
            data: Collected logon failure data from multiple windows.

        Returns:
            List of finding dicts, each describing a detected pattern.
        """
        findings: list[dict[str, Any]] = []

        # --- Pattern 1: Fast Brute Force ---
        fast_events = data.get("fast_events", [])
        ip_counts: dict[str, int] = defaultdict(int)
        for event in fast_events:
            src_ip = self._extract_nested(event, self._src_ip_field)
            if src_ip and src_ip not in self._ip_whitelist:
                ip_counts[src_ip] += 1

        for ip, count in ip_counts.items():
            if count >= self._fast_threshold:
                findings.append({
                    "pattern": "fast_brute_force",
                    "severity": Severity.HIGH,
                    "source_ip": ip,
                    "failure_count": count,
                    "window": f"{self._fast_window_min} min",
                    "threshold": self._fast_threshold,
                    "description": (
                        f"Fast brute force: {count} login failures from {ip} "
                        f"in {self._fast_window_min} minutes"
                    ),
                })

        # --- Pattern 2: Slow/Low-and-Slow Brute Force ---
        slow_agg = data.get("slow_agg", {})
        for ip, count in slow_agg.items():
            if ip in self._ip_whitelist:
                continue
            if count >= self._slow_threshold:
                findings.append({
                    "pattern": "slow_brute_force",
                    "severity": Severity.MEDIUM,
                    "source_ip": ip,
                    "failure_count": count,
                    "window": f"{self._slow_window_hours} hours",
                    "threshold": self._slow_threshold,
                    "description": (
                        f"Low-and-slow brute force: {count} login failures from {ip} "
                        f"over {self._slow_window_hours} hours"
                    ),
                })

        # --- Pattern 3: Distributed Attack ---
        distributed_agg = data.get("distributed_agg", {})
        for account, source_ips in distributed_agg.items():
            # Filter whitelisted IPs
            filtered_ips = [ip for ip in source_ips if ip not in self._ip_whitelist]
            if len(filtered_ips) >= self._distributed_ips:
                findings.append({
                    "pattern": "distributed_brute_force",
                    "severity": Severity.HIGH,
                    "target_account": account,
                    "source_ips": filtered_ips,
                    "unique_sources": len(filtered_ips),
                    "window": f"{self._distributed_window_min} min",
                    "threshold": self._distributed_ips,
                    "description": (
                        f"Distributed attack: {len(filtered_ips)} unique IPs "
                        f"targeting account '{account}' in "
                        f"{self._distributed_window_min} minutes"
                    ),
                })

        # --- Pattern 4: Password Spray ---
        spray_agg = data.get("spray_agg", {})
        for src_ip, target_accounts in spray_agg.items():
            if src_ip in self._ip_whitelist:
                continue
            if len(target_accounts) >= self._spray_accounts:
                findings.append({
                    "pattern": "password_spray",
                    "severity": Severity.CRITICAL,
                    "source_ip": src_ip,
                    "target_accounts": target_accounts,
                    "unique_accounts": len(target_accounts),
                    "window": f"{self._spray_window_min} min",
                    "threshold": self._spray_accounts,
                    "description": (
                        f"Password spray: {src_ip} tried {len(target_accounts)} "
                        f"different accounts in {self._spray_window_min} minutes"
                    ),
                })

        # Update metrics
        total_events = len(fast_events) + sum(slow_agg.values())
        self._events_processed += total_events
        self._metrics.inc_events(total_events)

        if findings:
            logger.warning("Detected %d brute force patterns", len(findings))

        return findings

    @staticmethod
    def _extract_nested(doc: dict[str, Any], dotted_key: str) -> Optional[str]:
        """
        Extract a value from a nested dict using a dotted key path.
        e.g. _extract_nested(doc, "data.srcip") -> doc["data"]["srcip"]
        """
        keys = dotted_key.split(".")
        current: Any = doc
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return str(current) if current is not None else None

    # ------------------------------------------------------------------
    # Decide: determine actions / قرار: تحديد الإجراءات
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Decide on actions for each finding.

        Args:
            findings: List of detected brute force patterns.

        Returns:
            List of action dicts.
        """
        actions: list[dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            pattern = finding["pattern"]
            source_ip = finding.get("source_ip", "unknown")
            target = finding.get("target_account", source_ip)
            alert_key = f"{pattern}:{source_ip}:{target}"

            # Check cooldown to avoid duplicate alerts
            last_alerted = self._alerted_cache.get(alert_key, 0.0)
            if now - last_alerted < self._alert_cooldown:
                logger.debug("Skipping alert (cooldown): %s", alert_key)
                continue

            # Alert action
            actions.append({
                "type": "alert",
                "severity": finding["severity"],
                "title": f"Brute Force Detected: {pattern.replace('_', ' ').title()}",
                "details": {
                    "pattern": finding["pattern"],
                    "source_ip": source_ip,
                    "target_account": finding.get("target_account", "N/A"),
                    "failure_count": finding.get("failure_count", "N/A"),
                    "unique_sources": finding.get("unique_sources", "N/A"),
                    "unique_accounts": finding.get("unique_accounts", "N/A"),
                    "window": finding["window"],
                    "description": finding["description"],
                },
                "alert_key": alert_key,
            })

            # Auto-block action (if enabled and severity is HIGH+)
            if (
                self._auto_block
                and source_ip != "unknown"
                and finding["severity"] >= Severity.HIGH
            ):
                actions.append({
                    "type": "block_ip",
                    "source_ip": source_ip,
                    "reason": finding["description"],
                })

            # Log to incident index
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
        Execute decided actions (alert, block, log).

        Args:
            actions: List of action dicts.

        Returns:
            Summary of actions taken.
        """
        alerts_sent = 0
        ips_blocked = 0
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
                    # Update cooldown cache
                    self._alerted_cache[action["alert_key"]] = time.time()

            elif action["type"] == "block_ip":
                try:
                    self.wazuh.block_ip(
                        agent_id="all",
                        ip_address=action["source_ip"],
                    )
                    ips_blocked += 1
                    logger.warning(
                        "Blocked IP %s via Wazuh active response",
                        action["source_ip"],
                    )
                except Exception as exc:
                    logger.error(
                        "Failed to block IP %s: %s", action["source_ip"], exc
                    )

            elif action["type"] == "log_incident":
                try:
                    finding = action["finding"]
                    self.os_client.index_document(
                        index="soc-brute-force-incidents",
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name,
                            "pattern": finding["pattern"],
                            "severity": finding["severity"].name,
                            "source_ip": finding.get("source_ip"),
                            "target_account": finding.get("target_account"),
                            "failure_count": finding.get("failure_count"),
                            "unique_sources": finding.get("unique_sources"),
                            "unique_accounts": finding.get("unique_accounts"),
                            "window": finding["window"],
                            "description": finding["description"],
                        },
                    )
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log brute force incident: %s", exc)

        # Prune old cooldown entries
        self._prune_cooldown_cache()

        # Report to supervisor
        if alerts_sent > 0 or ips_blocked > 0:
            self.report_to_supervisor({
                "type": "brute_force_report",
                "alerts_sent": alerts_sent,
                "ips_blocked": ips_blocked,
                "incidents_logged": incidents_logged,
            })

        return {
            "alerts_sent": alerts_sent,
            "ips_blocked": ips_blocked,
            "incidents_logged": incidents_logged,
        }

    def _prune_cooldown_cache(self) -> None:
        """Remove expired entries from the alert cooldown cache."""
        now = time.time()
        expired = [
            k for k, v in self._alerted_cache.items()
            if now - v > self._alert_cooldown * 2
        ]
        for k in expired:
            del self._alerted_cache[k]


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
    agent = BruteForceAgent()
    agent.run_loop()
