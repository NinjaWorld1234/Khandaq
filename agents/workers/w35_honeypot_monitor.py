"""
SOC Platform - Worker Agent W35: Honeypot/Deception Monitor
وكيل مراقبة مصائد العسل والخداع

Monitors alerts from honeypot services (Dionaea, Cowrie, T-Pot) via Wazuh.
Any interaction with a honeypot = confirmed attacker (zero false positives).

Tracks: source IPs, attack types (SSH brute force, SMB exploitation,
HTTP scanning), attacker tools/techniques, session durations.
Auto-blocks attacker IPs, stores profiles in soc-honeypot-intel index,
and cross-references honeypot visitors with production network connections.

Interval: 30 seconds | Supervisor: soc:detection-supervisor
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w35_honeypot_monitor")

# Honeypot rule groups in Wazuh
_COWRIE_GROUPS = ("cowrie", "ssh_honeypot", "telnet_honeypot")
_DIONAEA_GROUPS = ("dionaea", "smb_honeypot", "ftp_honeypot")
_HTTP_HONEYPOT_GROUPS = ("http_honeypot", "web_honeypot", "glastopf")
_ALL_HONEYPOT_GROUPS = _COWRIE_GROUPS + _DIONAEA_GROUPS + _HTTP_HONEYPOT_GROUPS

# Attack type classification by Wazuh rule.id ranges
_ATTACK_RULES: Dict[str, List[str]] = {
    "ssh_brute_force": ["80101", "80102", "80103", "80104"],
    "ssh_command_exec": ["80105", "80106", "80107"],
    "smb_exploitation": ["81001", "81002", "81003", "81004"],
    "http_scanning": ["82001", "82002", "82003"],
    "ftp_brute_force": ["81101", "81102"],
    "telnet_login": ["80201", "80202", "80203"],
    "malware_download": ["81005", "81006", "82004"],
}

# Reverse lookup: rule_id -> attack_type
_RULE_TO_ATTACK: Dict[str, str] = {}
for _atype, _rids in _ATTACK_RULES.items():
    for _rid in _rids:
        _RULE_TO_ATTACK[_rid] = _atype

# Internal network ranges (RFC 1918) for severity escalation
_INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.")


class HoneypotMonitorAgent(BaseAgent):
    """
    Honeypot/Deception Monitor Agent (W35).
    وكيل مراقبة مصائد العسل

    Zero false-positive detection: any interaction with a honeypot is
    by definition malicious. Classifies attacks, builds attacker profiles,
    auto-blocks source IPs, and cross-references with production logs.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w35_honeypot_monitor",
            description="Monitors honeypot interactions for confirmed attacker activity",
            interval_seconds=30,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")
        self._intel_index = "soc-honeypot-intel"
        self._auto_block = self._agent_config.get("auto_block", True)
        self._known_attackers: Dict[str, Dict[str, Any]] = {}
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown = 300  # 5 min cooldown per attacker IP

    @staticmethod
    def _is_internal(ip: str) -> bool:
        """Check if an IP belongs to an internal RFC-1918 range."""
        return any(ip.startswith(p) for p in _INTERNAL_PREFIXES)

    @staticmethod
    def _extract(doc: Dict[str, Any], dotted_key: str) -> Optional[str]:
        """Extract a nested value from a dict using dotted key notation."""
        current: Any = doc
        for key in dotted_key.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return str(current) if current is not None else None

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[Dict[str, Any]]:
        """Fetch honeypot alerts from the last 2 minutes and production
        network events for cross-referencing."""
        try:
            hp_query = {
                "bool": {
                    "should": [
                        {"terms": {"rule.groups": list(_ALL_HONEYPOT_GROUPS)}},
                        {"wildcard": {"rule.groups": "*honeypot*"}},
                        {"wildcard": {"agent.name": "*honeypot*"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            honeypot_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2, query=hp_query, size=2000,
            )
            production_ips: Set[str] = set()
            if honeypot_events:
                attacker_ips = {
                    self._extract(e, "data.srcip") for e in honeypot_events
                } - {None}
                if attacker_ips:
                    prod_query = {
                        "bool": {
                            "must": [{"terms": {"data.srcip": list(attacker_ips)}}],
                            "must_not": [
                                {"terms": {"rule.groups": list(_ALL_HONEYPOT_GROUPS)}}
                            ],
                        }
                    }
                    prod_events = self.os_client.get_events_since(
                        index=self._alert_index, minutes=60, query=prod_query, size=500,
                    )
                    production_ips = {
                        self._extract(e, "data.srcip") for e in prod_events
                    } - {None}

            return {"honeypot_events": honeypot_events, "prod_crossref_ips": production_ips}
        except Exception as exc:
            logger.error("Failed to collect honeypot data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Classify every honeypot interaction and build attacker profiles."""
        findings: List[Dict[str, Any]] = []
        events = data.get("honeypot_events", [])
        prod_ips: Set[str] = data.get("prod_crossref_ips", set())

        profiles: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "attack_types": set(), "rule_ids": set(), "event_count": 0,
            "first_seen": None, "last_seen": None, "commands": [],
            "credentials": [], "in_production": False,
        })

        for event in events:
            src_ip = self._extract(event, "data.srcip")
            if not src_ip:
                continue

            rule_id = self._extract(event, "rule.id") or "unknown"
            timestamp = self._extract(event, "@timestamp") or ""
            attack_type = _RULE_TO_ATTACK.get(rule_id, "unknown_interaction")
            command = self._extract(event, "data.command")
            username = self._extract(event, "data.dstuser") or self._extract(event, "data.username")
            password = self._extract(event, "data.password")

            prof = profiles[src_ip]
            prof["attack_types"].add(attack_type)
            prof["rule_ids"].add(rule_id)
            prof["event_count"] += 1
            if not prof["first_seen"] or timestamp < prof["first_seen"]:
                prof["first_seen"] = timestamp
            if not prof["last_seen"] or timestamp > prof["last_seen"]:
                prof["last_seen"] = timestamp
            if command and len(prof["commands"]) < 20:
                prof["commands"].append(command)
            if username and password:
                cred = f"{username}:{password}"
                if cred not in prof["credentials"] and len(prof["credentials"]) < 20:
                    prof["credentials"].append(cred)
            if src_ip in prod_ips:
                prof["in_production"] = True

        self._events_processed += len(events)
        self._metrics.inc_events(len(events))

        for src_ip, prof in profiles.items():
            is_internal = self._is_internal(src_ip)
            in_prod = prof["in_production"]

            if is_internal or in_prod:
                severity = Severity.CRITICAL
            elif prof["event_count"] >= 20 or len(prof["attack_types"]) >= 3:
                severity = Severity.CRITICAL
            else:
                severity = Severity.HIGH

            desc_parts = [f"Honeypot interaction from {src_ip}"]
            if is_internal:
                desc_parts.append("INTERNAL IP — possible compromised host")
            if in_prod:
                desc_parts.append("Also seen in production network traffic")

            findings.append({
                "source_ip": src_ip,
                "severity": severity,
                "is_internal": is_internal,
                "in_production": in_prod,
                "attack_types": sorted(prof["attack_types"]),
                "event_count": prof["event_count"],
                "first_seen": prof["first_seen"],
                "last_seen": prof["last_seen"],
                "commands": prof["commands"][:10],
                "credentials_tried": len(prof["credentials"]),
                "description": " | ".join(desc_parts),
            })

        if findings:
            logger.warning("Detected %d honeypot attacker(s)", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create alert, block, and intel-storage actions for each attacker."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            src_ip = finding["source_ip"]
            cooldown_key = f"hp:{src_ip}"
            last = self._alerted_cache.get(cooldown_key, 0.0)

            if now - last >= self._alert_cooldown:
                actions.append({
                    "type": "alert",
                    "severity": finding["severity"],
                    "title": "Honeypot Interaction — Confirmed Attacker",
                    "details": {
                        "source_ip": src_ip,
                        "is_internal": finding["is_internal"],
                        "in_production": finding["in_production"],
                        "attack_types": ", ".join(finding["attack_types"]),
                        "event_count": finding["event_count"],
                        "credentials_tried": finding["credentials_tried"],
                        "description": finding["description"],
                    },
                    "cooldown_key": cooldown_key,
                })

            if self._auto_block:
                actions.append({"type": "block_ip", "source_ip": src_ip})

            actions.append({"type": "store_intel", "finding": finding})

            if finding["is_internal"] or finding["in_production"]:
                actions.append({
                    "type": "escalate",
                    "finding": finding,
                })

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alert, block, escalation, and intel-storage actions."""
        alerts_sent = 0
        ips_blocked = 0
        intel_stored = 0

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
                    self._alerted_cache[action["cooldown_key"]] = time.time()

            elif action["type"] == "block_ip":
                try:
                    self.redis_bus.publish("soc:firewall-commands", {
                        "action": "block",
                        "ip": action["source_ip"],
                        "reason": "honeypot_interaction",
                        "agent": self.name,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    ips_blocked += 1
                    logger.warning("Issued block for attacker IP %s", action["source_ip"])
                except Exception as exc:
                    logger.error("Failed to block IP %s: %s", action["source_ip"], exc)

            elif action["type"] == "store_intel":
                try:
                    finding = action["finding"]
                    doc_id = hashlib.sha256(finding["source_ip"].encode()).hexdigest()[:16]
                    self.os_client.index_document(
                        index=self._intel_index,
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "source_ip": finding["source_ip"],
                            "is_internal": finding["is_internal"],
                            "in_production": finding["in_production"],
                            "attack_types": finding["attack_types"],
                            "event_count": finding["event_count"],
                            "first_seen": finding["first_seen"],
                            "last_seen": finding["last_seen"],
                            "credentials_tried": finding["credentials_tried"],
                            "commands_sample": finding["commands"],
                        },
                        doc_id=doc_id,
                    )
                    intel_stored += 1
                except Exception as exc:
                    logger.error("Failed to store honeypot intel: %s", exc)

            elif action["type"] == "escalate":
                finding = action["finding"]
                self.report_to_supervisor({
                    "type": "honeypot_critical",
                    "source_ip": finding["source_ip"],
                    "is_internal": finding["is_internal"],
                    "in_production": finding["in_production"],
                    "description": finding["description"],
                })

        # Prune stale cooldown entries
        cutoff = time.time() - self._alert_cooldown * 3
        self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent or ips_blocked:
            self.report_to_supervisor({
                "type": "honeypot_report",
                "alerts_sent": alerts_sent,
                "ips_blocked": ips_blocked,
                "intel_stored": intel_stored,
            })

        return {"alerts_sent": alerts_sent, "ips_blocked": ips_blocked, "intel_stored": intel_stored}


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
    agent = HoneypotMonitorAgent()
    agent.run_loop()
