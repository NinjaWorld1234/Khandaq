"""
SOC Platform - Worker Agent W34: Cloud / Infrastructure Trail Monitor
وكيل مراقبة مسار البنية التحتية

Monitors infrastructure changes from Wazuh SCA and system logs:
- New user accounts created
- Sudo / admin privilege grants
- Firewall rule changes (iptables, ufw, firewalld)
- SSH key additions
- Crontab modifications
- Systemd service installations
- Docker container launches
- Package installations (apt, yum, dnf, pip)

Tracks every change in the soc-infra-changes index with:
who, what, when, where.

Interval: 120 seconds
Supervisor channel: soc:infra-supervisor
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w34_cloud_trail")

# ---------------------------------------------------------------------------
# Detection rule patterns
# ---------------------------------------------------------------------------

# Wazuh rule IDs that map to infrastructure changes
_RULE_CATEGORIES: Dict[str, str] = {
    # User account management
    "5901": "user_created",
    "5902": "user_deleted",
    "5903": "group_changed",
    "5904": "group_added",
    "5905": "user_modified",
    # Sudo / privilege
    "5401": "sudo_command",
    "5402": "sudo_failed",
    "5403": "sudo_granted",
    # SSH
    "5710": "ssh_key_change",
    "5711": "sshd_config_change",
    "5712": "authorized_keys_change",
    # Firewall
    "4101": "firewall_change",
    "80740": "iptables_change",
    "80741": "ufw_change",
}

# Log-level regex patterns for events Wazuh may not tag with known rule IDs
_LOG_PATTERNS: Dict[str, re.Pattern] = {
    "user_created": re.compile(
        r"(useradd|adduser|new\s+user|new\s+account|user\s+added)",
        re.IGNORECASE,
    ),
    "privilege_grant": re.compile(
        r"(usermod\s+.*-[aG].*sudo|usermod\s+.*-[aG].*wheel|"
        r"visudo|added\s+to\s+group\s+(sudo|wheel|admin|root)|"
        r"grant\s+ALL\s+PRIVILEGES)",
        re.IGNORECASE,
    ),
    "firewall_change": re.compile(
        r"(iptables\s+-[AIDRF]|ufw\s+(allow|deny|delete|insert)|"
        r"firewall-cmd\s+--(add|remove|permanent)|nft\s+(add|delete))",
        re.IGNORECASE,
    ),
    "ssh_key_addition": re.compile(
        r"(ssh-rsa|ssh-ed25519|ecdsa-sha2|authorized_keys|ssh-keygen|ssh-copy-id)",
        re.IGNORECASE,
    ),
    "crontab_change": re.compile(
        r"(crontab\s+-[eirl]|REPLACE\s+\(.*crontab|"
        r"BEGIN\s+EDIT|END\s+EDIT|LIST\s+\(|"
        r"/etc/cron\.(d|daily|hourly|weekly|monthly))",
        re.IGNORECASE,
    ),
    "systemd_service": re.compile(
        r"(systemctl\s+(enable|disable|mask|unmask|daemon-reload)|"
        r"service\s+\S+\s+(start|stop|restart|enable)|"
        r"Created\s+symlink.*\.service|"
        r"/etc/systemd/system/.*\.service)",
        re.IGNORECASE,
    ),
    "docker_launch": re.compile(
        r"(docker\s+(run|create|start|compose\s+up)|"
        r"container\s+(create|start)|"
        r"dockerd.*start)",
        re.IGNORECASE,
    ),
    "package_install": re.compile(
        r"(apt(-get)?\s+install|yum\s+install|dnf\s+install|"
        r"pip3?\s+install|dpkg\s+-i|rpm\s+-[iU]|"
        r"Installed:\s+\S+|pacman\s+-S)",
        re.IGNORECASE,
    ),
}

# Which detection categories are privilege-related (→ HIGH severity)
_PRIVILEGE_CATEGORIES: Set[str] = {
    "user_created", "user_modified", "privilege_grant",
    "sudo_granted", "sudo_command", "ssh_key_addition",
    "authorized_keys_change",
}


class CloudTrailAgent(BaseAgent):
    """
    Infrastructure Trail Monitor (W34).
    Tracks configuration and privilege changes across all monitored hosts.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w34_cloud_trail",
            description="Monitors infrastructure changes: users, privileges, firewall, SSH, crontabs, services, packages",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )

        # Deduplication: change_key → last_alert_ts
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown: int = self._agent_config.get("alert_cooldown", 900)

        # Track per-host change volume for anomaly detection
        self._host_change_counts: Dict[str, int] = defaultdict(int)
        self._change_burst_threshold: int = self._agent_config.get(
            "change_burst_threshold", 20,
        )

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[List[Dict[str, Any]]]:
        """Fetch infrastructure-related events from Wazuh alerts and syslog."""
        query = {
            "bool": {
                "should": [
                    # Match any of the known Wazuh rule IDs
                    {"terms": {"rule.id": list(_RULE_CATEGORIES.keys())}},
                    # SCA / syscollector changes
                    {"match": {"rule.groups": "syscheck"}},
                    {"match": {"rule.groups": "sca"}},
                    {"match": {"rule.groups": "audit"}},
                    {"match": {"rule.groups": "account_changed"}},
                    {"match": {"rule.groups": "pam"}},
                    # Crontab edits reported by Wazuh FIM
                    {"wildcard": {"syscheck.path": "/etc/cron*"}},
                    {"wildcard": {"syscheck.path": "/var/spool/cron/*"}},
                    # systemd service changes via FIM
                    {"wildcard": {"syscheck.path": "/etc/systemd/system/*"}},
                    # Package manager logs
                    {"match_phrase": {"location": "/var/log/dpkg.log"}},
                    {"match_phrase": {"location": "/var/log/yum.log"}},
                    # Docker daemon events
                    {"match": {"predecoder.program_name": "dockerd"}},
                ],
                "minimum_should_match": 1,
            },
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=3,
                query=query,
                size=5000,
            )
        except Exception as exc:
            logger.error("Failed to collect infra-trail events: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify each event and produce change-tracking findings."""
        findings: List[Dict[str, Any]] = []
        self._host_change_counts.clear()

        for event in data:
            agent_info = event.get("agent", {})
            host = agent_info.get("name", "unknown-host")
            agent_ip = agent_info.get("ip", "")
            rule = event.get("rule", {})
            rule_id = rule.get("id", "")
            rule_desc = rule.get("description", "")
            full_log = event.get("full_log", "")
            timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())
            user = (
                event.get("data", {}).get("srcuser")
                or event.get("data", {}).get("dstuser")
                or event.get("data", {}).get("audit", {}).get("loginuid", "")
                or "unknown"
            )
            syscheck_path = event.get("syscheck", {}).get("path", "")

            # --- Determine category ---
            category: Optional[str] = None

            # First, check Wazuh rule ID mapping
            if rule_id in _RULE_CATEGORIES:
                category = _RULE_CATEGORIES[rule_id]

            # Second, scan log text against regex patterns
            if category is None:
                for cat_name, pattern in _LOG_PATTERNS.items():
                    if pattern.search(full_log) or pattern.search(rule_desc):
                        category = cat_name
                        break

            # Third, fall back on syscheck paths
            if category is None and syscheck_path:
                if "cron" in syscheck_path:
                    category = "crontab_change"
                elif ".service" in syscheck_path:
                    category = "systemd_service"
                elif "authorized_keys" in syscheck_path:
                    category = "ssh_key_addition"

            if category is None:
                continue  # Not an infra-change we care about

            # --- Determine severity ---
            severity = (
                Severity.HIGH if category in _PRIVILEGE_CATEGORIES
                else Severity.MEDIUM
            )

            # --- Extract detail ---
            detail = rule_desc or full_log[:300]

            finding = {
                "category": category,
                "severity": severity,
                "host": host,
                "host_ip": agent_ip,
                "who": user,
                "what": detail,
                "when": timestamp,
                "where": syscheck_path or f"rule:{rule_id}",
                "rule_id": rule_id,
            }
            findings.append(finding)

            self._host_change_counts[host] += 1

        # --- Burst detection: too many changes on a single host ---
        for host, count in self._host_change_counts.items():
            if count >= self._change_burst_threshold:
                findings.append({
                    "category": "change_burst",
                    "severity": Severity.HIGH,
                    "host": host,
                    "host_ip": "",
                    "who": "multiple",
                    "what": f"Burst of {count} infrastructure changes on {host} in a single cycle",
                    "when": datetime.now(timezone.utc).isoformat(),
                    "where": "aggregate",
                    "rule_id": "",
                })

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Decide which findings warrant alerts and escalation."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            change_key = (
                f"{finding['category']}:{finding['host']}:"
                f"{finding['who']}:{finding['where']}"
            )

            # Cooldown deduplication
            if now - self._alerted_cache.get(change_key, 0.0) < self._alert_cooldown:
                # Still log the change, just skip the alert
                actions.append({"type": "log_change", "finding": finding})
                continue

            # Alert
            actions.append({
                "type": "alert",
                "severity": finding["severity"],
                "title": f"Infra Change: {finding['category'].replace('_', ' ').title()}",
                "details": {k: v for k, v in finding.items() if k != "severity"},
                "change_key": change_key,
            })

            # Escalate if HIGH or above
            if finding["severity"] >= Severity.HIGH:
                actions.append({"type": "escalate", "finding": finding})

            # Always log to the tracking index
            actions.append({"type": "log_change", "finding": finding})

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alerts, escalations, and change-log indexing."""
        alerts_sent = 0
        escalations = 0
        changes_logged = 0

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
                    self._alerted_cache[action["change_key"]] = time.time()

            elif action["type"] == "escalate":
                self.report_to_supervisor({
                    "type": "infra_change_escalation",
                    **action["finding"],
                })
                escalations += 1

            elif action["type"] == "log_change":
                try:
                    finding = action["finding"]
                    self.os_client.index_document(
                        index="soc-infra-changes",
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name,
                            "category": finding["category"],
                            "severity": finding["severity"].name,
                            "host": finding["host"],
                            "host_ip": finding.get("host_ip", ""),
                            "who": finding["who"],
                            "what": finding["what"],
                            "when": finding["when"],
                            "where": finding["where"],
                            "rule_id": finding.get("rule_id", ""),
                        },
                    )
                    changes_logged += 1
                except Exception as exc:
                    logger.error("Failed to index infra change: %s", exc)

        # Prune stale cooldown entries
        cutoff = time.time() - self._alert_cooldown * 2
        self._alerted_cache = {
            k: v for k, v in self._alerted_cache.items() if v > cutoff
        }

        if alerts_sent or changes_logged:
            self.report_to_supervisor({
                "type": "infra_trail_summary",
                "alerts_sent": alerts_sent,
                "escalations": escalations,
                "changes_logged": changes_logged,
            })

        return {
            "alerts_sent": alerts_sent,
            "escalations": escalations,
            "changes_logged": changes_logged,
        }


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
    agent = CloudTrailAgent()
    agent.run_loop()
