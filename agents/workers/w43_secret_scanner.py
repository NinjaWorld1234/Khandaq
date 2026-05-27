"""
SOC Platform - Worker Agent W43: Secret / Credential Scanner
وكيل فحص الأسرار والبيانات المعتمدة

Scans for exposed secrets in logs and file changes:
- AWS access keys (AKIA…)
- Private keys (RSA, DSA, EC, OpenSSH)
- Database connection URLs (mysql://, postgres://, mongodb://)
- Passwords in config files (password=, passwd=, secret=)
- Bearer / JWT tokens
- API keys and generic tokens
- Azure / GCP credentials
- Connection strings (Server=…;Password=…)

Sources: Wazuh FIM alerts, application logs, syslog.

Interval: 300 seconds
Supervisor channel: soc:detection-supervisor
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w43_secret_scanner")

# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: Dict[str, Tuple[re.Pattern, Severity, str]] = {
    "aws_access_key": (
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        Severity.CRITICAL,
        "AWS Access Key ID exposed",
    ),
    "aws_secret_key": (
        re.compile(
            r"""(?:aws_secret_access_key|secret_?key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "AWS Secret Access Key exposed",
    ),
    "private_key": (
        re.compile(r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"),
        Severity.CRITICAL,
        "Private key material found",
    ),
    "database_url": (
        re.compile(
            r"(mysql|postgres|postgresql|mongodb|redis|amqp|mssql)"
            r"://[^\s:]+:[^\s@]+@[^\s]+",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Database connection URL with credentials",
    ),
    "password_in_config": (
        re.compile(
            r"""(?:password|passwd|pass|pwd|secret|credentials)\s*[=:]\s*['"]([^'"]{4,})['"]""",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Password or secret in configuration",
    ),
    "password_plain_assign": (
        re.compile(
            r"""(?:password|passwd|secret)\s*=\s*(\S{6,})""",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Password assigned in plaintext",
    ),
    "bearer_token": (
        re.compile(
            r"""(?:Authorization|Bearer)\s*[=:]\s*['"]?Bearer\s+([A-Za-z0-9\-_\.]{20,})['"]?""",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Bearer token exposed",
    ),
    "jwt_token": (
        re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"
        ),
        Severity.HIGH,
        "JWT token found in logs",
    ),
    "generic_api_key": (
        re.compile(
            r"""(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|auth[_-]?token)"""
            r"""\s*[=:]\s*['"]?([A-Za-z0-9\-_]{20,})['"]?""",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "API key or token exposed",
    ),
    "github_token": (
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        Severity.CRITICAL,
        "GitHub personal access token exposed",
    ),
    "slack_token": (
        re.compile(r"xox[bpors]-[0-9]{10,}-[A-Za-z0-9-]+"),
        Severity.HIGH,
        "Slack token exposed",
    ),
    "azure_connection_string": (
        re.compile(
            r"(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,}",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Azure connection string with key",
    ),
    "gcp_service_key": (
        re.compile(
            r'"private_key"\s*:\s*"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        ),
        Severity.CRITICAL,
        "GCP service account key file content",
    ),
    "connection_string": (
        re.compile(
            r"(?:Server|Data\s+Source)\s*=\s*[^;]+;\s*(?:.*?)Password\s*=\s*[^;]+",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Connection string with embedded password",
    ),
}

# Paths / sources that are expected to contain secrets (false-positive suppression)
_SAFE_PATHS: Set[str] = {
    "/etc/shadow",          # Already protected by OS permissions
    "/etc/gshadow",
    "/proc/",               # Kernel virtual FS
    ".git/config",          # Git credential helper (usually safe)
}

# Max length of matched content we store (redacted)
_MAX_MATCH_LEN = 60


def _redact(value: str) -> str:
    """Keep first 6 and last 4 chars, mask the rest."""
    if len(value) <= 12:
        return value[:3] + "***" + value[-2:]
    return value[:6] + "****" + value[-4:]


def _fingerprint(secret_type: str, host: str, path: str, matched: str) -> str:
    """Stable hash for deduplication across cycles."""
    raw = f"{secret_type}|{host}|{path}|{matched}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


class SecretScannerAgent(BaseAgent):
    """
    Secret / Credential Scanner (W43).
    Scans Wazuh FIM alerts and application logs for leaked secrets.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w43_secret_scanner",
            description="Scans logs and file changes for exposed secrets and credentials",
            interval_seconds=300,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )

        # Dedup: fingerprint → last_alert_ts
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown: int = self._agent_config.get("alert_cooldown", 1800)
        self._cache_lock = threading.Lock()

        # Track unique secrets per cycle for summary reporting
        self._cycle_stats: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[List[Dict[str, Any]]]:
        """Fetch FIM change alerts and application logs that may contain secrets."""
        query = {
            "bool": {
                "should": [
                    # Wazuh FIM (file integrity monitoring) events
                    {"match": {"rule.groups": "syscheck"}},
                    {"match": {"rule.groups": "fim"}},
                    # Configuration file changes
                    {"wildcard": {"syscheck.path": "*.conf"}},
                    {"wildcard": {"syscheck.path": "*.env"}},
                    {"wildcard": {"syscheck.path": "*.yml"}},
                    {"wildcard": {"syscheck.path": "*.yaml"}},
                    {"wildcard": {"syscheck.path": "*.json"}},
                    {"wildcard": {"syscheck.path": "*.properties"}},
                    {"wildcard": {"syscheck.path": "*.cfg"}},
                    {"wildcard": {"syscheck.path": "*.ini"}},
                    # Application logs that might echo secrets
                    {"match_phrase": {"location": "/var/log/syslog"}},
                    {"match_phrase": {"location": "/var/log/messages"}},
                    {"match_phrase": {"location": "/var/log/auth.log"}},
                    {"wildcard": {"location": "/var/log/app*"}},
                    {"wildcard": {"location": "/opt/*/logs/*"}},
                ],
                "minimum_should_match": 1,
            },
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=6,
                query=query,
                size=10000,
            )
        except Exception as exc:
            logger.error("Failed to collect FIM/log events: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan each event for secret patterns."""
        findings: List[Dict[str, Any]] = []
        self._cycle_stats.clear()

        for event in data:
            try:
                host = (event.get("agent") or {}).get("name", "unknown-host")
                host_ip = (event.get("agent") or {}).get("ip", "")
                syscheck = event.get("syscheck", {})
                file_path = syscheck.get("path", event.get("location", ""))
                full_log = event.get("full_log", "")
                diff_content = syscheck.get("diff", "")

                # Skip known-safe paths
                if any(safe in file_path for safe in _SAFE_PATHS):
                    continue

                # Combine all searchable text
                searchable = f"{full_log}\n{diff_content}"
                if not searchable.strip():
                    continue

                # Run every pattern against the text
                for secret_type, (pattern, severity, description) in _SECRET_PATTERNS.items():
                    try:
                        match = pattern.search(searchable)
                        if not match:
                            continue

                        matched_text = match.group(0)
                        fp = _fingerprint(secret_type, host, file_path, matched_text)

                        findings.append({
                            "secret_type": secret_type,
                            "severity": severity,
                            "host": host,
                            "host_ip": host_ip,
                            "file_path": file_path,
                            "description": description,
                            "matched_redacted": _redact(matched_text),
                            "fingerprint": fp,
                            "event_timestamp": event.get(
                                "timestamp", datetime.now(timezone.utc).isoformat()
                            ),
                        })

                        self._cycle_stats[secret_type] = (
                            self._cycle_stats.get(secret_type, 0) + 1
                        )
                    except Exception as e:
                        logger.warning("Error searching pattern %s: %s", secret_type, e)
            except Exception as e:
                logger.warning("Error processing event: %s", e)

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Determine alerts and actions; deduplicate by fingerprint."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            try:
                fp = finding["fingerprint"]

                # Always store the finding
                actions.append({"type": "log_secret", "finding": finding})

                # Cooldown check for alerting
                with self._cache_lock:
                    last_alert = self._alerted_cache.get(fp, 0.0)
                if now - last_alert < self._alert_cooldown:
                    continue

                # Create alert — always CRITICAL for secrets (override to at least CRITICAL)
                alert_severity = max(finding["severity"], Severity.CRITICAL)
                actions.append({
                    "type": "alert",
                    "severity": alert_severity,
                    "title": f"Exposed Secret: {finding['secret_type'].replace('_', ' ').title()}",
                    "details": {
                        k: v for k, v in finding.items()
                        if k not in ("severity", "fingerprint")
                    },
                    "fingerprint": fp,
                })

                # All secret exposures escalate to supervisor
                actions.append({"type": "escalate", "finding": finding})
            except Exception as e:
                logger.warning("Error evaluating secret finding action: %s", e)

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alerts, escalations, and index secret findings."""
        alerts_sent = 0
        escalations = 0
        secrets_logged = 0

        for action in actions:
            try:
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
                        with self._cache_lock:
                            self._alerted_cache[action["fingerprint"]] = time.time()

                elif action["type"] == "escalate":
                    finding = action["finding"]
                    self.report_to_supervisor({
                        "type": "secret_exposure_escalation",
                        "secret_type": finding["secret_type"],
                        "host": finding["host"],
                        "file_path": finding["file_path"],
                        "description": finding["description"],
                        "matched_redacted": finding["matched_redacted"],
                    })
                    escalations += 1

                elif action["type"] == "log_secret":
                    try:
                        finding = action["finding"]
                        self.os_client.index_document(
                            index="soc-secrets",
                            document={
                                "@timestamp": datetime.now(timezone.utc).isoformat(),
                                "agent_name": self.name,
                                "secret_type": finding["secret_type"],
                                "severity": finding["severity"].name,
                                "host": finding["host"],
                                "host_ip": finding.get("host_ip", ""),
                                "file_path": finding["file_path"],
                                "description": finding["description"],
                                "matched_redacted": finding["matched_redacted"],
                                "fingerprint": finding["fingerprint"],
                                "event_timestamp": finding["event_timestamp"],
                            },
                        )
                        secrets_logged += 1
                    except Exception as exc:
                        logger.error("Failed to index secret finding: %s", exc)
            except Exception as e:
                logger.warning("Error executing secret action: %s", e)

        # Prune stale cooldown entries
        cutoff = time.time() - self._alert_cooldown * 2
        with self._cache_lock:
            self._alerted_cache = {
                k: v for k, v in self._alerted_cache.items() if v > cutoff
            }

        # Summary report to supervisor
        if alerts_sent or secrets_logged:
            self.report_to_supervisor({
                "type": "secret_scan_summary",
                "alerts_sent": alerts_sent,
                "escalations": escalations,
                "secrets_logged": secrets_logged,
                "types_found": dict(self._cycle_stats),
            })

        return {
            "alerts_sent": alerts_sent,
            "escalations": escalations,
            "secrets_logged": secrets_logged,
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
    agent = SecretScannerAgent()
    agent.run_loop()
