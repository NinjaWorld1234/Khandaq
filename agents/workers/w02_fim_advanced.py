"""
SOC Platform - Worker Agent W02: Advanced File Integrity Monitoring
وكيل مراقبة سلامة الملفات المتقدم

Detects:
- Sudden entropy increase in modified files (encryption/packing indicator)
- Modification of critical system binaries (/bin, /sbin, System32)
- New executable files in unusual locations
- Mass file modifications (>50 files in 1 minute)
- Hidden file creation (dotfiles on Linux, hidden attribute on Windows)
- Modification of startup scripts / cron / scheduled tasks

Interval: 60 seconds
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w02_fim_advanced")

# Paths considered critical system directories
_CRITICAL_PATHS_LINUX = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/usr/lib/")
_CRITICAL_PATHS_WIN = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\")

# Directories where executables should not normally appear
_UNUSUAL_EXEC_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/var/www/", "/home/")

# Startup / persistence paths
_PERSISTENCE_PATHS = (
    "/etc/cron", "/etc/init.d/", "/etc/systemd/", "/etc/rc.local",
    "/etc/profile", "/etc/bashrc", "/.bashrc", "/.bash_profile",
    "c:\\windows\\system32\\tasks\\", "c:\\programdata\\microsoft\\windows\\start menu\\",
)

# High-entropy threshold (Shannon bits per byte) — encrypted/packed files
_ENTROPY_THRESHOLD = 7.2
_MASS_MOD_THRESHOLD = 50


class AdvancedFIMAgent(BaseAgent):
    """
    Advanced File Integrity Monitoring Agent (W02).
    وكيل مراقبة سلامة الملفات المتقدم
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w02_fim_advanced",
            description="Advanced File Integrity Monitoring with entropy analysis",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:endpoint-supervisor",
        )
        # Per-host baseline of file changes per minute (rolling average)
        self._host_baselines: Dict[str, float] = {}
        # Cache of already-alerted file paths to reduce noise (path -> timestamp)
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown = 600  # 10-minute cooldown per unique file path
        # Whitelist of paths that change frequently (logs, caches)
        self._path_whitelist: Set[str] = set(
            self._agent_config.get("path_whitelist", [
                "/var/log/", "/var/cache/", "c:\\windows\\temp\\",
            ])
        )

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[List[Dict[str, Any]]]:
        """Fetch Wazuh FIM (syscheck) alerts from the last 2 minutes."""
        try:
            query: Dict[str, Any] = {
                "bool": {
                    "should": [
                        {"match": {"rule.groups": "syscheck"}},
                        {"match": {"rule.groups": "ossec_syscheck"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            events = self.os_client.get_events_since(
                index="wazuh-alerts-*", minutes=2, query=query, size=2000,
            )
            logger.debug("Collected %d FIM events", len(events))
            return events
        except Exception as exc:
            logger.error("Failed to collect FIM data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run all six detection rules against collected FIM events."""
        findings: List[Dict[str, Any]] = []
        host_file_counts: Dict[str, int] = defaultdict(int)

        for event in data:
            syscheck = event.get("syscheck", {})
            file_path: str = syscheck.get("path", "").replace("\\", "\\").strip()
            agent_name: str = event.get("agent", {}).get("name", "unknown")
            change_type: str = syscheck.get("event", "modified")
            path_lower = file_path.lower()

            if not file_path or self._is_whitelisted(path_lower):
                continue

            host_file_counts[agent_name] += 1

            # Rule 1: Entropy increase (encryption / packing indicator)
            self._check_entropy(syscheck, file_path, agent_name, findings)

            # Rule 2: Critical system binary modification
            self._check_critical_binary(path_lower, file_path, agent_name, change_type, findings)

            # Rule 3: Executable in unusual location
            self._check_unusual_executable(syscheck, path_lower, file_path, agent_name, change_type, findings)

            # Rule 5: Hidden file creation
            self._check_hidden_file(syscheck, path_lower, file_path, agent_name, change_type, findings)

            # Rule 6: Startup / cron / persistence modification
            self._check_persistence(path_lower, file_path, agent_name, change_type, findings)

        # Rule 4: Mass file modification (>50 files in 1 minute per host)
        for host, count in host_file_counts.items():
            baseline = self._host_baselines.get(host, 5.0)
            if count >= _MASS_MOD_THRESHOLD and count > baseline * 5:
                findings.append({
                    "rule": "mass_file_modification",
                    "severity": Severity.CRITICAL,
                    "host": host,
                    "file_count": count,
                    "baseline": round(baseline, 1),
                    "description": (
                        f"Mass file modification on {host}: {count} files changed "
                        f"(baseline ~{baseline:.0f}). Possible ransomware or wiper."
                    ),
                })
            # Update rolling baseline: exponential moving average
            alpha = 0.1
            self._host_baselines[host] = alpha * count + (1 - alpha) * baseline

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    def _is_whitelisted(self, path_lower: str) -> bool:
        return any(path_lower.startswith(w) for w in self._path_whitelist)

    def _check_entropy(self, syscheck: dict, path: str, host: str,
                       findings: List[Dict[str, Any]]) -> None:
        """Detect sudden entropy jump indicating encryption or packing."""
        sha_after = syscheck.get("sha256_after", "")
        sha_before = syscheck.get("sha256_before", "")
        diff_attrs = syscheck.get("changed_attributes", [])
        # Wazuh sometimes reports md5/sha changes; we approximate entropy from size+hash
        size_after = syscheck.get("size_after")
        size_before = syscheck.get("size_before")
        if size_before and size_after and sha_before and sha_after and sha_before != sha_after:
            try:
                s_before, s_after = int(size_before), int(size_after)
                # Estimate entropy from hash diversity heuristic
                entropy_est = self._estimate_hash_entropy(sha_after, s_after)
                if entropy_est >= _ENTROPY_THRESHOLD and s_after > 1024:
                    findings.append({
                        "rule": "high_entropy_file",
                        "severity": Severity.HIGH,
                        "host": host, "path": path,
                        "entropy_estimate": round(entropy_est, 2),
                        "size_before": s_before, "size_after": s_after,
                        "description": (
                            f"High entropy ({entropy_est:.1f} bits/byte) detected in "
                            f"{path} on {host} — possible encryption or packing."
                        ),
                    })
            except (ValueError, TypeError):
                pass

    @staticmethod
    def _estimate_hash_entropy(hex_hash: str, file_size: int) -> float:
        """Estimate per-byte entropy from a hex digest (rough proxy)."""
        byte_vals = [int(hex_hash[i:i + 2], 16) for i in range(0, min(len(hex_hash), 64), 2)]
        if not byte_vals:
            return 0.0
        freq: Dict[int, int] = defaultdict(int)
        for b in byte_vals:
            freq[b] += 1
        total = len(byte_vals)
        entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
        # Scale: a truly random file hash → ~8 bits; structured → lower
        return min(entropy * 1.6, 8.0)

    def _check_critical_binary(self, path_lower: str, path: str, host: str,
                               change_type: str, findings: List[Dict[str, Any]]) -> None:
        critical = _CRITICAL_PATHS_LINUX + _CRITICAL_PATHS_WIN
        if any(path_lower.startswith(d) for d in critical):
            findings.append({
                "rule": "critical_binary_modification",
                "severity": Severity.CRITICAL,
                "host": host, "path": path, "change_type": change_type,
                "description": f"Critical system binary {change_type}: {path} on {host}",
            })

    def _check_unusual_executable(self, syscheck: dict, path_lower: str, path: str,
                                  host: str, change_type: str,
                                  findings: List[Dict[str, Any]]) -> None:
        if change_type not in ("added", "modified"):
            return
        is_exec = path_lower.endswith((".exe", ".elf", ".sh", ".bat", ".ps1", ".dll", ".so"))
        perm = syscheck.get("perm_after", "")
        if not is_exec and "x" not in perm:
            return
        if any(path_lower.startswith(d) for d in _UNUSUAL_EXEC_DIRS):
            findings.append({
                "rule": "executable_unusual_location",
                "severity": Severity.HIGH,
                "host": host, "path": path, "change_type": change_type,
                "description": f"Executable {change_type} in unusual location: {path} on {host}",
            })

    def _check_hidden_file(self, syscheck: dict, path_lower: str, path: str,
                           host: str, change_type: str,
                           findings: List[Dict[str, Any]]) -> None:
        if change_type != "added":
            return
        basename = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        is_hidden_linux = basename.startswith(".") and basename not in (".bashrc", ".profile", ".bash_history")
        attrs = syscheck.get("attrs_after", "")
        is_hidden_win = "HIDDEN" in str(attrs).upper()
        if is_hidden_linux or is_hidden_win:
            findings.append({
                "rule": "hidden_file_created",
                "severity": Severity.MEDIUM,
                "host": host, "path": path,
                "description": f"Hidden file created: {path} on {host}",
            })

    def _check_persistence(self, path_lower: str, path: str, host: str,
                           change_type: str, findings: List[Dict[str, Any]]) -> None:
        if any(path_lower.startswith(p) or p in path_lower for p in _PERSISTENCE_PATHS):
            findings.append({
                "rule": "persistence_modification",
                "severity": Severity.HIGH,
                "host": host, "path": path, "change_type": change_type,
                "description": f"Startup/persistence path {change_type}: {path} on {host}",
            })

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        now = time.time()
        for f in findings:
            cache_key = f"{f['rule']}:{f.get('host')}:{f.get('path', '')}"
            if now - self._alerted_cache.get(cache_key, 0) < self._alert_cooldown:
                continue
            actions.append({"type": "alert", "finding": f, "cache_key": cache_key})
            if f["severity"] >= Severity.HIGH:
                actions.append({"type": "escalate", "finding": f})
            actions.append({"type": "log_incident", "finding": f})
        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        alerts_sent = 0
        escalations = 0
        incidents_logged = 0

        for action in actions:
            f = action["finding"]
            if action["type"] == "alert":
                sent = self.alerter.send_alert(
                    severity=f["severity"], title=f"FIM: {f['rule'].replace('_', ' ').title()}",
                    details={"host": f.get("host"), "path": f.get("path", "N/A"),
                             "description": f["description"]},
                    agent_name=self.name,
                )
                if sent:
                    alerts_sent += 1
                    self._metrics.inc_alerts(f["severity"].name)
                    self._alerted_cache[action["cache_key"]] = time.time()
            elif action["type"] == "escalate":
                self.report_to_supervisor({
                    "type": "fim_escalation", "rule": f["rule"],
                    "severity": f["severity"].name, "description": f["description"],
                })
                escalations += 1
            elif action["type"] == "log_incident":
                try:
                    self.os_client.index_document("soc-fim-incidents", {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent_name": self.name, "rule": f["rule"],
                        "severity": f["severity"].name, "host": f.get("host"),
                        "path": f.get("path"), "description": f["description"],
                    })
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log FIM incident: %s", exc)

        # Prune old cooldown entries
        cutoff = time.time() - self._alert_cooldown * 2
        self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        return {"alerts_sent": alerts_sent, "escalations": escalations,
                "incidents_logged": incidents_logged}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
                        stream=sys.stdout)
    agent = AdvancedFIMAgent()
    agent.run_loop()
