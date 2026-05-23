"""
SOC Platform - Worker Agent W04: Rootkit Detection
وكيل كشف الجذور الخفية

Detects:
- Hidden processes (process in /proc but not in ps output)
- Hidden ports (port open but not in netstat)
- Modified system binaries (hash mismatch via rootcheck)
- Suspicious kernel modules (lsmod anomalies)
- LD_PRELOAD hijacking
- /etc/ld.so.preload modifications
- Hidden files in /tmp, /dev/shm
- SUID bit on unusual binaries

Interval: 300 seconds
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w04_rootkit_hunter")

# Wazuh rootcheck rule IDs by category
_HIDDEN_PROCESS_RULES = {"510", "511", "512"}
_HIDDEN_PORT_RULES = {"513", "514"}
_BINARY_MODIFIED_RULES = {"550", "551", "552", "553"}
_KERNEL_MODULE_RULES = {"516", "517"}
_TROJAN_RULES = {"510", "511", "512", "513", "514", "515", "516", "517", "518", "519"}

# Known-good kernel modules (baseline)
_KNOWN_GOOD_MODULES: Set[str] = {
    "ext4", "xfs", "btrfs", "nfs", "cifs", "fuse", "overlay",
    "iptable_filter", "ip6table_filter", "nf_conntrack", "br_netfilter",
    "vboxdrv", "vboxnetflt", "kvm", "kvm_intel", "kvm_amd",
    "nvidia", "snd_hda_intel", "iwlwifi", "e1000", "virtio_net",
}

# Paths where SUID is expected
_SUID_WHITELIST: Set[str] = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chfn",
    "/usr/bin/pkexec", "/usr/bin/crontab", "/usr/sbin/unix_chkpwd",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/ping", "/usr/bin/traceroute",
}


class RootkitHunterAgent(BaseAgent):
    """
    Rootkit Detection Agent (W04).
    وكيل كشف الجذور الخفية
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w04_rootkit_hunter",
            description="Detects kernel-level rootkits, hidden processes, and system tampering",
            interval_seconds=300,
            config=config,
            supervisor_channel="soc:endpoint-supervisor",
        )
        # Track alerted items to avoid duplicates
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown = 1800  # 30 min cooldown
        # Known-good process set populated from SCA baselines
        self._known_good_procs: Set[str] = set(
            self._agent_config.get("known_good_processes", [
                "systemd", "sshd", "cron", "rsyslogd", "wazuh-agentd",
                "wazuh-modulesd", "wazuh-execd", "wazuh-syscheckd",
            ])
        )
        self._suid_whitelist: Set[str] = _SUID_WHITELIST | set(
            self._agent_config.get("suid_whitelist", [])
        )

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """Fetch rootcheck and SCA alerts from the last 6 minutes."""
        try:
            rootcheck_query: Dict[str, Any] = {
                "bool": {
                    "should": [
                        {"match": {"rule.groups": "rootcheck"}},
                        {"match": {"rule.groups": "syscheck"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            rootcheck_events = self.os_client.get_events_since(
                index="wazuh-alerts-*", minutes=6, query=rootcheck_query, size=2000,
            )

            sca_query: Dict[str, Any] = {"match": {"rule.groups": "sca"}}
            sca_events = self.os_client.get_events_since(
                index="wazuh-alerts-*", minutes=6, query=sca_query, size=500,
            )

            logger.debug("Collected %d rootcheck and %d SCA events",
                         len(rootcheck_events), len(sca_events))
            return {"rootcheck": rootcheck_events, "sca": sca_events}
        except Exception as exc:
            logger.error("Failed to collect rootkit data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rootcheck_events = data.get("rootcheck", [])
        sca_events = data.get("sca", [])

        for event in rootcheck_events:
            rule_id = str(event.get("rule", {}).get("id", ""))
            rule_desc = event.get("rule", {}).get("description", "")
            host = event.get("agent", {}).get("name", "unknown")
            full_log = event.get("full_log", "")
            data_title = event.get("data", {}).get("title", "")

            # Rule 1: Hidden processes
            if rule_id in _HIDDEN_PROCESS_RULES:
                findings.append({
                    "rule": "hidden_process", "severity": Severity.CRITICAL,
                    "host": host, "rule_id": rule_id,
                    "detail": data_title or rule_desc,
                    "description": f"Hidden process detected on {host}: {data_title or rule_desc}",
                })

            # Rule 2: Hidden ports
            elif rule_id in _HIDDEN_PORT_RULES:
                findings.append({
                    "rule": "hidden_port", "severity": Severity.CRITICAL,
                    "host": host, "rule_id": rule_id,
                    "detail": data_title or rule_desc,
                    "description": f"Hidden port detected on {host}: {data_title or rule_desc}",
                })

            # Rule 3: Modified system binaries
            elif rule_id in _BINARY_MODIFIED_RULES:
                findings.append({
                    "rule": "binary_hash_mismatch", "severity": Severity.CRITICAL,
                    "host": host, "rule_id": rule_id,
                    "detail": data_title or rule_desc,
                    "description": f"System binary modified (hash mismatch) on {host}: {data_title or rule_desc}",
                })

            # Rule 4: Suspicious kernel modules
            elif rule_id in _KERNEL_MODULE_RULES:
                module_name = self._extract_module_name(full_log)
                if module_name and module_name not in _KNOWN_GOOD_MODULES:
                    findings.append({
                        "rule": "suspicious_kernel_module", "severity": Severity.HIGH,
                        "host": host, "module": module_name, "rule_id": rule_id,
                        "description": f"Suspicious kernel module '{module_name}' on {host}",
                    })

            # Rule 5 & 6: LD_PRELOAD / ld.so.preload
            if "ld_preload" in full_log.lower() or "ld.so.preload" in full_log.lower():
                findings.append({
                    "rule": "ld_preload_hijack", "severity": Severity.CRITICAL,
                    "host": host, "detail": full_log[:200],
                    "description": f"LD_PRELOAD hijacking detected on {host}: {full_log[:120]}",
                })

            # Rule 7: Hidden files in /tmp or /dev/shm
            if self._is_hidden_in_sensitive_dir(full_log, data_title):
                findings.append({
                    "rule": "hidden_file_sensitive_dir", "severity": Severity.HIGH,
                    "host": host, "detail": data_title or full_log[:200],
                    "description": f"Hidden file in sensitive directory on {host}: {data_title or full_log[:120]}",
                })

            # Rule 8: SUID on unusual binary (from rootcheck trojans/anomalies)
            suid_path = self._extract_suid_path(full_log, data_title)
            if suid_path and suid_path not in self._suid_whitelist:
                findings.append({
                    "rule": "unusual_suid_binary", "severity": Severity.HIGH,
                    "host": host, "path": suid_path,
                    "description": f"SUID bit set on unusual binary on {host}: {suid_path}",
                })

        # SCA failures that indicate rootkit-related checks failing
        for event in sca_events:
            sca_result = event.get("data", {}).get("result", "")
            sca_title = event.get("data", {}).get("title", "")
            host = event.get("agent", {}).get("name", "unknown")
            if sca_result == "failed" and any(kw in sca_title.lower()
                    for kw in ("rootkit", "kernel", "hidden", "suid", "preload")):
                findings.append({
                    "rule": "sca_rootkit_check_failed", "severity": Severity.MEDIUM,
                    "host": host, "detail": sca_title,
                    "description": f"SCA rootkit-related check failed on {host}: {sca_title}",
                })

        self._events_processed += len(rootcheck_events) + len(sca_events)
        self._metrics.inc_events(len(rootcheck_events) + len(sca_events))
        if findings:
            logger.warning("Detected %d rootkit indicators", len(findings))
        return findings

    @staticmethod
    def _extract_module_name(log_line: str) -> Optional[str]:
        """Extract kernel module name from rootcheck log entry."""
        for token in ("module:", "Module:", "loaded:"):
            if token in log_line:
                parts = log_line.split(token, 1)
                if len(parts) == 2:
                    return parts[1].strip().split()[0].strip("'\"")
        return None

    @staticmethod
    def _is_hidden_in_sensitive_dir(full_log: str, title: str) -> bool:
        combined = (full_log + " " + title).lower()
        has_hidden = "hidden" in combined or combined.count("/.") > 0
        has_sensitive = any(d in combined for d in ("/tmp/", "/dev/shm/", "/var/tmp/"))
        return has_hidden and has_sensitive

    @staticmethod
    def _extract_suid_path(full_log: str, title: str) -> Optional[str]:
        combined = full_log + " " + title
        if "suid" not in combined.lower() and "SUID" not in combined:
            return None
        for token in combined.split():
            if token.startswith("/") and not token.endswith(":"):
                return token.strip("'\".,;")
        return None

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        now = time.time()
        for f in findings:
            cache_key = f"{f['rule']}:{f.get('host')}:{f.get('detail', f.get('path', ''))[:80]}"
            if now - self._alerted_cache.get(cache_key, 0) < self._alert_cooldown:
                continue
            actions.append({"type": "alert", "finding": f, "cache_key": cache_key})
            # All rootkit findings are worth escalating
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
                    severity=f["severity"],
                    title=f"Rootkit: {f['rule'].replace('_', ' ').title()}",
                    details={"host": f.get("host"), "detail": f.get("detail", f.get("path", "")),
                             "description": f["description"]},
                    agent_name=self.name,
                )
                if sent:
                    alerts_sent += 1
                    self._metrics.inc_alerts(f["severity"].name)
                    self._alerted_cache[action["cache_key"]] = time.time()

            elif action["type"] == "escalate":
                self.report_to_supervisor({
                    "type": "rootkit_detection", "rule": f["rule"],
                    "severity": f["severity"].name, "host": f.get("host"),
                    "description": f["description"],
                })
                escalations += 1

            elif action["type"] == "log_incident":
                try:
                    self.os_client.index_document("soc-rootkit-incidents", {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent_name": self.name, "rule": f["rule"],
                        "severity": f["severity"].name, "host": f.get("host"),
                        "description": f["description"],
                    })
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log rootkit incident: %s", exc)

        # Prune stale cache entries
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
    agent = RootkitHunterAgent()
    agent.run_loop()
