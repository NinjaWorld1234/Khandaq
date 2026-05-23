"""
SOC Platform - Worker Agent W17: YARA Rule Scanner
وكيل ماسح قواعد يارا

Monitors new files detected by Wazuh FIM (File Integrity Monitoring) from
OpenSearch and performs string/regex pattern matching against known malware
families: Mimikatz, webshells, crypto miners, ransomware notes, backdoors.

Since yara-python may not be available in all environments, this agent uses
built-in re module for pattern matching against file paths, names, and
Wazuh FIM metadata fields (syscheck.sha256, syscheck.path, etc.).

Severity: CRITICAL for known malware, HIGH for suspicious patterns.
Interval: 60 seconds
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w17_yara_scanner")

# --------------------------------------------------------------------------
# Malware signature patterns (regex / plain string)
# --------------------------------------------------------------------------

YARA_RULES: list[dict[str, Any]] = [
    # --- Mimikatz ---
    {"name": "Mimikatz_Credential_Dumper", "family": "mimikatz", "severity": Severity.CRITICAL,
     "patterns": [r"sekurlsa::logonpasswords", r"lsadump::sam", r"kerberos::golden",
                  r"mimikatz\.exe", r"mimilib\.dll", r"sekurlsa::wdigest",
                  r"privilege::debug"]},
    # --- Web Shells ---
    {"name": "Generic_WebShell", "family": "webshell", "severity": Severity.CRITICAL,
     "patterns": [r"(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|\$_(?:POST|GET|REQUEST))",
                  r"<%\s*(?:eval|execute)\s*request", r"Runtime\.getRuntime\(\)\.exec",
                  r"c99shell|r57shell|b374k|weevely|wso\s*shell",
                  r"phpspy|alfa\s*shell|p0wny.*shell"]},
    # --- Crypto Miners ---
    {"name": "CryptoMiner_Strings", "family": "cryptominer", "severity": Severity.HIGH,
     "patterns": [r"stratum\+tcp://", r"xmrig|xmr-stak|cpuminer|cgminer|bfgminer",
                  r"monero.*wallet|pool\.minergate\.com|coinhive\.min\.js",
                  r"cryptonight|randomx.*mining"]},
    # --- Ransomware ---
    {"name": "Ransomware_Note", "family": "ransomware", "severity": Severity.CRITICAL,
     "patterns": [r"your\s+files\s+(?:have\s+been|are)\s+encrypted",
                  r"pay\s+(?:bitcoin|btc|ransom)", r"decrypt(?:ion)?\s+tool",
                  r"\.locked|\.crypt|\.enc(?:rypted)?|\.wannacry|\.cerber",
                  r"READ_?ME_?(?:TO_?DECRYPT|RANSOM)"]},
    # --- Backdoors & RATs ---
    {"name": "Backdoor_Indicators", "family": "backdoor", "severity": Severity.CRITICAL,
     "patterns": [r"cobalt\s*strike|beacon\.dll|cobaltstrike",
                  r"meterpreter|metasploit|reverse_tcp",
                  r"ncat\.exe|nc\.exe.*-e\s+cmd",
                  r"empire|powershell_empire|invoke-empire"]},
    # --- Suspicious Paths ---
    {"name": "Suspicious_File_Location", "family": "suspicious_path", "severity": Severity.HIGH,
     "patterns": [r"\\(?:temp|tmp)\\[^\\]+\.(?:exe|dll|ps1|bat|vbs|js|hta|scr)",
                  r"/tmp/\.[\w]+",  # hidden file in /tmp
                  r"(?:recycle\.bin|\\recycler\\).*\.(?:exe|dll)",
                  r"\\windows\\fonts\\.*\.(?:exe|dll|ps1)"]},
]

# Compile all patterns once at module level for performance
_COMPILED_RULES: list[dict[str, Any]] = []
for _rule in YARA_RULES:
    compiled = []
    for pat in _rule["patterns"]:
        try:
            compiled.append(re.compile(pat, re.IGNORECASE))
        except re.error as e:
            logger.warning("Failed to compile pattern '%s': %s", pat, e)
    _COMPILED_RULES.append({**_rule, "_compiled": compiled})


class YaraScannerAgent(BaseAgent):
    """
    YARA Rule Scanner Agent (W17).
    Scans Wazuh FIM events for known malware patterns using regex matching.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w17_yara_scanner",
            description="YARA-style pattern scanner for Wazuh FIM file events",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:endpoint-supervisor",
        )
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")
        self._scan_window_min: int = self._agent_config.get("scan_window_min", 2)
        self._alerted_cache: dict[str, float] = {}
        self._alert_cooldown: int = 900  # 15 min cooldown per file+rule
        self._total_scanned: int = 0
        self._total_matched: int = 0

    # ------------------------------------------------------------------
    # Collect: fetch FIM syscheck events from OpenSearch
    # ------------------------------------------------------------------

    def collect(self) -> Optional[list[dict[str, Any]]]:
        """Fetch Wazuh FIM (syscheck) events from the last scan window."""
        try:
            query = {"bool": {"must": [
                {"match": {"rule.groups": "syscheck"}},
                {"exists": {"field": "syscheck.path"}},
            ]}}
            events = self.os_client.get_events_since(
                index=self._alert_index,
                minutes=self._scan_window_min,
                query=query,
                size=500,
            )
            logger.info("Collected %d FIM events for YARA scanning", len(events))
            return events
        except Exception as exc:
            logger.error("Failed to collect FIM events: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze: match events against YARA-style patterns
    # ------------------------------------------------------------------

    def analyze(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Scan each FIM event against all compiled YARA rules."""
        findings: list[dict[str, Any]] = []
        for event in data:
            self._total_scanned += 1
            syscheck = event.get("syscheck", {})
            file_path = syscheck.get("path", "")
            diff_content = syscheck.get("diff", "")
            event_text = syscheck.get("event", "")
            # Build a combined text blob to scan
            scan_text = f"{file_path} {diff_content} {event_text}"
            rule_desc = event.get("rule", {}).get("description", "")
            scan_text += f" {rule_desc}"

            for rule in _COMPILED_RULES:
                for compiled_re in rule["_compiled"]:
                    match = compiled_re.search(scan_text)
                    if match:
                        self._total_matched += 1
                        findings.append({
                            "rule_name": rule["name"],
                            "family": rule["family"],
                            "severity": rule["severity"],
                            "matched_pattern": match.group(0),
                            "file_path": file_path,
                            "sha256": syscheck.get("sha256_after", "N/A"),
                            "agent_id": event.get("agent", {}).get("id", "N/A"),
                            "agent_name": event.get("agent", {}).get("name", "N/A"),
                            "timestamp": event.get("@timestamp", ""),
                        })
                        break  # one match per rule per event is enough

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        if findings:
            logger.warning("YARA scan: %d matches in %d events", len(findings), len(data))
        return findings

    # ------------------------------------------------------------------
    # Decide: build alert and logging actions
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Create alert and incident-log actions, respecting cooldowns."""
        actions: list[dict[str, Any]] = []
        now = time.time()
        for finding in findings:
            cache_key = f"{finding['rule_name']}:{finding['file_path']}"
            if now - self._alerted_cache.get(cache_key, 0.0) < self._alert_cooldown:
                continue
            actions.append({
                "type": "alert",
                "severity": finding["severity"],
                "title": f"YARA Match: {finding['rule_name']}",
                "details": {
                    "family": finding["family"],
                    "file_path": finding["file_path"],
                    "matched_pattern": finding["matched_pattern"],
                    "sha256": finding["sha256"],
                    "endpoint_agent": finding["agent_name"],
                },
                "cache_key": cache_key,
            })
            actions.append({"type": "log_incident", "finding": finding})
        return actions

    # ------------------------------------------------------------------
    # Act: send alerts, log incidents, report to supervisor
    # ------------------------------------------------------------------

    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """Execute alert and logging actions."""
        alerts_sent = 0
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
                    self._alerted_cache[action["cache_key"]] = time.time()
            elif action["type"] == "log_incident":
                try:
                    f = action["finding"]
                    self.os_client.index_document("soc-yara-matches", document={
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent_name": self.name,
                        "rule_name": f["rule_name"], "family": f["family"],
                        "severity": f["severity"].name,
                        "file_path": f["file_path"], "sha256": f["sha256"],
                        "matched_pattern": f["matched_pattern"],
                        "endpoint_agent": f["agent_name"],
                    })
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log YARA incident: %s", exc)

        # Prune cooldown cache
        cutoff = time.time() - self._alert_cooldown * 2
        self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent:
            self.report_to_supervisor({
                "type": "yara_scan_report",
                "alerts_sent": alerts_sent, "incidents_logged": incidents_logged,
                "total_scanned": self._total_scanned,
                "total_matched": self._total_matched,
            })
        return {"alerts_sent": alerts_sent, "incidents_logged": incidents_logged}


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
    agent = YaraScannerAgent()
    agent.run_loop()
