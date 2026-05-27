"""
SOC Platform - Worker Agent W18: Sandbox / Attachment Analyzer
وكيل تحليل الصناديق الرملية والمرفقات

Monitors file download events and email attachments from Wazuh/Zeek:
- Extension mismatch (exe disguised as pdf), double extensions (.pdf.exe)
- Known malicious extensions (.scr, .hta, .js, .vbs, .wsf, .pif)
- Files from suspicious source directories (temp, downloads, appdata)
- Office documents with macros (Wazuh alerts for macro-related events)
- Hash lookups against known malware hash lists in OpenSearch

Interval: 60 seconds
"""

from __future__ import annotations

import logging
import re
import time
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w18_sandbox_analyzer")

# Dangerous executable extensions
_MALICIOUS_EXTS: set[str] = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".msi", ".msp",
    ".ps1", ".psm1", ".psd1", ".reg",
}

# Document extensions that commonly carry macros
_MACRO_DOC_EXTS: set[str] = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".ppam"}

# Document extensions (benign-looking) used in extension mismatch attacks
_DOCUMENT_EXTS: set[str] = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".jpg", ".png"}

# Suspicious source directories (lowered for comparison)
_SUSPICIOUS_DIRS: list[re.Pattern[str]] = [
    re.compile(r"\\(?:temp|tmp)\\", re.IGNORECASE),
    re.compile(r"\\appdata\\(?:local|roaming)\\temp\\", re.IGNORECASE),
    re.compile(r"\\downloads\\", re.IGNORECASE),
    re.compile(r"/tmp/", re.IGNORECASE),
    re.compile(r"\\public\\", re.IGNORECASE),
    re.compile(r"\\programdata\\", re.IGNORECASE),
]

# Double extension pattern: e.g. report.pdf.exe, invoice.doc.scr
_DOUBLE_EXT_RE = re.compile(
    r"\.\w{2,5}\.(?:exe|scr|pif|bat|cmd|vbs|js|hta|ps1|com|wsf)$",
    re.IGNORECASE,
)


class SandboxAnalyzerAgent(BaseAgent):
    """
    Sandbox / Attachment Analyzer Agent (W18).
    Analyzes file metadata for malicious traits without executing files.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w18_sandbox_analyzer",
            description="Analyzes file downloads and attachments for malicious indicators",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:endpoint-supervisor",
        )
        self._wazuh_index = self._agent_config.get("wazuh_index", "wazuh-alerts-*")
        self._zeek_index = self._agent_config.get("zeek_index", "zeek-*")
        self._hash_index = self._agent_config.get("hash_index", "soc-malware-hashes")
        self._scan_window_min: int = self._agent_config.get("scan_window_min", 2)
        self._alerted_cache: dict[str, float] = {}
        self._alert_cooldown: int = 600
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[dict[str, Any]]:
        """Gather file-related events from Wazuh and Zeek."""
        try:
            # Wazuh FIM and file download events
            fim_query = {"bool": {"should": [
                {"match": {"rule.groups": "syscheck"}},
                {"match": {"rule.groups": "attachment"}},
                {"match": {"data.type": "file"}},
            ], "minimum_should_match": 1}}
            fim_events = self.os_client.get_events_since(
                index=self._wazuh_index, minutes=self._scan_window_min,
                query=fim_query, size=10000,
            )
            # Zeek file extraction events
            zeek_query = {"bool": {"must": [{"exists": {"field": "filename"}}]}}
            zeek_events = self.os_client.get_events_since(
                index=self._zeek_index, minutes=self._scan_window_min,
                query=zeek_query, size=10000,
            )
            logger.info("Collected %d Wazuh + %d Zeek file events",
                        len(fim_events), len(zeek_events))
            return {"wazuh_events": fim_events, "zeek_events": zeek_events}
        except Exception as exc:
            logger.error("Failed to collect file events: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Run all detection checks on collected file events."""
        findings: list[dict[str, Any]] = []
        all_hashes: list[str] = []

        # Analyze Wazuh events
        for event in data.get("wazuh_events", []):
            try:
                syscheck = event.get("syscheck", {})
                file_path = syscheck.get("path", (event.get("data") or {}).get("path", ""))
                file_hash = syscheck.get("sha256_after", "")
                host = (event.get("agent") or {}).get("name", "unknown")
                if file_hash:
                    all_hashes.append(file_hash)
                findings.extend(self._check_file(file_path, file_hash, event, "wazuh", host))
            except Exception as e:
                logger.warning("Error analyzing Wazuh file event: %s", e)

        # Analyze Zeek events
        for event in data.get("zeek_events", []):
            try:
                file_path = event.get("filename", "")
                file_hash = event.get("sha256", event.get("md5", ""))
                host = event.get("id.orig_h", "unknown")
                if file_hash:
                    all_hashes.append(file_hash)
                findings.extend(self._check_file(file_path, file_hash, event, "zeek", host))
            except Exception as e:
                logger.warning("Error analyzing Zeek file event: %s", e)

        # Batch check hashes against known malware list
        if all_hashes:
            known_hits = self._check_hashes_bulk(all_hashes)
            for hit_hash, malware_name in known_hits.items():
                findings.append({
                    "check": "known_malware_hash",
                    "severity": Severity.CRITICAL,
                    "file_hash": hit_hash,
                    "malware_name": malware_name,
                    "description": f"File hash matches known malware: {malware_name}",
                })

        total = len(data.get("wazuh_events", [])) + len(data.get("zeek_events", []))
        self._events_processed += total
        self._metrics.inc_events(total)
        return findings

    def _check_file(self, path: str, file_hash: str,
                    event: dict[str, Any], source: str, host: str) -> list[dict[str, Any]]:
        """Run heuristic checks on a single file event."""
        results: list[dict[str, Any]] = []
        if not path:
            return results
        path_lower = path.lower()

        # 1. Double extension detection
        if _DOUBLE_EXT_RE.search(path_lower):
            results.append({
                "check": "double_extension", "severity": Severity.HIGH,
                "file_path": path, "source": source, "file_hash": file_hash, "host": host,
                "description": f"Double extension detected: {path}",
            })

        # 2. Known malicious extension
        ext = self._get_extension(path_lower)
        if ext in _MALICIOUS_EXTS:
            for sus_dir in _SUSPICIOUS_DIRS:
                if sus_dir.search(path):
                    results.append({
                        "check": "malicious_ext_suspicious_dir", "severity": Severity.HIGH,
                        "file_path": path, "extension": ext, "source": source,
                        "file_hash": file_hash, "host": host,
                        "description": f"Executable ({ext}) in suspicious directory: {path}",
                    })
                    break

        # 3. Macro-enabled Office document
        if ext in _MACRO_DOC_EXTS:
            results.append({
                "check": "macro_document", "severity": Severity.MEDIUM,
                "file_path": path, "extension": ext, "source": source,
                "file_hash": file_hash, "host": host,
                "description": f"Macro-enabled Office document detected: {path}",
            })

        # 4. Extension mismatch: MIME-type or rule description hints at executable
        rule_desc = (event.get("rule") or {}).get("description", "").lower()
        if ext in _DOCUMENT_EXTS and ("executable" in rule_desc or "pe32" in rule_desc):
            results.append({
                "check": "extension_mismatch", "severity": Severity.CRITICAL,
                "file_path": path, "extension": ext, "source": source,
                "file_hash": file_hash, "host": host,
                "description": f"Extension mismatch – {ext} file is actually executable: {path}",
            })

        return results

    def _check_hashes_bulk(self, hashes: list[str]) -> dict[str, str]:
        """Look up file hashes against the known malware hash index."""
        hits: dict[str, str] = {}
        try:
            query = {"bool": {"must": [
                {"terms": {"hash": hashes}},
            ]}}
            results = self.os_client.search(index=self._hash_index, body={
                "query": query, "size": len(hashes), "_source": ["hash", "malware_name"],
            })
            for hit in (results.get("hits") or {}).get("hits", []):
                src = hit.get("_source", {})
                hits[src.get("hash", "")] = src.get("malware_name", "unknown")
        except Exception as exc:
            logger.debug("Hash lookup failed (index may not exist): %s", exc)
        return hits

    @staticmethod
    def _get_extension(path: str) -> str:
        """Extract the final file extension from a path."""
        path_sep_pos = max(path.rfind("\\"), path.rfind("/"))
        dot_pos = path.rfind(".")
        if dot_pos > path_sep_pos:
            return path[dot_pos:]
        return ""

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build alert actions, respecting cooldown to avoid duplicates."""
        actions: list[dict[str, Any]] = []
        now = time.time()
        for f in findings:
            cache_key = f"{f['check']}:{f.get('file_path', f.get('file_hash', ''))}"
            if now - self._alerted_cache.get(cache_key, 0.0) < self._alert_cooldown:
                continue
            actions.append({
                "type": "alert", "severity": f["severity"],
                "title": f"File Analysis: {f['check'].replace('_', ' ').title()}",
                "details": {k: v for k, v in f.items() if k != "severity"},
                "cache_key": cache_key,
            })
            actions.append({"type": "log_incident", "finding": f})
        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """Send alerts and log incidents."""
        alerts_sent = 0
        incidents_logged = 0
        for action in actions:
            if action["type"] == "alert":
                sent = self.alerter.send_alert(
                    severity=action["severity"], title=action["title"],
                    details=action["details"], agent_name=self.name,
                )
                if sent:
                    alerts_sent += 1
                    self._metrics.inc_alerts(action["severity"].name)
                    with self._cache_lock:

                        self._alerted_cache[action["cache_key"]] = time.time()

                    # Forward to supervisor for potential correlation and escalation
                    self.report_to_supervisor({
                        "type": "sandbox_analysis_alert",
                        "severity": action["severity"],
                        "agent": action["details"].get("host", ""),
                        "details": action["details"]
                    })
            elif action["type"] == "log_incident":
                try:
                    self.os_client.index_document("soc-file-analysis", document={
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent_name": self.name,
                        **{k: (v.name if isinstance(v, Severity) else v)
                           for k, v in action["finding"].items()},
                    })
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log file analysis incident: %s", exc)

        if alerts_sent:
            self.report_to_supervisor({
                "type": "file_analysis_report",
                "alerts_sent": alerts_sent, "incidents_logged": incidents_logged,
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
    agent = SandboxAnalyzerAgent()
    agent.run_loop()
