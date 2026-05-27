# SOC Platform - Worker Agent W03: Ransomware Canary
# وكيل الإنذار المبكر من فيروسات الفدية - ملفات الطُعم
"""
Ransomware Early Warning Agent (Canary Files)
=============================================

Detects ransomware activity through multiple indicators:

1. **Canary files**: Hidden marker files placed in monitored directories.
   Any modification detected via Wazuh FIM triggers CRITICAL alerts.
2. **Volume Shadow Copy deletion**: ``vssadmin.exe delete shadows`` commands.
3. **Boot configuration changes**: ``bcdedit.exe /set safeboot`` commands.
4. **Mass file extension changes**: Bulk renames to known ransomware
   extensions (.encrypted, .locked, .cry, .crypt, etc.).
5. **Known ransomware process names**: Pattern matching against a curated
   list of ransomware binaries.

On canary file modification the agent immediately requests host isolation
via the Wazuh Active Response API.

Interval: 30 seconds (must react fast!)
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
import re
import time
import threading
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.wazuh_client import WazuhClient

logger = logging.getLogger("soc.agent.w03_ransomware_canary")

# ---------------------------------------------------------------------------
# Constants / ثوابت
# ---------------------------------------------------------------------------

# Default directories in which canary files are planted
# مسارات المجلدات الافتراضية لملفات الطُعم
DEFAULT_CANARY_DIRS: list[str] = [
    "/var/log",
    "/tmp",
    "/home",
    "/opt",
    "/root",
    "/srv",
    "/etc",
    "C:\\Users\\Public\\Documents",
    "C:\\ProgramData",
]

# Name of canary files (prefixed with dot to be hidden on Linux)
CANARY_FILENAME = ".soc_canary_sentinel.dat"

# Wazuh alert indices in OpenSearch / فهارس تنبيهات وازوه
WAZUH_ALERTS_INDEX = "wazuh-alerts-*"

# Known ransomware file extensions / امتدادات ملفات الفدية المعروفة
RANSOMWARE_EXTENSIONS: set[str] = {
    ".encrypted", ".locked", ".cry", ".crypt", ".crypto",
    ".locky", ".cerber", ".zepto", ".thor", ".aaa",
    ".abc", ".xyz", ".zzz", ".micro", ".ttt",
    ".mp3", ".vvv", ".ccc", ".ecc", ".ezz",
    ".exx", ".xtbl", ".enc", ".wallet",
    ".dharma", ".onion", ".bip", ".gamma", ".combo",
    ".arrow", ".phobos", ".makop", ".devos", ".roger",
    ".eight", ".money", ".ransom", ".WNCRY", ".wcry",
}

# Known ransomware process name patterns / أنماط أسماء عمليات الفدية المعروفة
RANSOMWARE_PROCESS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"wanna(?:cry|crypt)", re.IGNORECASE),
    re.compile(r"petya|notpetya|goldeneye", re.IGNORECASE),
    re.compile(r"locky|cerber|cryptolocker", re.IGNORECASE),
    re.compile(r"ryuk|conti|lockbit|blackcat", re.IGNORECASE),
    re.compile(r"revil|sodinokibi|darkside", re.IGNORECASE),
    re.compile(r"maze|egregor|clop|hive", re.IGNORECASE),
    re.compile(r"blackmatter|avoslocker|blackbasta", re.IGNORECASE),
    re.compile(r"phobos|dharma|makop|stop/djvu", re.IGNORECASE),
    re.compile(r"ransomexx|ragnar_locker|babuk", re.IGNORECASE),
]

# FIM rule groups / مجموعات قواعد مراقبة سلامة الملفات
FIM_RULE_GROUP = "syscheck"


class RansomwareCanaryAgent(BaseAgent):
    """
    Ransomware Early Warning Agent using canary files and behavioral indicators.
    وكيل الإنذار المبكر من فيروسات الفدية باستخدام ملفات الطُعم والمؤشرات السلوكية
    """

    def __init__(
        self,
        config: Optional[SOCConfig] = None,
        canary_dirs: Optional[list[str]] = None,
    ) -> None:
        super().__init__(
            name="w03_ransomware_canary",
            description="Ransomware Early Warning Agent – canary files and behavioral detection",
            interval_seconds=30,
            config=config,
            supervisor_channel="soc:endpoint-supervisor",
        )
        # Wazuh Client for Active Response
        self._wazuh: Optional[WazuhClient] = None
        self._cache_lock = threading.Lock()

        # Canary directories – configurable via constructor or config file
        # مجلدات ملفات الطُعم - قابلة للتخصيص
        self.canary_dirs: list[str] = (
            canary_dirs
            or self._agent_config.get("canary_dirs", DEFAULT_CANARY_DIRS)
        )

        # Registry of deployed canary files: path → expected SHA-256 hash
        # سجل ملفات الطُعم المنشورة: المسار → التجزئة المتوقعة
        self.canary_registry: dict[str, str] = {}

        # Track the last query timestamp to avoid reprocessing alerts
        self._last_check_minutes: int = 1  # look-back window in minutes

        # Extension change counter per host (for detecting mass renames)
        self._extension_change_counts: dict[str, int] = {}
        self._extension_change_window_start: float = time.time()
        self._extension_change_threshold: int = self._agent_config.get(
            "mass_rename_threshold", 20,
        )

    @property
    def wazuh(self) -> WazuhClient:
        """Lazy init Wazuh Client."""
        if self._wazuh is None:
            with self._cache_lock:
                if self._wazuh is None:
                    self._wazuh = WazuhClient(self.config)
        return self._wazuh

    # ------------------------------------------------------------------
    # Canary file management / إدارة ملفات الطُعم
    # ------------------------------------------------------------------
    def setup_canary_files(self) -> dict[str, str]:
        """
        Create canary files in all configured directories.

        Each canary file contains a unique sentinel string whose SHA-256
        hash is recorded.  Any modification to the file will change the
        hash, triggering an alert.

        Returns:
            dict mapping file path → expected SHA-256 hash.
        """
        registry: dict[str, str] = {}

        for directory in self.canary_dirs:
            if not os.path.isdir(directory):
                logger.debug("Canary dir does not exist, skipping: %s", directory)
                continue

            canary_path = os.path.join(directory, CANARY_FILENAME)
            sentinel = (
                f"SOC-CANARY-SENTINEL|{canary_path}|"
                f"{datetime.datetime.now(datetime.timezone.utc).isoformat()}|"
                f"{os.urandom(16).hex()}"
            )

            try:
                # إصلاح V3-SEC-CRIT-01: Ensure file is writable before opening if it exists
                if os.path.exists(canary_path):
                    try:
                        os.chmod(canary_path, 0o600)
                    except OSError:
                        pass

                with open(canary_path, "w", encoding="utf-8") as fh:
                    fh.write(sentinel)

                # Make read-only to increase suspicion on modification
                try:
                    os.chmod(canary_path, 0o444)
                except OSError:
                    pass  # Windows may not support chmod the same way

                expected_hash = hashlib.sha256(sentinel.encode()).hexdigest()
                registry[canary_path] = expected_hash
                logger.info("✅ Canary deployed: %s (hash=%s…)", canary_path, expected_hash[:12])

            except PermissionError:
                logger.warning("Permission denied creating canary: %s", canary_path)
            except OSError as exc:
                logger.error("Failed to create canary %s: %s", canary_path, exc)

        self.canary_registry = registry
        logger.info("Canary setup complete – %d canary files deployed", len(registry))
        return registry

    # ------------------------------------------------------------------
    # Collect: gather recent events / جمع: الأحداث الأخيرة
    # ------------------------------------------------------------------
    def collect(self) -> dict[str, Any]:
        """
        Collect recent FIM, process-creation, and command-line events
        from OpenSearch that may indicate ransomware activity.
        """
        # Deploy canaries on first run if not already done
        if not self.canary_registry:
            self.setup_canary_files()

        data: dict[str, Any] = {
            "fim_events": [],
            "shadow_copy_events": [],
            "boot_config_events": [],
            "process_events": [],
        }

        lookback = self._last_check_minutes

        # 1. FIM events on canary files
        canary_paths = list(self.canary_registry.keys())
        if canary_paths:
            try:
                fim_query = {
                    "bool": {
                        "must": [
                            {"term": {"rule.groups": FIM_RULE_GROUP}},
                            {"terms": {"syscheck.path": canary_paths}},
                        ]
                    }
                }
                data["fim_events"] = self.os_client.get_events_since(
                    index=WAZUH_ALERTS_INDEX, minutes=lookback,
                    query=fim_query, size=10000,
                )
            except Exception as exc:
                logger.error("FIM canary query failed: %s", exc)

        # 2. Shadow copy deletion commands (vssadmin, wmic, PowerShell)
        try:
            shadow_query = {
                "bool": {
                    "should": [
                        {"bool": {"must": [
                            {"match_phrase": {"data.win.eventdata.commandLine": "vssadmin"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "delete"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "shadows"}},
                        ]}},
                        {"bool": {"must": [
                            {"match_phrase": {"data.win.eventdata.commandLine": "wmic"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "shadowcopy"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "delete"}},
                        ]}},
                        {"bool": {"must": [
                            {"match_phrase": {"data.win.eventdata.commandLine": "Get-WmiObject"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "Win32_ShadowCopy"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "Delete"}},
                        ]}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            data["shadow_copy_events"] = self.os_client.get_events_since(
                index=WAZUH_ALERTS_INDEX, minutes=lookback,
                query=shadow_query, size=10000,
            )
        except Exception as exc:
            logger.error("Shadow copy query failed: %s", exc)

        # 3. Boot configuration changes (bcdedit safeboot / recovery disabled)
        try:
            boot_query = {
                "bool": {
                    "should": [
                        {"bool": {"must": [
                            {"match_phrase": {"data.win.eventdata.commandLine": "bcdedit"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "safeboot"}},
                        ]}},
                        {"bool": {"must": [
                            {"match_phrase": {"data.win.eventdata.commandLine": "bcdedit"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "recoveryenabled"}},
                            {"match_phrase": {"data.win.eventdata.commandLine": "no"}},
                        ]}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            data["boot_config_events"] = self.os_client.get_events_since(
                index=WAZUH_ALERTS_INDEX, minutes=lookback,
                query=boot_query, size=10000,
            )
        except Exception as exc:
            logger.error("Boot config query failed: %s", exc)

        # 4. Process creation events (Sysmon Event ID 1) for ransomware name matching
        try:
            proc_query = {"term": {"data.win.system.eventID": "1"}}
            data["process_events"] = self.os_client.get_events_since(
                index=WAZUH_ALERTS_INDEX, minutes=lookback,
                query=proc_query, size=10000,
            )
        except Exception as exc:
            logger.error("Process event query failed: %s", exc)

        # 5. Mass extension changes via FIM
        try:
            ext_terms = [f"*{ext}" for ext in list(RANSOMWARE_EXTENSIONS)[:30]]
            ext_query = {
                "bool": {
                    "must": [{"term": {"rule.groups": FIM_RULE_GROUP}}],
                    "should": [{"wildcard": {"syscheck.path": ext}} for ext in ext_terms],
                    "minimum_should_match": 1,
                }
            }
            data["extension_events"] = self.os_client.get_events_since(
                index=WAZUH_ALERTS_INDEX, minutes=lookback,
                query=ext_query, size=10000,
            )
        except Exception as exc:
            logger.error("Extension change query failed: %s", exc)

        return data

    # ------------------------------------------------------------------
    # Analyze: detect ransomware indicators / تحليل: كشف مؤشرات الفدية
    # ------------------------------------------------------------------
    def analyze(self, data: Any) -> list[dict[str, Any]]:
        """
        Analyze collected events for ransomware indicators.
        Returns a list of findings dicts.
        """
        findings: list[dict[str, Any]] = []

        # --- Canary FIM alerts ---
        for event in data.get("fim_events", []):
            try:
                syscheck_obj = event.get("syscheck") or {}
                canary_path = syscheck_obj.get("path", "unknown")
                agent_info = event.get("agent") or {}
                findings.append({
                    "type": "canary_modified",
                    "canary_path": canary_path,
                    "hostname": agent_info.get("name", "unknown"),
                    "wazuh_agent_id": agent_info.get("id", "unknown"),
                    "raw_event": event,
                })
            except Exception as e:
                logger.warning("Error processing canary fim event: %s", e)

        # --- Shadow copy deletion ---
        for event in data.get("shadow_copy_events", []):
            try:
                agent_info = event.get("agent") or {}
                data_obj = event.get("data") or {}
                win_obj = data_obj.get("win") or {}
                ev_obj = win_obj.get("eventdata") or {}
                cmd = ev_obj.get("commandLine", "N/A")
                findings.append({
                    "type": "shadow_copy_deleted",
                    "hostname": agent_info.get("name", "unknown"),
                    "command_line": cmd,
                    "raw_event": event,
                })
            except Exception as e:
                logger.warning("Error processing shadow copy event: %s", e)

        # --- Boot config changes ---
        for event in data.get("boot_config_events", []):
            try:
                agent_info = event.get("agent") or {}
                data_obj = event.get("data") or {}
                win_obj = data_obj.get("win") or {}
                ev_obj = win_obj.get("eventdata") or {}
                cmd = ev_obj.get("commandLine", "N/A")
                findings.append({
                    "type": "boot_config_tampered",
                    "hostname": agent_info.get("name", "unknown"),
                    "command_line": cmd,
                    "raw_event": event,
                })
            except Exception as e:
                logger.warning("Error processing boot config event: %s", e)

        # --- Known ransomware process names ---
        for event in data.get("process_events", []):
            try:
                data_obj = event.get("data") or {}
                win_obj = data_obj.get("win") or {}
                ed = win_obj.get("eventdata") or {}
                process_name = ed.get("image", "")
                original_name = ed.get("originalFileName", "")
                command_line = ed.get("commandLine", "")
                check_strings = [s for s in [process_name, original_name, command_line] if s]
                for pattern in RANSOMWARE_PROCESS_PATTERNS:
                    if any(pattern.search(s) for s in check_strings):
                        agent_obj = event.get("agent") or {}
                        findings.append({
                            "type": "ransomware_process",
                            "hostname": agent_obj.get("name", "unknown"),
                            "process_name": process_name,
                            "command_line": command_line,
                            "matched_pattern": pattern.pattern,
                            "raw_event": event,
                        })
                        break
            except Exception as e:
                logger.warning("Error processing ransomware process event: %s", e)

        # --- Mass extension changes ---
        # Reset counter window every 5 minutes
        if time.time() - self._extension_change_window_start > 300:
            self._extension_change_counts.clear()
            self._extension_change_window_start = time.time()

        for event in data.get("extension_events", []):
            try:
                agent_obj = event.get("agent") or {}
                hostname = agent_obj.get("name", "unknown")
                self._extension_change_counts[hostname] = (
                    self._extension_change_counts.get(hostname, 0) + 1
                )
            except Exception as e:
                logger.warning("Error processing extension event: %s", e)

        for hostname, count in list(self._extension_change_counts.items()):
            try:
                if count >= self._extension_change_threshold:
                    findings.append({
                        "type": "mass_extension_change",
                        "hostname": hostname,
                        "change_count": count,
                        "threshold": self._extension_change_threshold,
                    })
                    self._extension_change_counts[hostname] = 0  # reset after detection
            except Exception as e:
                logger.warning("Error processing extension counts: %s", e)

        return findings

    # ------------------------------------------------------------------
    # Decide: determine alert severity / قرار: تحديد خطورة التنبيه
    # ------------------------------------------------------------------
    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Map each finding to an alert action with severity, title and MITRE info.
        """
        actions: list[dict[str, Any]] = []

        for finding in findings:
            ftype = finding["type"]

            if ftype == "canary_modified":
                actions.append({
                    "alert": True,
                    "severity": Severity.CRITICAL,
                    "title": "🚨 RANSOMWARE CANARY FILE MODIFIED",
                    "details": {
                        "canary_path": finding["canary_path"],
                        "hostname": finding["hostname"],
                        "mitre_technique": "T1486 - Data Encrypted for Impact",
                        "mitre_tactic": "Impact",
                    },
                    "isolate_host": True,
                    "wazuh_agent_id": finding["wazuh_agent_id"],
                })

            elif ftype == "shadow_copy_deleted":
                actions.append({
                    "alert": True,
                    "severity": Severity.HIGH,
                    "title": "⚠️ VOLUME SHADOW COPY DELETION DETECTED",
                    "details": {
                        "hostname": finding["hostname"],
                        "command_line": finding["command_line"],
                        "mitre_technique": "T1490 - Inhibit System Recovery",
                        "mitre_tactic": "Impact",
                    },
                })

            elif ftype == "boot_config_tampered":
                actions.append({
                    "alert": True,
                    "severity": Severity.HIGH,
                    "title": "⚠️ BOOT CONFIGURATION TAMPERED",
                    "details": {
                        "hostname": finding["hostname"],
                        "command_line": finding["command_line"],
                        "mitre_technique": "T1490 - Inhibit System Recovery",
                        "mitre_tactic": "Impact",
                    },
                })

            elif ftype == "ransomware_process":
                actions.append({
                    "alert": True,
                    "severity": Severity.CRITICAL,
                    "title": "🚨 KNOWN RANSOMWARE PROCESS DETECTED",
                    "details": {
                        "hostname": finding["hostname"],
                        "process_name": finding["process_name"],
                        "command_line": finding["command_line"],
                        "matched_pattern": finding["matched_pattern"],
                        "mitre_technique": "T1204 - User Execution",
                        "mitre_tactic": "Execution",
                    },
                })

            elif ftype == "mass_extension_change":
                actions.append({
                    "alert": True,
                    "severity": Severity.CRITICAL,
                    "title": "🚨 MASS FILE EXTENSION CHANGE DETECTED",
                    "details": {
                        "hostname": finding["hostname"],
                        "change_count": finding["change_count"],
                        "threshold": finding["threshold"],
                        "mitre_technique": "T1486 - Data Encrypted for Impact",
                        "mitre_tactic": "Impact",
                    },
                })

        return actions

    # ------------------------------------------------------------------
    # Act: send alerts + isolate / تنفيذ: إرسال تنبيهات + عزل
    # ------------------------------------------------------------------
    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Execute decided actions: send alerts and isolate hosts if needed.
        """
        alerts_sent = 0
        hosts_isolated = 0

        for action in actions:
            # Send alert
            if action.get("alert"):
                sent = self.alerter.send_alert(
                    severity=action["severity"],
                    title=action["title"],
                    details=action["details"],
                    agent_name=self.name,
                )
                if sent:
                    alerts_sent += 1
                    self._metrics.inc_alerts(action["severity"].name)

            # Immediate host isolation for canary file modification
            if action.get("isolate_host"):
                wazuh_agent_id = action.get("wazuh_agent_id", "")
                if wazuh_agent_id:
                    try:
                        logger.critical(
                            "🔴 CANARY COMPROMISED – isolating host (agent %s)",
                            wazuh_agent_id,
                        )
                        self.wazuh.isolate_agent(wazuh_agent_id)
                        hosts_isolated += 1
                    except Exception as exc:
                        logger.error("Host isolation failed: %s", exc)

        self._events_processed += 1
        self._metrics.inc_events(1)

        if alerts_sent or hosts_isolated:
            self.report_to_supervisor({
                "type": "ransomware_report",
                "alerts_sent": alerts_sent,
                "hosts_isolated": hosts_isolated,
            })

        return {"alerts_sent": alerts_sent, "hosts_isolated": hosts_isolated}


# ---------------------------------------------------------------------------
# Entry point / نقطة الدخول
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = RansomwareCanaryAgent()
    agent.run_loop()
