"""
SOC Platform - Worker Agent W41: Active Directory Enumeration Detection
وكيل كشف استطلاع الدليل النشط

Detects AD reconnaissance activities:
- LDAP queries for all users/groups (Event 4662 Directory Service Access)
- BloodHound / SharpHound enumeration (rapid LDAP queries)
- net user /domain, net group /domain commands
- nltest /dclist, dsquery, adfind.exe
- GPO enumeration (Group Policy access)
- AdminSDHolder queries

Tracks LDAP query volume per user:
  Normal admin:  10-50 queries/hour
  Attacker:      500+ queries in minutes

Interval: 120 seconds | Supervisor: soc:endpoint-supervisor
"""

from __future__ import annotations

import logging
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w41_ad_enumeration")

# LDAP query volume thresholds
_LDAP_HIGH_THRESHOLD = 200       # queries/window → HIGH
_LDAP_CRITICAL_THRESHOLD = 500   # queries/window → CRITICAL
_LDAP_WINDOW_S = 300             # 5 minute window

# AdminSDHolder object GUID
_ADMIN_SD_HOLDER_GUID = "560b0102-a681-11d2-a9c6-0000f87a9e42"

# Suspicious recon tools / commands
_RECON_TOOLS = {
    "sharphound.exe", "bloodhound.exe", "adfind.exe",
    "ldapsearch", "dsquery.exe", "csvde.exe", "ldifde.exe",
    "adexplorer.exe", "powervu.exe",
}

_RECON_CMD_PATTERNS = [
    ("net.exe", "user /domain"),
    ("net.exe", "group /domain"),
    ("net.exe", "localgroup administrators"),
    ("net1.exe", "user /domain"),
    ("net1.exe", "group /domain"),
    ("nltest.exe", "/dclist"),
    ("nltest.exe", "/domain_trusts"),
    ("dsquery.exe", "user"),
    ("dsquery.exe", "computer"),
    ("dsquery.exe", "group"),
    ("gpresult", "/r"),
    ("powershell", "get-aduser"),
    ("powershell", "get-adgroup"),
    ("powershell", "get-adcomputer"),
    ("powershell", "get-addomaincontroller"),
    ("powershell", "get-gpo"),
]

# GPO-related object GUIDs
_GPO_GUIDS: Set[str] = {
    "f30e3bc2-9ff0-11d1-b603-0000f80367c1",  # Group Policy Container
    "f30e3bc1-9ff0-11d0-b603-0000f80367c1",  # Group Policy Template
}


class ADEnumerationAgent(BaseAgent):
    """
    AD Enumeration Detection Agent (W41).
    وكيل كشف استطلاع الدليل النشط

    Monitors Directory Service Access and process creation events
    to detect Active Directory reconnaissance and enumeration.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w41_ad_enumeration",
            description="Detects BloodHound, SharpHound, and AD reconnaissance activities",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")

        # LDAP query tracking: user -> [(timestamp, count_in_batch), ...]
        self._ldap_volume: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        # User baselines: user -> avg queries/hour (rolling)
        self._ldap_baselines: Dict[str, float] = {}
        self._baseline_samples: Dict[str, List[int]] = defaultdict(list)
        self._baseline_window = 168  # 7 days of hourly samples

        # Whitelist for known admin tools/accounts
        self._admin_whitelist: Set[str] = set(
            self._agent_config.get("admin_whitelist", [])
        )

        # Cooldown
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown = 600
        self._cache_lock = threading.Lock()

    @staticmethod
    def _extract(doc: Dict[str, Any], dotted_key: str) -> Optional[str]:
        if dotted_key in doc:
            return str(doc[dotted_key])
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
        """Fetch Directory Service Access and process creation events."""
        try:
            # Event 4662: Directory Service Access
            ds_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"match": {"data.win.system.eventID": "4662"}},
                size=10000,
            )
            # Event 4688: Process Creation (for recon commands)
            process_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"match": {"data.win.system.eventID": "4688"}},
                size=10000,
            )
            # Event 5136: Directory Service Object Modified
            ds_modify = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"match": {"data.win.system.eventID": "5136"}},
                size=10000,
            )
            # Sysmon Event 1: Process Create (more detailed command lines)
            sysmon_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"bool": {"must": [
                    {"match": {"data.win.system.providerName": "Microsoft-Windows-Sysmon"}},
                    {"match": {"data.win.system.eventID": "1"}},
                ]}},
                size=10000,
            )
            return {
                "ds_events": ds_events,
                "process_events": process_events,
                "ds_modify": ds_modify,
                "sysmon_events": sysmon_events,
            }
        except Exception as exc:
            logger.error("Failed to collect AD enumeration data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect AD enumeration patterns."""
        findings: List[Dict[str, Any]] = []
        ds_events = data.get("ds_events", [])
        process_events = data.get("process_events", [])
        ds_modify = data.get("ds_modify", [])
        sysmon_events = data.get("sysmon_events", [])

        total = len(ds_events) + len(process_events) + len(ds_modify) + len(sysmon_events)
        self._events_processed += total
        self._metrics.inc_events(total)

        now = time.time()

        # --- LDAP query volume analysis (Event 4662) ---
        ldap_counts: Dict[str, int] = defaultdict(int)
        admin_sd_users: Set[str] = set()
        gpo_enum_users: Dict[str, int] = defaultdict(int)

        for event in ds_events:
            try:
                user = self._extract(event, "data.win.eventdata.subjectUserName") or ""
                if not user or user.endswith("$") or user in self._admin_whitelist:
                    continue

                obj_type = (self._extract(event, "data.win.eventdata.objectType") or "").lower()
                properties = (self._extract(event, "data.win.eventdata.properties") or "").lower()

                ldap_counts[user] += 1

                # AdminSDHolder access
                if _ADMIN_SD_HOLDER_GUID.lower() in properties:
                    admin_sd_users.add(user)

                # GPO enumeration
                for gpo_guid in _GPO_GUIDS:
                    if gpo_guid.lower() in properties or gpo_guid.lower() in obj_type:
                        gpo_enum_users[user] += 1
            except Exception as e:
                logger.warning("Error processing DS event: %s", e)

        # Track volumes and detect anomalies
        for user, count in ldap_counts.items():
            try:
                self._ldap_volume[user].append((now, count))
                # Prune old entries
                self._ldap_volume[user] = [
                    (t, c) for t, c in self._ldap_volume[user]
                    if now - t < _LDAP_WINDOW_S
                ]
                # Sum queries in window
                window_total = sum(c for _, c in self._ldap_volume[user])

                # Update baseline
                self._baseline_samples[user].append(count)
                if len(self._baseline_samples[user]) > self._baseline_window:
                    self._baseline_samples[user] = self._baseline_samples[user][-self._baseline_window:]
                baseline = sum(self._baseline_samples[user]) / max(len(self._baseline_samples[user]), 1)
                self._ldap_baselines[user] = baseline

                # Detect anomalous volume
                if window_total >= _LDAP_CRITICAL_THRESHOLD:
                    findings.append({
                        "pattern": "ldap_enumeration",
                        "severity": Severity.CRITICAL,
                        "user": user,
                        "query_count": window_total,
                        "baseline_avg": round(baseline, 1),
                        "window_seconds": _LDAP_WINDOW_S,
                        "description": (
                            f"Critical LDAP enumeration: '{user}' made {window_total} "
                            f"directory queries in {_LDAP_WINDOW_S // 60} min "
                            f"(baseline: {baseline:.0f}/cycle)"
                        ),
                    })
                elif window_total >= _LDAP_HIGH_THRESHOLD:
                    findings.append({
                        "pattern": "ldap_enumeration",
                        "severity": Severity.HIGH,
                        "user": user,
                        "query_count": window_total,
                        "baseline_avg": round(baseline, 1),
                        "window_seconds": _LDAP_WINDOW_S,
                        "description": (
                            f"High LDAP enumeration: '{user}' made {window_total} "
                            f"directory queries in {_LDAP_WINDOW_S // 60} min"
                        ),
                    })
            except Exception as e:
                logger.warning("Error computing LDAP volume: %s", e)

        # AdminSDHolder queries
        for user in admin_sd_users:
            try:
                findings.append({
                    "pattern": "admin_sd_holder_query",
                    "severity": Severity.HIGH,
                    "user": user,
                    "description": (
                        f"AdminSDHolder access: '{user}' queried the AdminSDHolder "
                        f"object — possible privilege escalation recon"
                    ),
                })
            except Exception as e:
                logger.warning("Error evaluating AdminSDHolder query: %s", e)

        # GPO enumeration
        for user, count in gpo_enum_users.items():
            try:
                if count >= 5:
                    findings.append({
                        "pattern": "gpo_enumeration",
                        "severity": Severity.MEDIUM,
                        "user": user,
                        "gpo_access_count": count,
                        "description": (
                            f"GPO enumeration: '{user}' accessed {count} Group "
                            f"Policy objects"
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating GPO enumeration: %s", e)

        # --- Recon tool / command detection (4688 + Sysmon 1) ---
        all_process_events = process_events + sysmon_events
        for event in all_process_events:
            try:
                user = self._extract(event, "data.win.eventdata.subjectUserName") or ""
                new_proc = (self._extract(event, "data.win.eventdata.newProcessName") or "").lower()
                cmd_line = (self._extract(event, "data.win.eventdata.commandLine") or "").lower()
                image = (self._extract(event, "data.win.eventdata.image") or "").lower()

                proc_name = new_proc or image
                if not user or user.endswith("$") or user in self._admin_whitelist:
                    continue

                # Check for known recon tools
                proc_basename = proc_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                if proc_basename in _RECON_TOOLS:
                    severity = Severity.CRITICAL if proc_basename in ("sharphound.exe", "bloodhound.exe") else Severity.HIGH
                    findings.append({
                        "pattern": "recon_tool",
                        "severity": severity,
                        "user": user,
                        "tool": proc_basename,
                        "command_line": cmd_line[:300],
                        "description": (
                            f"AD recon tool: '{user}' executed '{proc_basename}'"
                        ),
                    })

                # Check for recon command patterns
                for tool, pattern in _RECON_CMD_PATTERNS:
                    if tool in proc_name and pattern in cmd_line:
                        findings.append({
                            "pattern": "recon_command",
                            "severity": Severity.MEDIUM,
                            "user": user,
                            "tool": tool,
                            "pattern_matched": pattern,
                            "command_line": cmd_line[:300],
                            "description": (
                                f"AD recon command: '{user}' ran '{tool} {pattern}'"
                            ),
                        })
                        break  # one match per event
            except Exception as e:
                logger.warning("Error processing recon process event: %s", e)

        if findings:
            logger.warning("Detected %d AD enumeration pattern(s)", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create actions for AD enumeration findings."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            try:
                key = f"{finding['pattern']}:{finding['user']}"
                with self._cache_lock:
                    last = self._alerted_cache.get(key, 0.0)
                if now - last < self._alert_cooldown:
                    continue

                actions.append({
                    "type": "alert",
                    "severity": finding["severity"],
                    "title": f"AD Enumeration: {finding['pattern'].replace('_', ' ').title()}",
                    "details": {k: v for k, v in finding.items() if k != "severity"},
                    "cooldown_key": key,
                })
                actions.append({"type": "log_incident", "finding": finding})

                if finding["severity"] >= Severity.CRITICAL:
                    actions.append({"type": "escalate", "finding": finding})
            except Exception as e:
                logger.warning("Error evaluating AD Enumeration action: %s", e)

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alert, logging, and escalation actions."""
        alerts_sent = 0
        incidents_logged = 0

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
                            self._alerted_cache[action["cooldown_key"]] = time.time()

                elif action["type"] == "log_incident":
                    try:
                        finding = action["finding"]
                        self.os_client.index_document(
                            index="soc-ad-enumeration-incidents",
                            document={
                                "@timestamp": datetime.now(timezone.utc).isoformat(),
                                "agent_name": self.name,
                                "pattern": finding["pattern"],
                                "severity": finding["severity"].name,
                                "user": finding["user"],
                                "description": finding["description"],
                                "query_count": finding.get("query_count"),
                                "tool": finding.get("tool"),
                            },
                        )
                        incidents_logged += 1
                    except Exception as exc:
                        logger.error("Failed to log AD enumeration incident: %s", exc)

                elif action["type"] == "escalate":
                    finding = action["finding"]
                    self.report_to_supervisor({
                        "type": "ad_enumeration_critical",
                        "pattern": finding["pattern"],
                        "user": finding["user"],
                        "description": finding["description"],
                    })
            except Exception as e:
                logger.warning("Error executing AD enumeration action: %s", e)

        # Prune cooldown
        cutoff = time.time() - self._alert_cooldown * 3
        with self._cache_lock:

            self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent:
            self.report_to_supervisor({
                "type": "ad_enumeration_report",
                "alerts_sent": alerts_sent,
                "incidents_logged": incidents_logged,
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
    agent = ADEnumerationAgent()
    agent.run_loop()
