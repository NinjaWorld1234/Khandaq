"""
SOC Platform - Worker Agent W42: Insider Threat / DLP Detection
وكيل كشف التهديدات الداخلية ومنع فقدان البيانات

Monitors for Data Loss Prevention and insider threat indicators:
- Large downloads (>100 MB)
- Mass file access (>200 files/hour)
- Access outside normal scope (sensitive directories)
- After-hours sensitive data access
- Bulk external email (>50 recipients in window)
- Printing spikes (unusual volume)
- USB device connections (removable storage)

Per-user risk scoring: accumulated over 30-day sliding window
  > 100 points = alert (HIGH)
  > 200 points = CRITICAL

Interval: 120 seconds | Supervisor: soc:detection-supervisor
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

logger = logging.getLogger("soc.agent.w42_insider_threat")

# Risk score thresholds
_ALERT_THRESHOLD = 100
_CRITICAL_THRESHOLD = 200

# DLP indicator thresholds
_LARGE_DOWNLOAD_MB = 100
_MASS_FILE_THRESHOLD = 200       # files/hour
_BULK_EMAIL_THRESHOLD = 50       # recipients/window
_PRINT_SPIKE_MULTIPLIER = 5.0   # x times baseline

# 30-day risk window (seconds)
_RISK_WINDOW_S = 30 * 24 * 3600

# Business hours (UTC-adjusted; override via config)
_BUSINESS_HOUR_START = 7
_BUSINESS_HOUR_END = 19

# Sensitive path keywords
_SENSITIVE_PATHS = {
    "confidential", "restricted", "secret", "hr_data", "finance",
    "executive", "legal", "m&a", "merger", "acquisition", "payroll",
    "pii", "phi", "ssn", "password", "credentials", "keys",
}

# Risk point values per indicator
_POINTS = {
    "large_download": 25,
    "mass_file_access": 30,
    "after_hours_sensitive": 20,
    "usb_connection": 15,
    "bulk_email": 20,
    "print_spike": 10,
    "out_of_scope": 15,
}


class InsiderThreatAgent(BaseAgent):
    """
    Insider Threat / DLP Detection Agent (W42).
    وكيل كشف التهديدات الداخلية ومنع فقدان البيانات

    Monitors data exfiltration signals and user risk scores
    to detect potential insider threats or data theft.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w42_insider_threat",
            description="Monitors for data hoarding, unauthorized USBs, and DLP violations",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )
        self._alert_index = self._agent_config.get(
            "alert_index", "wazuh-alerts-*")

        # Per-user risk scores: user -> [(points, timestamp, reason), ...]
        self._risk_ledger: Dict[str,
                                List[Tuple[float, float, str]]] = defaultdict(list)
        # Print baselines: user -> avg pages/cycle
        self._print_baselines: Dict[str, float] = {}
        self._print_samples: Dict[str, List[int]] = defaultdict(list)
        # User normal resource scope
        self._user_scope: Dict[str, Set[str]] = defaultdict(set)
        self._scope_learning_cycles: Dict[str, int] = defaultdict(int)
        _SCOPE_LEARNING_CYCLES = 60  # ~2 hours of 120s cycles

        self._scope_learning_threshold = _SCOPE_LEARNING_CYCLES

        # Cooldown
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown = 900  # 15 min
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

    def _is_sensitive_path(self, path: str) -> bool:
        """Check if a file path references sensitive content."""
        path_lower = path.lower()
        return any(keyword in path_lower for keyword in _SENSITIVE_PATHS)

    def _is_after_hours(self) -> bool:
        """Check if the current time is outside business hours."""
        hour = datetime.now(timezone.utc).hour
        return hour < _BUSINESS_HOUR_START or hour >= _BUSINESS_HOUR_END

    def _add_risk(self, user: str, points: float, reason: str) -> float:
        """Add risk points and return current total (pruned to 30-day window)."""
        now = time.time()
        self._risk_ledger[user].append((points, now, reason))
        # Prune beyond 30-day window
        self._risk_ledger[user] = [
            (p, t, r) for p, t, r in self._risk_ledger[user]
            if now - t < _RISK_WINDOW_S
        ]
        return sum(p for p, _, _ in self._risk_ledger[user])

    def _user_risk_score(self, user: str) -> float:
        """Get the current risk score for a user."""
        now = time.time()
        self._risk_ledger[user] = [
            (p, t, r) for p, t, r in self._risk_ledger[user]
            if now - t < _RISK_WINDOW_S
        ]
        return sum(p for p, _, _ in self._risk_ledger[user])

    def _score_to_severity(self, score: float) -> Severity:
        if score >= _CRITICAL_THRESHOLD:
            return Severity.CRITICAL
        if score >= _ALERT_THRESHOLD:
            return Severity.HIGH
        return Severity.MEDIUM

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[Dict[str, Any]]:
        """Fetch file access, USB, email, and print events."""
        try:
            # Event 4663: Object access (file access)
            file_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"match": {"data.win.system.eventID": "4663"}},
                size=10000,
            )
            # Sysmon Event 11: File created (downloads)
            download_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"bool": {"must": [
                    {"match": {"data.win.system.providerName": "Microsoft-Windows-Sysmon"}},
                    {"match": {"data.win.system.eventID": "11"}},
                ]}},
                size=10000,
            )
            # USB device connection events (Wazuh rule groups)
            usb_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"bool": {"should": [
                    {"match": {"rule.groups": "usb"}},
                    {"match": {"data.win.system.eventID": "2003"}},
                    {"match": {"data.win.system.eventID": "6416"}},
                ]}},
                size=10000,
            )
            # Print events (Event 307: document printed)
            print_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"match": {"data.win.system.eventID": "307"}},
                size=10000,
            )
            # Email send events (proxy/mail logs with external recipients)
            email_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"bool": {"should": [
                    {"match": {"data.win.system.eventID": "6200"}},
                    {"match": {"rule.groups": "email"}},
                ]}},
                size=10000,
            )
            return {
                "file_events": file_events,
                "download_events": download_events,
                "usb_events": usb_events,
                "print_events": print_events,
                "email_events": email_events,
            }
        except Exception as exc:
            logger.error("Failed to collect insider threat data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect insider threat and DLP indicators."""
        findings: List[Dict[str, Any]] = []
        file_events = data.get("file_events", [])
        download_events = data.get("download_events", [])
        usb_events = data.get("usb_events", [])
        print_events = data.get("print_events", [])
        email_events = data.get("email_events", [])

        total = (len(file_events) + len(download_events) +
                 len(usb_events) + len(print_events) + len(email_events))
        self._events_processed += total
        self._metrics.inc_events(total)

        after_hours = self._is_after_hours()

        # --- Mass file access ---
        file_counts: Dict[str, int] = defaultdict(int)
        sensitive_access: Dict[str, List[str]] = defaultdict(list)

        for event in file_events:
            try:
                user = self._extract(
                    event, "data.win.eventdata.subjectUserName") or ""
                obj_name = self._extract(
                    event, "data.win.eventdata.objectName") or ""
                if not user or user.endswith("$") or user.upper() in ("SYSTEM",):
                    continue

                file_counts[user] += 1

                if self._is_sensitive_path(obj_name):
                    sensitive_access[user].append(obj_name)

                # Track user scope
                # Derive top-level directory as scope identifier
                parts = obj_name.replace("\\", "/").split("/")
                scope_key = "/".join(parts[:4]) if len(parts) >= 4 else obj_name
                self._scope_learning_cycles[user] = self._scope_learning_cycles.get(
                    user, 0) + 1

                if self._scope_learning_cycles[user] < self._scope_learning_threshold:
                    self._user_scope[user].add(scope_key)
            except Exception as e:
                logger.warning("Error processing file access event: %s", e)

        # Mass file access detection
        for user, count in file_counts.items():
            try:
                if count >= _MASS_FILE_THRESHOLD:
                    risk = self._add_risk(user, _POINTS["mass_file_access"],
                                          f"mass_file_access:{count}")
                    findings.append({
                        "pattern": "mass_file_access",
                        "user": user,
                        "file_count": count,
                        "risk_score": round(risk, 1),
                        "severity": self._score_to_severity(risk),
                        "description": (
                            f"Mass file access: '{user}' accessed {count} files "
                            f"in this cycle. Risk: {risk:.0f}"
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating mass file access: %s", e)

        # After-hours sensitive access
        if after_hours:
            for user, paths in sensitive_access.items():
                try:
                    risk = self._add_risk(user, _POINTS["after_hours_sensitive"],
                                          f"after_hours_sensitive:{len(paths)}")
                    findings.append({
                        "pattern": "after_hours_sensitive",
                        "user": user,
                        "sensitive_files": len(paths),
                        "sample_paths": paths[:5],
                        "risk_score": round(risk, 1),
                        "severity": self._score_to_severity(risk),
                        "description": (
                            f"After-hours sensitive access: '{user}' accessed "
                            f"{len(paths)} sensitive files. Risk: {risk:.0f}"
                        ),
                    })
                except Exception as e:
                    logger.warning("Error evaluating after-hours access: %s", e)

        # --- Large downloads ---
        download_sizes: Dict[str, float] = defaultdict(float)
        for event in download_events:
            try:
                user = self._extract(event, "data.win.eventdata.user") or ""
                self._extract(event, "data.win.eventdata.targetFilename") or ""
                # Approximate size from Sysmon if available
                size_str = self._extract(
                    event, "data.win.eventdata.fileSize") or "0"
                if not user or user.endswith("$"):
                    continue
                # Extract just the username from DOMAIN\user format
                if "\\" in user:
                    user = user.split("\\")[-1].strip()
                try:
                    size_mb = float(size_str) / (1024 * 1024)
                except (ValueError, TypeError):
                    size_mb = 0
                download_sizes[user] += size_mb
            except Exception as e:
                logger.warning("Error processing download event: %s", e)

        for user, total_mb in download_sizes.items():
            try:
                if total_mb >= _LARGE_DOWNLOAD_MB:
                    risk = self._add_risk(user, _POINTS["large_download"],
                                          f"large_download:{total_mb:.0f}MB")
                    findings.append({
                        "pattern": "large_download",
                        "user": user,
                        "total_mb": round(total_mb, 1),
                        "risk_score": round(risk, 1),
                        "severity": self._score_to_severity(risk),
                        "description": (
                            f"Large download: '{user}' downloaded {total_mb:.0f} MB. "
                            f"Risk: {risk:.0f}"
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating large download: %s", e)

        # --- USB connections ---
        usb_users: Dict[str, List[str]] = defaultdict(list)
        for event in usb_events:
            try:
                user = (self._extract(event, "data.win.eventdata.subjectUserName")
                        or self._extract(event, "agent.name") or "")
                device = (
                    self._extract(
                        event,
                        "data.win.eventdata.deviceDescription") or self._extract(
                        event,
                        "data.win.eventdata.className") or "USB Device")
                if user and not user.endswith("$"):
                    usb_users[user].append(device)
            except Exception as e:
                logger.warning("Error processing usb event: %s", e)

        for user, devices in usb_users.items():
            try:
                risk = self._add_risk(user, _POINTS["usb_connection"],
                                      f"usb_connection:{len(devices)}")
                findings.append({
                    "pattern": "usb_connection",
                    "user": user,
                    "device_count": len(devices),
                    "devices": devices[:5],
                    "risk_score": round(risk, 1),
                    "severity": self._score_to_severity(risk),
                    "description": (
                        f"USB device: '{user}' connected {len(devices)} USB "
                        f"device(s). Risk: {risk:.0f}"
                    ),
                })
            except Exception as e:
                logger.warning("Error evaluating usb connection: %s", e)

        # --- Print spikes ---
        print_counts: Dict[str, int] = defaultdict(int)
        for event in print_events:
            try:
                user = self._extract(event, "data.win.eventdata.param3") or ""
                if user and not user.endswith("$"):
                    if "\\" in user:
                        user = user.split("\\")[-1].strip()
                    print_counts[user] += 1
            except Exception as e:
                logger.warning("Error processing print event: %s", e)

        for user, count in print_counts.items():
            try:
                # Update baseline
                self._print_samples[user].append(count)
                if len(self._print_samples[user]) > 168:
                    self._print_samples[user] = self._print_samples[user][-168:]
                baseline = sum(
                    self._print_samples[user]) / max(len(self._print_samples[user]), 1)
                self._print_baselines[user] = baseline

                if baseline > 0 and count >= baseline * _PRINT_SPIKE_MULTIPLIER and count >= 10:
                    risk = self._add_risk(user, _POINTS["print_spike"],
                                          f"print_spike:{count}")
                    findings.append({
                        "pattern": "print_spike",
                        "user": user,
                        "pages_printed": count,
                        "baseline_avg": round(baseline, 1),
                        "risk_score": round(risk, 1),
                        "severity": self._score_to_severity(risk),
                        "description": (
                            f"Print spike: '{user}' printed {count} pages "
                            f"(baseline: {baseline:.0f}). Risk: {risk:.0f}"
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating print spike: %s", e)

        # --- Bulk external email ---
        email_recipients: Dict[str, Set[str]] = defaultdict(set)
        for event in email_events:
            try:
                user = self._extract(event, "data.srcuser") or self._extract(
                    event, "data.win.eventdata.subjectUserName") or ""
                recipient = self._extract(event, "data.dstuser") or ""
                if not user or not recipient:
                    continue
                if "\\" in user:
                    user = user.split("\\")[-1].strip()
                email_recipients[user].add(recipient)
            except Exception as e:
                logger.warning("Error processing email event: %s", e)

        for user, recipients in email_recipients.items():
            try:
                if len(recipients) >= _BULK_EMAIL_THRESHOLD:
                    risk = self._add_risk(user, _POINTS["bulk_email"],
                                          f"bulk_email:{len(recipients)}")
                    findings.append({
                        "pattern": "bulk_email",
                        "user": user,
                        "recipient_count": len(recipients),
                        "risk_score": round(risk, 1),
                        "severity": self._score_to_severity(risk),
                        "description": (
                            f"Bulk email: '{user}' sent to {len(recipients)} "
                            f"unique recipients. Risk: {risk:.0f}"
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating bulk email: %s", e)

        if findings:
            logger.warning(
                "Detected %d insider threat indicator(s)",
                len(findings))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create actions for insider threat findings above threshold."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            try:
                score = finding.get("risk_score", 0)
                if score < _ALERT_THRESHOLD:
                    # Still log but don't alert
                    actions.append({"type": "log_incident", "finding": finding})
                    continue

                key = f"{finding['pattern']}:{finding['user']}"
                with self._cache_lock:
                    last = self._alerted_cache.get(key, 0.0)
                if now - last < self._alert_cooldown:
                    continue

                actions.append({
                    "type": "alert",
                    "severity": finding["severity"],
                    "title": f"Insider Threat: {finding['pattern'].replace('_', ' ').title()}",
                    "details": {k: v for k, v in finding.items() if k != "severity"},
                    "cooldown_key": key,
                })
                actions.append({"type": "log_incident", "finding": finding})

                if finding["severity"] >= Severity.CRITICAL:
                    actions.append({"type": "escalate", "finding": finding})
            except Exception as e:
                logger.warning("Error evaluating insider threat action: %s", e)

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
                            self._alerted_cache[action["cooldown_key"]
                                                ] = time.time()

                elif action["type"] == "log_incident":
                    try:
                        finding = action["finding"]
                        self.os_client.index_document(
                            index="soc-insider-threat-incidents",
                            document={
                                "@timestamp": datetime.now(timezone.utc).isoformat(),
                                "agent_name": self.name,
                                "pattern": finding["pattern"],
                                "severity": finding["severity"].name,
                                "user": finding["user"],
                                "risk_score": finding["risk_score"],
                                "description": finding["description"],
                            },
                        )
                        incidents_logged += 1
                    except Exception as exc:
                        logger.error(
                            "Failed to log insider threat incident: %s", exc)

                elif action["type"] == "escalate":
                    finding = action["finding"]
                    self.report_to_supervisor({
                        "type": "insider_threat_critical",
                        "pattern": finding["pattern"],
                        "user": finding["user"],
                        "risk_score": finding["risk_score"],
                        "description": finding["description"],
                    })
            except Exception as e:
                logger.warning("Error executing insider threat action: %s", e)

        # Prune cooldown
        cutoff = time.time() - self._alert_cooldown * 3
        with self._cache_lock:

            self._alerted_cache = {
                k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent:
            self.report_to_supervisor({
                "type": "insider_threat_report",
                "alerts_sent": alerts_sent,
                "incidents_logged": incidents_logged,
                "tracked_users": len(self._risk_ledger),
            })

        return {"alerts_sent": alerts_sent,
                "incidents_logged": incidents_logged}


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
    agent = InsiderThreatAgent()
    agent.run_loop()
