"""
SOC Platform - Worker Agent W38: Anomalous Identity / UEBA Detection
وكيل تحليل سلوك المستخدمين والكيانات

User and Entity Behavior Analytics (UEBA):
- Builds behavior profiles per user: normal login times, source IPs,
  accessed resources, typical data volumes
- Detects: login at unusual hour, login from new IP range, access to
  new resources, service account used interactively, compound anomalies
- Risk score 0-100: >80=CRITICAL, >60=HIGH, >40=MEDIUM, decays over time
- Stores profiles in user-profiles index, 14-day learning period

Interval: 120 seconds | Supervisor: soc:detection-supervisor
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w38_anomalous_identity")

# Risk score thresholds
_CRITICAL_THRESHOLD = 80
_HIGH_THRESHOLD = 60
_MEDIUM_THRESHOLD = 40

# Learning period (seconds) — 14 days
_LEARNING_PERIOD_S = 14 * 24 * 3600

# Risk score decay half-life (hours)
_DECAY_HALF_LIFE_H = 24.0

# Anomaly point values
_POINTS_UNUSUAL_HOUR = 20
_POINTS_NEW_IP_RANGE = 25
_POINTS_NEW_RESOURCE = 15
_POINTS_SERVICE_INTERACTIVE = 35
_POINTS_IMPOSSIBLE_TRAVEL = 40
_POINTS_MULTIPLE_FAILURES = 10


class AnomalousIdentityAgent(BaseAgent):
    """
    UEBA / Anomalous Identity Detection Agent (W38).
    وكيل تحليل السلوك الشاذ للهويات

    Builds per-user behavioral baselines and detects deviations that
    may indicate compromised accounts or insider threats.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w38_anomalous_identity",
            description="User and Entity Behavior Analytics — anomalous identity detection",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")
        self._profile_index = self._agent_config.get("profile_index", "soc-user-profiles")

        # In-memory profiles: user -> profile dict
        self._profiles: Dict[str, Dict[str, Any]] = {}
        # Accumulated risk scores: user -> (score, last_update_ts)
        self._risk_scores: Dict[str, Tuple[float, float]] = {}

        # Cooldown cache
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown = 600

        # Service account patterns
        self._service_prefixes = tuple(
            self._agent_config.get("service_prefixes", ["svc_", "svc-", "sa_", "app_"])
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract(doc: Dict[str, Any], dotted_key: str) -> Optional[str]:
        current: Any = doc
        for key in dotted_key.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return str(current) if current is not None else None

    @staticmethod
    def _ip_to_range(ip: str) -> str:
        """Convert an IP to its /24 range string."""
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ip

    def _get_profile(self, user: str) -> Dict[str, Any]:
        """Get or create a behavior profile for a user."""
        if user not in self._profiles:
            self._profiles[user] = {
                "user": user,
                "first_seen": time.time(),
                "login_hours": defaultdict(int),    # hour -> count
                "source_ip_ranges": set(),           # /24 ranges seen
                "resources": set(),                  # resources accessed
                "total_logins": 0,
                "is_service_account": user.lower().startswith(self._service_prefixes),
                "interactive_logon_count": 0,
            }
        return self._profiles[user]

    def _is_in_learning(self, profile: Dict[str, Any]) -> bool:
        """Check if user is still in the 14-day learning period."""
        return (time.time() - profile["first_seen"]) < _LEARNING_PERIOD_S

    def _decayed_score(self, user: str) -> float:
        """Return the current risk score after time decay."""
        if user not in self._risk_scores:
            return 0.0
        score, last_ts = self._risk_scores[user]
        hours_elapsed = (time.time() - last_ts) / 3600.0
        decay = math.exp(-0.693 * hours_elapsed / _DECAY_HALF_LIFE_H)
        return score * decay

    def _add_risk(self, user: str, points: float) -> float:
        """Add risk points and return new total (capped at 100)."""
        current = self._decayed_score(user)
        new_score = min(100.0, current + points)
        self._risk_scores[user] = (new_score, time.time())
        return new_score

    def _score_to_severity(self, score: float) -> Severity:
        if score >= _CRITICAL_THRESHOLD:
            return Severity.CRITICAL
        if score >= _HIGH_THRESHOLD:
            return Severity.HIGH
        if score >= _MEDIUM_THRESHOLD:
            return Severity.MEDIUM
        return Severity.LOW

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[Dict[str, Any]]:
        """Fetch authentication and access events for behavior analysis."""
        try:
            # Windows logon events (4624 = success, 4625 = failure)
            logon_success = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"match": {"data.win.system.eventID": "4624"}},
                size=5000,
            )
            logon_failure = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"match": {"data.win.system.eventID": "4625"}},
                size=3000,
            )
            # Resource access events (4663 = object access)
            resource_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"match": {"data.win.system.eventID": "4663"}},
                size=3000,
            )
            # VPN/remote access events
            vpn_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3,
                query={"bool": {"should": [
                    {"match": {"data.win.system.eventID": "6272"}},
                    {"match": {"data.win.system.eventID": "6278"}},
                ]}},
                size=1000,
            )
            return {
                "logon_success": logon_success,
                "logon_failure": logon_failure,
                "resource_events": resource_events,
                "vpn_events": vpn_events,
            }
        except Exception as exc:
            logger.error("Failed to collect identity data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze authentication events against user behavior profiles."""
        findings: List[Dict[str, Any]] = []
        logon_success = data.get("logon_success", [])
        logon_failure = data.get("logon_failure", [])
        resource_events = data.get("resource_events", [])
        vpn_events = data.get("vpn_events", [])

        total = len(logon_success) + len(logon_failure) + len(resource_events) + len(vpn_events)
        self._events_processed += total
        self._metrics.inc_events(total)

        # Track failures per user for this cycle
        failure_counts: Dict[str, int] = defaultdict(int)
        for event in logon_failure:
            user = self._extract(event, "data.win.eventdata.targetUserName") or ""
            if user and not user.endswith("$"):
                failure_counts[user] += 1

        # Process successful logons
        for event in logon_success:
            user = self._extract(event, "data.win.eventdata.targetUserName") or ""
            src_ip = self._extract(event, "data.win.eventdata.ipAddress") or ""
            logon_type = self._extract(event, "data.win.eventdata.logonType") or ""
            timestamp_str = self._extract(event, "timestamp") or ""

            if not user or user.endswith("$") or user.upper() in ("SYSTEM", "ANONYMOUS LOGON"):
                continue

            profile = self._get_profile(user)
            anomalies: List[str] = []
            risk_added = 0.0

            # Parse hour from event timestamp
            try:
                event_hour = datetime.fromisoformat(
                    timestamp_str.replace("Z", "+00:00")
                ).hour
            except (ValueError, AttributeError):
                event_hour = datetime.now(timezone.utc).hour

            # --- Anomaly 1: Unusual hour ---
            if not self._is_in_learning(profile) and profile["total_logins"] > 10:
                hour_total = sum(profile["login_hours"].values())
                hour_pct = profile["login_hours"].get(event_hour, 0) / max(hour_total, 1)
                if hour_pct < 0.02:  # less than 2% of historical logins at this hour
                    anomalies.append(f"unusual_login_hour_{event_hour:02d}")
                    risk_added += _POINTS_UNUSUAL_HOUR

            # --- Anomaly 2: New IP range ---
            if src_ip and src_ip not in ("-", "::1", "127.0.0.1"):
                ip_range = self._ip_to_range(src_ip)
                if not self._is_in_learning(profile) and ip_range not in profile["source_ip_ranges"]:
                    anomalies.append(f"new_ip_range:{ip_range}")
                    risk_added += _POINTS_NEW_IP_RANGE
                profile["source_ip_ranges"].add(ip_range)

            # --- Anomaly 3: Service account interactive login ---
            if profile["is_service_account"] and logon_type in ("2", "10", "11"):
                anomalies.append(f"service_account_interactive_logon_type_{logon_type}")
                risk_added += _POINTS_SERVICE_INTERACTIVE
                profile["interactive_logon_count"] += 1

            # --- Anomaly 4: High failure count preceding success ---
            if failure_counts.get(user, 0) >= 5:
                anomalies.append(f"multiple_failures_then_success:{failure_counts[user]}")
                risk_added += _POINTS_MULTIPLE_FAILURES

            # Update profile
            profile["login_hours"][event_hour] += 1
            profile["total_logins"] += 1

            # Record finding if anomalies detected
            if anomalies and risk_added > 0:
                new_score = self._add_risk(user, risk_added)
                severity = self._score_to_severity(new_score)
                findings.append({
                    "pattern": "anomalous_identity",
                    "user": user,
                    "source_ip": src_ip,
                    "anomalies": anomalies,
                    "risk_points_added": risk_added,
                    "risk_score": round(new_score, 1),
                    "severity": severity,
                    "in_learning": self._is_in_learning(profile),
                    "description": (
                        f"User '{user}' anomalies: {', '.join(anomalies)}. "
                        f"Risk score: {new_score:.0f}/100"
                    ),
                })

        # Process resource access anomalies
        resources_per_user: Dict[str, Set[str]] = defaultdict(set)
        for event in resource_events:
            user = self._extract(event, "data.win.eventdata.subjectUserName") or ""
            obj_name = self._extract(event, "data.win.eventdata.objectName") or ""
            if user and obj_name and not user.endswith("$"):
                resources_per_user[user].add(obj_name)

        for user, resources in resources_per_user.items():
            profile = self._get_profile(user)
            if self._is_in_learning(profile):
                profile["resources"].update(resources)
                continue
            new_resources = resources - profile["resources"]
            if len(new_resources) >= 5:
                risk_added = _POINTS_NEW_RESOURCE * min(len(new_resources) / 5, 3.0)
                new_score = self._add_risk(user, risk_added)
                severity = self._score_to_severity(new_score)
                findings.append({
                    "pattern": "new_resource_access",
                    "user": user,
                    "new_resource_count": len(new_resources),
                    "sample_resources": sorted(new_resources)[:10],
                    "risk_points_added": round(risk_added, 1),
                    "risk_score": round(new_score, 1),
                    "severity": severity,
                    "description": (
                        f"User '{user}' accessed {len(new_resources)} previously "
                        f"unseen resources. Risk score: {new_score:.0f}/100"
                    ),
                })
            profile["resources"].update(resources)

        if findings:
            logger.warning("Detected %d identity anomaly finding(s)", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create actions for identity anomaly findings above threshold."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            if finding.get("in_learning"):
                continue  # suppress alerts during learning period

            score = finding.get("risk_score", 0)
            if score < _MEDIUM_THRESHOLD:
                continue

            key = f"{finding['pattern']}:{finding['user']}"
            last = self._alerted_cache.get(key, 0.0)
            if now - last < self._alert_cooldown:
                continue

            actions.append({
                "type": "alert",
                "severity": finding["severity"],
                "title": f"Anomalous Identity: {finding['user']}",
                "details": {k: v for k, v in finding.items() if k != "severity"},
                "cooldown_key": key,
            })
            actions.append({"type": "log_incident", "finding": finding})
            actions.append({"type": "store_profile", "user": finding["user"]})

            if finding["severity"] >= Severity.CRITICAL:
                actions.append({"type": "escalate", "finding": finding})

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alert, logging, profile storage, and escalation actions."""
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
                    self._alerted_cache[action["cooldown_key"]] = time.time()

            elif action["type"] == "log_incident":
                try:
                    finding = action["finding"]
                    self.os_client.index_document(
                        index="soc-identity-incidents",
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name,
                            "pattern": finding["pattern"],
                            "severity": finding["severity"].name,
                            "user": finding["user"],
                            "risk_score": finding["risk_score"],
                            "anomalies": finding.get("anomalies", []),
                            "description": finding["description"],
                        },
                    )
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log identity incident: %s", exc)

            elif action["type"] == "store_profile":
                try:
                    user = action["user"]
                    profile = self._profiles.get(user, {})
                    self.os_client.index_document(
                        index=self._profile_index,
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "user": user,
                            "risk_score": round(self._decayed_score(user), 1),
                            "total_logins": profile.get("total_logins", 0),
                            "known_ip_ranges": len(profile.get("source_ip_ranges", set())),
                            "known_resources": len(profile.get("resources", set())),
                            "is_service_account": profile.get("is_service_account", False),
                        },
                    )
                except Exception as exc:
                    logger.error("Failed to store user profile: %s", exc)

            elif action["type"] == "escalate":
                finding = action["finding"]
                self.report_to_supervisor({
                    "type": "identity_anomaly_critical",
                    "user": finding["user"],
                    "risk_score": finding["risk_score"],
                    "anomalies": finding.get("anomalies", []),
                    "description": finding["description"],
                })

        # Prune cooldown cache
        cutoff = time.time() - self._alert_cooldown * 3
        self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent:
            self.report_to_supervisor({
                "type": "identity_report",
                "alerts_sent": alerts_sent,
                "incidents_logged": incidents_logged,
                "tracked_users": len(self._profiles),
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
    agent = AnomalousIdentityAgent()
    agent.run_loop()
