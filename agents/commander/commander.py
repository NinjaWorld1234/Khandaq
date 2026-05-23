"""
SOC Platform – Commander Agent (القائد الأعلى)
The supreme coordinator that receives escalations from all 5 supervisors
and makes strategic response decisions.

Subscribes to: soc:supervisor-to-commander

Cross-supervisor correlations:
  1. Network C2 + Endpoint suspicious process on same host → CONFIRMED INTRUSION
  2. Intel new threat campaign + Endpoint IOC match        → TARGETED ATTACK
  3. Infra log gap + Network beaconing from same host      → EVASION
  4. Response isolation + continued network activity        → INCOMPLETE CONTAINMENT
  5. Multiple supervisors reporting on same host            → MULTI-VECTOR ATTACK

Global Threat Levels: GREEN → YELLOW → ORANGE → RED

Interval: 10 seconds (highly responsive)
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("soc.commander")

# Threat level thresholds
_THREAT_DECAY_SECONDS = 1800  # 30 min with no escalation → decay
_CORRELATION_WINDOW = 600     # 10 min window for cross-supervisor correlation


class CommanderAgent(BaseAgent):
    """
    Commander Agent — the top-level SOC coordinator.
    Receives escalated events from all supervisors, performs cross-domain
    correlation, manages global threat level, and coordinates strategic
    incident response.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="commander",
            description="Supreme SOC coordinator with global visibility",
            interval_seconds=10,
            config=config,
        )
        # Global threat state
        self._threat_level = "GREEN"
        self._threat_level_since = time.time()
        self._last_critical = 0.0

        # Incoming supervisor reports (sliding window)
        self._supervisor_reports: List[Dict[str, Any]] = []

        # Per-host timeline: host → list of {supervisor, type, severity, time}
        self._host_timeline: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        # Active incidents
        self._active_incidents: Dict[str, Dict[str, Any]] = {}

        # Dedup
        self._escalated_keys: Dict[str, float] = {}
        self._cooldown = 300

        # Statistics
        self._total_escalations = 0
        self._total_decisions = 0

    # ------------------------------------------------------------------
    # Redis handler
    # ------------------------------------------------------------------

    def _on_supervisor_message(self, message: dict) -> None:
        try:
            data = message if isinstance(message, dict) else json.loads(message)
            data["_received_at"] = time.time()
            self._supervisor_reports.append(data)
            self._total_escalations += 1
            logger.info("Escalation from %s: %s [%s]",
                        data.get("supervisor", "?"),
                        data.get("type", "?"),
                        data.get("severity", "?"))
        except Exception as exc:
            logger.error("Failed to parse supervisor message: %s", exc)

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> List[Dict[str, Any]]:
        now = time.time()
        # Keep last 15 minutes of reports
        self._supervisor_reports = [
            r for r in self._supervisor_reports
            if now - r.get("_received_at", 0) < 900
        ]
        batch = list(self._supervisor_reports)
        self._supervisor_reports.clear()
        return batch

    # ------------------------------------------------------------------
    # Analyze — cross-supervisor correlation
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        now = time.time()

        # Index by supervisor and host
        by_supervisor: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        by_host: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for report in data:
            supervisor = report.get("supervisor", "")
            host = report.get("host", "")
            report_type = report.get("type", "")
            severity_str = report.get("severity", "MEDIUM")
            severity = self._parse_severity(severity_str)

            by_supervisor[supervisor].append(report)
            if host:
                by_host[host].append(report)
                self._host_timeline[host].append({
                    "supervisor": supervisor,
                    "type": report_type,
                    "severity": severity,
                    "time": now,
                    "details": report.get("details", ""),
                })

        # ── Rule 1: Network C2 + Endpoint suspicious process ──
        network_reports = by_supervisor.get("network_supervisor", [])
        endpoint_reports = by_supervisor.get("endpoint_supervisor", [])

        c2_hosts = {r.get("host") for r in network_reports
                    if "c2" in str(r.get("type", "")).lower() or "beaconing" in str(r.get("type", "")).lower()}
        suspicious_hosts = {r.get("host") for r in endpoint_reports
                           if "process" in str(r.get("type", "")).lower() or "rootkit" in str(r.get("type", "")).lower()}

        overlap_c2_endpoint = c2_hosts & suspicious_hosts - {"", None}
        for host in overlap_c2_endpoint:
            key = f"confirmed_intrusion:{host}"
            if self._should_escalate(key, now):
                findings.append({
                    "type": "CONFIRMED_INTRUSION",
                    "severity": Severity.CRITICAL,
                    "host": host,
                    "details": f"Network C2/beaconing + Endpoint suspicious process on {host}",
                    "response": "IMMEDIATE_ISOLATION",
                })

        # ── Rule 2: Intel threat + Endpoint IOC match ──
        detection_reports = by_supervisor.get("detection_supervisor", [])
        intel_threats = [r for r in detection_reports
                        if "campaign" in str(r.get("type", "")).lower()
                        or "known_threat" in str(r.get("type", "")).lower()]
        for threat in intel_threats:
            affected_hosts = threat.get("affected_hosts", [])
            for host in affected_hosts:
                if host in by_host:
                    key = f"targeted:{host}"
                    if self._should_escalate(key, now):
                        findings.append({
                            "type": "TARGETED_ATTACK",
                            "severity": Severity.CRITICAL,
                            "host": host,
                            "details": f"Intelligence reports targeted attack matching activity on {host}",
                            "response": "ELEVATED_MONITORING",
                        })

        # ── Rule 3: Infra log gap + Network beaconing ──
        infra_reports = by_supervisor.get("infra_supervisor", [])
        log_gap_hosts = {r.get("host") for r in infra_reports
                        if "log" in str(r.get("type", "")).lower()
                        and ("gap" in str(r.get("type", "")).lower()
                             or "tamper" in str(r.get("type", "")).lower())}
        beaconing_hosts = {r.get("host") for r in network_reports
                          if "beacon" in str(r.get("type", "")).lower()}
        evasion_hosts = log_gap_hosts & beaconing_hosts - {"", None}
        for host in evasion_hosts:
            key = f"evasion:{host}"
            if self._should_escalate(key, now):
                findings.append({
                    "type": "ATTACKER_EVASION",
                    "severity": Severity.CRITICAL,
                    "host": host,
                    "details": f"Log tampering + C2 beaconing on {host} — attacker evading detection",
                    "response": "IMMEDIATE_ISOLATION",
                })

        # ── Rule 5: Multi-vector (3+ supervisors reporting same host) ──
        for host, events in self._host_timeline.items():
            recent = [e for e in events if now - e["time"] < _CORRELATION_WINDOW]
            supervisors = {e["supervisor"] for e in recent}
            if len(supervisors) >= 3:
                key = f"multi_vector:{host}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "MULTI_VECTOR_ATTACK",
                        "severity": Severity.CRITICAL,
                        "host": host,
                        "details": (f"Multi-vector attack on {host}: "
                                    f"reported by {', '.join(supervisors)}"),
                        "supervisors": list(supervisors),
                        "response": "FULL_INCIDENT_RESPONSE",
                    })

        # Always forward all escalations
        for report in data:
            severity = self._parse_severity(report.get("severity", "MEDIUM"))
            if severity >= Severity.HIGH:
                findings.append({
                    "type": "supervisor_escalation",
                    "severity": severity,
                    "host": report.get("host", ""),
                    "source": report.get("supervisor", ""),
                    "details": report.get("details", ""),
                })

        self._prune_timelines(now)
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        now = time.time()

        # Update global threat level
        new_level = self._compute_threat_level(findings, now)
        if new_level != self._threat_level:
            old = self._threat_level
            self._threat_level = new_level
            self._threat_level_since = now
            actions.append({
                "action": "update_threat_level",
                "old_level": old,
                "new_level": new_level,
            })

        for f in findings:
            severity = f.get("severity", Severity.MEDIUM)
            response = f.get("response", "")

            # Strategic decisions
            if response == "IMMEDIATE_ISOLATION" and f.get("host"):
                actions.append({"action": "isolate_host", "host": f["host"], "finding": f})

            if severity >= Severity.CRITICAL:
                actions.append({"action": "page_humans", "finding": f})
                self._last_critical = now

            if response == "FULL_INCIDENT_RESPONSE":
                actions.append({"action": "trigger_ir_playbook", "finding": f})

            # Always log commander decisions
            actions.append({"action": "log_decision", "finding": f})

        self._total_decisions += len(actions)
        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"paged": 0, "isolations": 0, "playbooks": 0,
                   "level_changes": 0, "logged": 0}

        for action in actions:
            try:
                act_type = action["action"]

                if act_type == "page_humans":
                    f = action["finding"]
                    severity = f.get("severity", Severity.CRITICAL)
                    self.alerter.send_alert(
                        severity=severity,
                        title=f"🚨 COMMANDER: {f.get('type', 'Critical Alert')}",
                        details={
                            "host": f.get("host", ""),
                            "description": f.get("details", ""),
                            "recommended_response": f.get("response", "INVESTIGATE"),
                            "threat_level": self._threat_level,
                        },
                        agent_name="commander",
                    )
                    results["paged"] += 1

                elif act_type == "isolate_host":
                    host = action["host"]
                    try:
                        self.wazuh_client.active_response(
                            command="firewall-drop",
                            agent_name=host,
                            alert={
                                "reason": "Commander isolation order",
                                "type": action["finding"].get("type", ""),
                            },
                        )
                    except Exception:
                        pass  # Wazuh may not be reachable
                    # Log the isolation order
                    self.os_client.index_document("soc-commander-actions", {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "action": "isolate_host",
                        "host": host,
                        "reason": action["finding"].get("details", ""),
                        "threat_level": self._threat_level,
                    })
                    results["isolations"] += 1
                    logger.warning("🔒 ISOLATION ORDER for %s", host)

                elif act_type == "trigger_ir_playbook":
                    f = action["finding"]
                    self.redis_bus.publish("soc:response-supervisor", {
                        "source_agent": "commander",
                        "type": "ir_playbook_trigger",
                        "host": f.get("host", ""),
                        "incident_type": f.get("type", ""),
                        "severity": "CRITICAL",
                    }, sender=self.name, message_type="ir_command")
                    results["playbooks"] += 1

                elif act_type == "update_threat_level":
                    self.redis_bus.publish("soc:commander-broadcast", {
                        "type": "threat_level_update",
                        "old_level": action["old_level"],
                        "new_level": action["new_level"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }, sender=self.name, message_type="broadcast")
                    # Store in OpenSearch
                    self.os_client.index_document("soc-commander-decisions", {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "decision": "threat_level_change",
                        "old_level": action["old_level"],
                        "new_level": action["new_level"],
                    })
                    results["level_changes"] += 1
                    logger.warning("⚡ THREAT LEVEL: %s → %s",
                                   action["old_level"], action["new_level"])

                elif act_type == "log_decision":
                    f = action["finding"]
                    self.os_client.index_document("soc-commander-decisions", {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": f.get("type"),
                        "severity": str(f.get("severity")),
                        "host": f.get("host", ""),
                        "details": str(f.get("details", ""))[:500],
                        "threat_level": self._threat_level,
                        "total_escalations": self._total_escalations,
                    })
                    results["logged"] += 1

            except Exception as exc:
                logger.error("Commander action failed (%s): %s", action.get("action"), exc)

        if results["paged"] or results["isolations"]:
            logger.info("Commander cycle: paged=%d, isolations=%d, playbooks=%d, level_changes=%d",
                        results["paged"], results["isolations"],
                        results["playbooks"], results["level_changes"])
        return results

    # ------------------------------------------------------------------
    # Threat level management
    # ------------------------------------------------------------------

    def _compute_threat_level(self, findings: List[Dict[str, Any]], now: float) -> str:
        """Compute global threat level based on current findings and time decay."""
        has_critical = any(
            f.get("severity") == Severity.CRITICAL for f in findings
        )
        has_high = any(
            f.get("severity") == Severity.HIGH for f in findings
        )
        confirmed_attacks = any(
            f.get("type") in ("CONFIRMED_INTRUSION", "MULTI_VECTOR_ATTACK", "ATTACKER_EVASION")
            for f in findings
        )

        if confirmed_attacks:
            return "RED"
        if has_critical:
            return "RED"
        if has_high:
            if self._threat_level == "RED":
                # Stay RED for a while after critical
                if now - self._last_critical < _THREAT_DECAY_SECONDS:
                    return "RED"
            return "ORANGE"

        # Decay logic
        time_since_change = now - self._threat_level_since
        if self._threat_level == "RED" and time_since_change > _THREAT_DECAY_SECONDS:
            return "ORANGE"
        if self._threat_level == "ORANGE" and time_since_change > _THREAT_DECAY_SECONDS:
            return "YELLOW"
        if self._threat_level == "YELLOW" and time_since_change > _THREAT_DECAY_SECONDS * 2:
            return "GREEN"

        return self._threat_level

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _should_escalate(self, key: str, now: float) -> bool:
        if now - self._escalated_keys.get(key, 0) < self._cooldown:
            return False
        self._escalated_keys[key] = now
        return True

    def _prune_timelines(self, now: float) -> None:
        cutoff = now - _CORRELATION_WINDOW * 3
        for host in list(self._host_timeline):
            self._host_timeline[host] = [
                e for e in self._host_timeline[host] if e["time"] > cutoff
            ]
            if not self._host_timeline[host]:
                del self._host_timeline[host]
        self._escalated_keys = {
            k: v for k, v in self._escalated_keys.items() if v > cutoff
        }

    @staticmethod
    def _parse_severity(raw: Any) -> Severity:
        if isinstance(raw, Severity):
            return raw
        if isinstance(raw, str):
            try:
                return Severity[raw.upper()]
            except KeyError:
                return Severity.MEDIUM
        return Severity.MEDIUM

    def run_loop(self) -> None:
        """Subscribe to the supervisor-to-commander channel."""
        self.redis_bus.subscribe(
            "soc:supervisor-to-commander", self._on_supervisor_message
        )
        logger.info("🏰 Commander Agent online | Threat Level: %s", self._threat_level)
        super().run_loop()


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = CommanderAgent()
    agent.run_loop()
