"""
SOC Platform – Response Supervisor
المشرف على وكلاء الاستجابة

Managed workers:
  W23 (Auto Case), W24 (Forensics), W25 (Reports), W26 (Smart Decision),
  W27 (Playbook Executor), W28 (Reinforcement Learning), W29 (Vulnerability)

Correlation rules:
  1. W29 critical vuln + active exploitation alert  → CRITICAL emergency patch
  2. W26 decision to isolate + W23 case created     → ensure playbook runs
  3. W29 vulnerability + W26 high-criticality asset  → priority patch
  4. Multiple W23 cases for same host in short window → escalate
  5. W28 feedback shows high FP rate → recommend tuning

Interval: 15 seconds
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

logger = logging.getLogger("soc.supervisor.response")

_CORRELATION_WINDOW = 600  # 10 minutes
_DAILY_SUMMARY_INTERVAL = 86400  # 24 hours


class ResponseSupervisor(BaseAgent):
    """
    Response Supervisor — coordinates incident response workflow.
    Tracks open cases, correlates vulnerability + exploitation, and
    ensures playbooks execute for confirmed incidents.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="response_supervisor",
            description="Coordinates incident response and case management",
            interval_seconds=15,
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        self._recent_alerts: List[Dict[str, Any]] = []
        # Track open cases per host
        self._open_cases: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # Track isolation decisions pending playbook confirmation
        self._pending_isolations: Dict[str, Dict[str, Any]] = {}
        # Vulnerability findings per host
        self._vuln_findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # Critical asset set from smart decision
        self._critical_assets: Set[str] = set()
        # FP rate feedback
        self._fp_rates: Dict[str, float] = {}
        self._last_daily_summary = 0.0
        self._escalated_keys: Dict[str, float] = {}
        self._cooldown = 300

    # ------------------------------------------------------------------
    # Redis handler
    # ------------------------------------------------------------------

    def _on_worker_message(self, message: dict) -> None:
        try:
            data = message if isinstance(message, dict) else json.loads(message)
            data["_received_at"] = time.time()
            data["_source"] = data.get("source_agent", data.get("agent_name", data.get("sender", "")))
            self._recent_alerts.append(data)
        except Exception as exc:
            logger.error("Failed to parse worker message: %s", exc)

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> List[Dict[str, Any]]:
        now = time.time()
        self._recent_alerts = [
            a for a in self._recent_alerts
            if now - a.get("_received_at", 0) < 900
        ]
        batch = list(self._recent_alerts)
        self._recent_alerts.clear()
        return batch

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        now = time.time()

        for alert in data:
            source = alert.get("_source", "")
            host = alert.get("host", "")
            severity = self._parse_severity(alert.get("severity", "MEDIUM"))

            # Categorize
            if "auto_case" in source.lower() or "w23" in source.lower():
                self._open_cases[host].append({"time": now, "alert": alert})
            elif "smart_decision" in source.lower() or "w26" in source.lower():
                decision = alert.get("decision", "")
                if "isolate" in str(decision).lower():
                    self._pending_isolations[host] = {"time": now, "alert": alert}
                if alert.get("asset_criticality") == "critical":
                    self._critical_assets.add(host)
            elif "vulnerability" in source.lower() or "w29" in source.lower():
                self._vuln_findings[host].append({"time": now, "alert": alert})
            elif "reinforcement" in source.lower() or "w28" in source.lower():
                for rule_id, fp_rate in alert.get("fp_rates", {}).items():
                    self._fp_rates[rule_id] = fp_rate

            # Forward HIGH/CRITICAL
            if severity >= Severity.HIGH:
                findings.append({
                    "type": "worker_escalation",
                    "source": source,
                    "severity": severity,
                    "host": host,
                    "details": alert,
                })

        # ── Rule 1: Critical vuln + active exploitation ──
        for host, vulns in self._vuln_findings.items():
            critical_vulns = [
                v for v in vulns
                if now - v["time"] < _CORRELATION_WINDOW
                and v["alert"].get("cvss", 0) >= 9.0
            ]
            active_cases = [
                c for c in self._open_cases.get(host, [])
                if now - c["time"] < _CORRELATION_WINDOW
            ]
            if critical_vulns and active_cases:
                key = f"vuln_exploit:{host}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "VULNERABILITY_UNDER_EXPLOITATION",
                        "severity": Severity.CRITICAL,
                        "host": host,
                        "details": (f"Critical vulnerability on {host} with "
                                    f"{len(active_cases)} active cases — emergency patch required"),
                        "vuln_count": len(critical_vulns),
                        "case_count": len(active_cases),
                    })

        # ── Rule 2: Isolation decision + ensure playbook ──
        for host, iso in list(self._pending_isolations.items()):
            if now - iso["time"] > _CORRELATION_WINDOW:
                del self._pending_isolations[host]
                continue
            cases = self._open_cases.get(host, [])
            recent_cases = [c for c in cases if now - c["time"] < _CORRELATION_WINDOW]
            if recent_cases:
                key = f"iso_playbook:{host}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "ISOLATION_PLAYBOOK_TRIGGER",
                        "severity": Severity.HIGH,
                        "host": host,
                        "details": f"Host {host} isolation decided — triggering incident response playbook",
                    })

        # ── Rule 3: Vulnerability on critical asset ──
        for host in self._critical_assets:
            vulns = [
                v for v in self._vuln_findings.get(host, [])
                if now - v["time"] < 3600
            ]
            if vulns:
                key = f"vuln_critical_asset:{host}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "CRITICAL_ASSET_VULNERABLE",
                        "severity": Severity.HIGH,
                        "host": host,
                        "details": f"Critical asset {host} has {len(vulns)} vulnerabilities — priority patch",
                        "vuln_count": len(vulns),
                    })

        # ── Rule 4: Multiple cases for same host ──
        for host, cases in self._open_cases.items():
            recent = [c for c in cases if now - c["time"] < _CORRELATION_WINDOW]
            if len(recent) >= 3:
                key = f"multi_case:{host}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "REPEATED_INCIDENTS",
                        "severity": Severity.HIGH,
                        "host": host,
                        "details": f"Host {host} has {len(recent)} cases in {_CORRELATION_WINDOW}s — possible ongoing attack",
                    })

        # ── Rule 5: High FP rate feedback ──
        for rule_id, rate in self._fp_rates.items():
            if rate > 0.85:
                key = f"fp_tune:{rule_id}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "HIGH_FALSE_POSITIVE_RATE",
                        "severity": Severity.LOW,
                        "details": f"Rule {rule_id} has {rate*100:.0f}% false positive rate — recommend tuning",
                        "rule_id": rule_id,
                        "fp_rate": rate,
                    })

        # ── Daily summary ──
        if now - self._last_daily_summary > _DAILY_SUMMARY_INTERVAL:
            self._last_daily_summary = now
            findings.append({
                "type": "DAILY_SUMMARY",
                "severity": Severity.LOW,
                "details": self._generate_daily_summary(),
            })

        self._prune(now)
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        for f in findings:
            severity = f.get("severity", Severity.MEDIUM)
            if severity >= Severity.HIGH:
                actions.append({"action": "escalate_to_commander", "finding": f})
            actions.append({"action": "log_event", "finding": f})
        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"escalated": 0, "logged": 0}
        for action in actions:
            try:
                f = action["finding"]
                if action["action"] == "escalate_to_commander":
                    payload = {
                        "supervisor": self.name,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": f.get("type"),
                        "severity": f["severity"].name
                            if hasattr(f.get("severity"), "name") else str(f.get("severity")),
                        "host": f.get("host", ""),
                        "details": f.get("details", ""),
                    }
                    self.redis_bus.publish(
                        "soc:supervisor-to-commander", payload,
                        sender=self.name, message_type="escalation",
                    )
                    results["escalated"] += 1

                elif action["action"] == "log_event":
                    self.os_client.index_document("soc-response-log", {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "supervisor": self.name,
                        "event_type": f.get("type"),
                        "severity": str(f.get("severity")),
                        "host": f.get("host", ""),
                        "details": str(f.get("details", ""))[:500],
                    })
                    results["logged"] += 1
            except Exception as exc:
                logger.error("Action failed: %s", exc)

        if results["escalated"]:
            logger.info("Cycle: %d escalated, %d logged", results["escalated"], results["logged"])
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _should_escalate(self, key: str, now: float) -> bool:
        if now - self._escalated_keys.get(key, 0) < self._cooldown:
            return False
        self._escalated_keys[key] = now
        return True

    def _prune(self, now: float) -> None:
        cutoff = now - _CORRELATION_WINDOW * 2
        for host in list(self._open_cases):
            self._open_cases[host] = [c for c in self._open_cases[host] if c["time"] > cutoff]
            if not self._open_cases[host]:
                del self._open_cases[host]
        for host in list(self._vuln_findings):
            self._vuln_findings[host] = [v for v in self._vuln_findings[host] if v["time"] > cutoff]
            if not self._vuln_findings[host]:
                del self._vuln_findings[host]
        self._escalated_keys = {k: v for k, v in self._escalated_keys.items() if v > cutoff}

    def _generate_daily_summary(self) -> str:
        total_cases = sum(len(c) for c in self._open_cases.values())
        total_vulns = sum(len(v) for v in self._vuln_findings.values())
        return (f"Daily Summary: {total_cases} open cases, {total_vulns} vulnerability findings, "
                f"{len(self._pending_isolations)} pending isolations, "
                f"{len(self._critical_assets)} critical assets tracked")

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
        self.redis_bus.subscribe(self.supervisor_channel, self._on_worker_message)
        super().run_loop()


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = ResponseSupervisor()
    agent.run_loop()
