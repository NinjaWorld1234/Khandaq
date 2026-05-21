# SOC Platform - Infrastructure Supervisor Agent
# المشرف على البنية التحتية - ينسق بين وكلاء العمال ويتخذ قرارات محلية
"""
Infrastructure Supervisor
=========================

Subscribes to Redis channels from its worker agents and performs
**cross-agent alert correlation** to detect multi-stage attacks:

Workers monitored:
    - **W12**: Log Tampering Detection
    - **W37**: Brute Force Detection
    - **W36**: Canary Tokens
    - **W29**: Lateral Movement / Network Scanning
    - **W43**: Data Exfiltration Detection
    - **W46**: Agent Health Monitoring

Correlation rules:
    1. **Defense Evasion**: W46 reports agent down + W12 reports log gap
       from the same host → CRITICAL escalation.
    2. **Confirmed Intrusion**: W36 canary triggered + W37 brute force
       from the same IP → CRITICAL escalation.
    3. **Covering Tracks**: W12 tampering on the same host as any other
       alert → escalate severity.

Autonomous decisions (no commander approval needed):
    - Auto-isolate host if canary token triggered
    - Auto-block IP if brute force confirmed

Escalates correlated alerts to the commander via Redis.

Interval: 10 seconds (must be responsive)
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.redis_bus import (
    CHANNEL_SUPERVISOR_TO_COMMANDER,
    RedisBus,
)
from shared.wazuh_client import WazuhClient

logger = logging.getLogger("soc.agent.s01_infra_supervisor")

# ---------------------------------------------------------------------------
# Constants / ثوابت
# ---------------------------------------------------------------------------

# Redis channels this supervisor subscribes to
# قنوات ريديس التي يشترك فيها المشرف
WORKER_CHANNELS: dict[str, str] = {
    "W12": "soc:agent-to-supervisor",  # All workers report on the shared channel
    "W37": "soc:agent-to-supervisor",
    "W36": "soc:agent-to-supervisor",
    "W29": "soc:agent-to-supervisor",
    "W43": "soc:agent-to-supervisor",
    "W46": "soc:agent-to-supervisor",
}

# Worker name mapping for identification in messages
WORKER_NAMES: dict[str, str] = {
    "w12_log_tampering": "W12",
    "w37_brute_force": "W37",
    "w36_canary_tokens": "W36",
    "w29_lateral_movement": "W29",
    "w43_data_exfiltration": "W43",
    "w46_system_health": "W46",
}

# Correlation window – alerts within this time window are correlated (seconds)
# نافذة الارتباط – التنبيهات ضمن هذه الفترة يتم ربطها
CORRELATION_WINDOW_SECONDS = 300  # 5 minutes

# Maximum alerts to retain in the correlation buffer
MAX_BUFFER_SIZE = 1000


@dataclass
class CorrelatedAlert:
    """
    A time-stamped alert from a worker, stored in the correlation buffer.
    تنبيه مؤرخ من وكيل عامل، مخزن في ذاكرة الارتباط
    """
    worker_id: str
    received_at: float  # time.time()
    alert_data: dict[str, Any]
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    severity: str = "INFO"


class InfraSupervisor(BaseAgent):
    """
    Infrastructure Supervisor – correlates alerts from worker agents
    and makes autonomous response decisions.
    المشرف على البنية التحتية – يربط التنبيهات ويتخذ قرارات استجابة ذاتية
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="s01_infra_supervisor",
            description="Infrastructure Supervisor – cross-agent correlation and autonomous response",
            interval_seconds=10,
            config=config,
        )

        self._wazuh: Optional[WazuhClient] = None

        # Correlation buffer – recent alerts from workers
        # ذاكرة الارتباط – التنبيهات الأخيرة من العمال
        self._alert_buffer: list[CorrelatedAlert] = []
        self._buffer_lock = threading.Lock()

        # Track which correlations have already been processed (avoid re-alerting)
        self._processed_correlations: set[str] = set()

        # Track auto-isolation and auto-block actions to avoid duplicates
        self._isolated_hosts: set[str] = set()
        self._blocked_ips: set[str] = set()

        # Subscriber started flag
        self._subscriber_started = False

        # Decision log for auditing
        self._decision_log: list[dict[str, Any]] = []

    @property
    def wazuh(self) -> WazuhClient:
        """Lazy-initialize Wazuh client."""
        if self._wazuh is None:
            self._wazuh = WazuhClient(self.config)
        return self._wazuh

    # ------------------------------------------------------------------
    # Redis subscription / الاشتراك في ريديس
    # ------------------------------------------------------------------
    def _start_subscriber(self) -> None:
        """
        Subscribe to the agent-to-supervisor channel and feed alerts
        into the correlation buffer.
        """
        def _on_message(message: dict[str, Any]) -> None:
            """Callback for incoming Redis messages from workers."""
            sender = message.get("sender", "unknown")
            payload = message.get("payload", {})

            # Map sender name to worker ID
            worker_id = WORKER_NAMES.get(sender, sender.upper())

            # Extract alert details from payload
            hostname = (
                payload.get("hostname")
                or payload.get("details", {}).get("hostname")
            )
            source_ip = (
                payload.get("source_ip")
                or payload.get("details", {}).get("source_ip")
            )
            severity = payload.get("severity", "INFO")

            correlated = CorrelatedAlert(
                worker_id=worker_id,
                received_at=time.time(),
                alert_data=payload,
                hostname=hostname,
                source_ip=source_ip,
                severity=severity,
            )

            with self._buffer_lock:
                self._alert_buffer.append(correlated)
                if len(self._alert_buffer) > MAX_BUFFER_SIZE:
                    self._alert_buffer = self._alert_buffer[-MAX_BUFFER_SIZE:]

            logger.debug(
                "Buffered alert from %s: hostname=%s, ip=%s",
                worker_id, hostname, source_ip,
            )

        try:
            self.redis_bus.subscribe("soc:agent-to-supervisor", _on_message)
            self._subscriber_started = True
            logger.info("📡 Subscribed to agent-to-supervisor channel")
        except Exception as exc:
            logger.error("Failed to subscribe to worker channel: %s", exc)

    # ------------------------------------------------------------------
    # Buffer management / إدارة ذاكرة الارتباط
    # ------------------------------------------------------------------
    def _get_recent_alerts(
        self,
        worker_id: Optional[str] = None,
        hostname: Optional[str] = None,
        source_ip: Optional[str] = None,
        window_seconds: int = CORRELATION_WINDOW_SECONDS,
    ) -> list[CorrelatedAlert]:
        """Retrieve alerts from the buffer matching filters within the window."""
        cutoff = time.time() - window_seconds
        results: list[CorrelatedAlert] = []

        with self._buffer_lock:
            for alert in self._alert_buffer:
                if alert.received_at < cutoff:
                    continue
                if worker_id and alert.worker_id != worker_id:
                    continue
                if hostname and alert.hostname != hostname:
                    continue
                if source_ip and alert.source_ip != source_ip:
                    continue
                results.append(alert)

        return results

    def _cleanup_old_alerts(self) -> None:
        """Remove alerts older than 2x the correlation window."""
        cutoff = time.time() - CORRELATION_WINDOW_SECONDS * 2
        with self._buffer_lock:
            self._alert_buffer = [a for a in self._alert_buffer if a.received_at >= cutoff]

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> dict[str, Any]:
        """Start subscriber if needed and return current buffer snapshot."""
        if not self._subscriber_started:
            self._start_subscriber()

        with self._buffer_lock:
            snapshot = list(self._alert_buffer)

        return {
            "buffer_size": len(snapshot),
            "alerts": snapshot,
        }

    # ------------------------------------------------------------------
    # Analyze: correlation rules / تحليل: قواعد الارتباط
    # ------------------------------------------------------------------
    def analyze(self, data: Any) -> list[dict[str, Any]]:
        """Run all correlation rules against the current buffer."""
        findings: list[dict[str, Any]] = []

        # Rule 1: Defense Evasion
        # W46 agent down + W12 log gap from same host = CRITICAL
        findings.extend(self._correlate_defense_evasion())

        # Rule 2: Confirmed Intrusion
        # W36 canary triggered + W37 brute force from same IP = CRITICAL
        findings.extend(self._correlate_confirmed_intrusion())

        # Rule 3: Covering Tracks
        # W12 tampering on same host as any other alert = escalate
        findings.extend(self._correlate_covering_tracks())

        return findings

    def _correlate_defense_evasion(self) -> list[dict[str, Any]]:
        """W46 agent down + W12 log gap from same host → defense evasion."""
        findings: list[dict[str, Any]] = []
        w46_alerts = self._get_recent_alerts(worker_id="W46")

        for health_alert in w46_alerts:
            host = health_alert.hostname
            if not host:
                continue
            w12_alerts = self._get_recent_alerts(worker_id="W12", hostname=host)
            if w12_alerts:
                key = f"defense_evasion:{host}"
                if key in self._processed_correlations:
                    continue
                self._processed_correlations.add(key)
                findings.append({
                    "type": "defense_evasion",
                    "hostname": host,
                    "w46_alert": health_alert.alert_data.get("title", ""),
                    "w12_count": len(w12_alerts),
                    "w12_first": w12_alerts[0].alert_data.get("title", ""),
                })

        return findings

    def _correlate_confirmed_intrusion(self) -> list[dict[str, Any]]:
        """W36 canary triggered + W37 brute force from same IP → confirmed intrusion."""
        findings: list[dict[str, Any]] = []
        w36_alerts = self._get_recent_alerts(worker_id="W36")

        for canary_alert in w36_alerts:
            ip = canary_alert.source_ip
            if not ip:
                # Try to find IP in alert metadata
                details = canary_alert.alert_data.get("details", {})
                ip = details.get("source_ip")
            if not ip:
                continue

            w37_alerts = self._get_recent_alerts(worker_id="W37", source_ip=ip)
            if w37_alerts:
                key = f"confirmed_intrusion:{ip}"
                if key in self._processed_correlations:
                    continue
                self._processed_correlations.add(key)
                findings.append({
                    "type": "confirmed_intrusion",
                    "source_ip": ip,
                    "hostname": canary_alert.hostname,
                    "canary_alert": canary_alert.alert_data.get("title", ""),
                    "brute_force_count": len(w37_alerts),
                    "wazuh_agent_id": canary_alert.alert_data.get("details", {}).get("wazuh_agent_id"),
                })

        return findings

    def _correlate_covering_tracks(self) -> list[dict[str, Any]]:
        """W12 tampering + any other worker alert on same host → covering tracks."""
        findings: list[dict[str, Any]] = []
        w12_alerts = self._get_recent_alerts(worker_id="W12")

        for tamper_alert in w12_alerts:
            host = tamper_alert.hostname
            if not host:
                continue

            correlated_workers: list[str] = []
            for wid in ["W37", "W36", "W29", "W43", "W46"]:
                if self._get_recent_alerts(worker_id=wid, hostname=host):
                    correlated_workers.append(wid)

            if correlated_workers:
                key = f"covering_tracks:{host}:{','.join(sorted(correlated_workers))}"
                if key in self._processed_correlations:
                    continue
                self._processed_correlations.add(key)
                findings.append({
                    "type": "covering_tracks",
                    "hostname": host,
                    "tamper_alert": tamper_alert.alert_data.get("title", ""),
                    "correlated_workers": correlated_workers,
                })

        return findings

    # ------------------------------------------------------------------
    # Decide / قرار
    # ------------------------------------------------------------------
    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Map correlated findings to alert and response actions."""
        actions: list[dict[str, Any]] = []

        for finding in findings:
            ftype = finding["type"]

            if ftype == "defense_evasion":
                actions.append({
                    "alert": True,
                    "severity": Severity.CRITICAL,
                    "title": "🔴 CORRELATED: DEFENSE EVASION DETECTED",
                    "details": {
                        "hostname": finding["hostname"],
                        "correlation_rule": "defense_evasion",
                        "w46_alert": finding["w46_alert"],
                        "w12_alerts_count": finding["w12_count"],
                        "mitre_technique": "T1562.001 - Disable or Modify Tools",
                        "mitre_tactic": "Defense Evasion",
                    },
                    "escalate": True,
                })

            elif ftype == "confirmed_intrusion":
                actions.append({
                    "alert": True,
                    "severity": Severity.CRITICAL,
                    "title": "🔴 CORRELATED: CONFIRMED INTRUSION",
                    "details": {
                        "source_ip": finding["source_ip"],
                        "hostname": finding.get("hostname"),
                        "correlation_rule": "confirmed_intrusion",
                        "canary_alert": finding["canary_alert"],
                        "brute_force_count": finding["brute_force_count"],
                        "mitre_technique": "T1110 - Brute Force",
                        "mitre_tactic": "Credential Access",
                    },
                    "escalate": True,
                    "auto_block_ip": finding["source_ip"],
                    "auto_isolate_host": finding.get("hostname"),
                    "wazuh_agent_id": finding.get("wazuh_agent_id"),
                })

            elif ftype == "covering_tracks":
                actions.append({
                    "alert": True,
                    "severity": Severity.CRITICAL,
                    "title": "🔴 CORRELATED: ATTACKER COVERING TRACKS",
                    "details": {
                        "hostname": finding["hostname"],
                        "correlation_rule": "covering_tracks",
                        "tamper_alert": finding["tamper_alert"],
                        "correlated_workers": finding["correlated_workers"],
                        "mitre_technique": "T1070 - Indicator Removal",
                        "mitre_tactic": "Defense Evasion",
                    },
                    "escalate": True,
                })

        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Execute actions: send alerts, escalate to commander, and perform
        autonomous response (block IP, isolate host).
        """
        alerts_sent = 0
        escalations = 0
        ips_blocked = 0
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

            # Escalate to commander
            if action.get("escalate"):
                try:
                    self.redis_bus.escalate_to_commander(
                        sender=self.name,
                        payload={
                            "title": action["title"],
                            "severity": action["severity"].name,
                            "details": action["details"],
                        },
                    )
                    escalations += 1
                    logger.info("⬆️ Escalated to commander: %s", action["title"][:60])
                except Exception as exc:
                    logger.error("Commander escalation failed: %s", exc)

            # AUTO-BLOCK IP – no commander approval needed
            ip_to_block = action.get("auto_block_ip")
            if ip_to_block and ip_to_block not in self._blocked_ips:
                try:
                    logger.critical("🚫 AUTO-BLOCKING IP: %s", ip_to_block)
                    self.wazuh.block_ip(agent_id="all", ip_address=ip_to_block)
                    self._blocked_ips.add(ip_to_block)
                    ips_blocked += 1
                    self._log_decision("AUTO_BLOCK_IP", ip_to_block, "Brute force + canary confirmed")
                except Exception as exc:
                    logger.error("Failed to block IP %s: %s", ip_to_block, exc)

            # AUTO-ISOLATE HOST – no commander approval needed
            host_to_isolate = action.get("auto_isolate_host")
            wazuh_agent_id = action.get("wazuh_agent_id")
            if host_to_isolate and host_to_isolate not in self._isolated_hosts and wazuh_agent_id:
                try:
                    logger.critical("🔒 AUTO-ISOLATING HOST: %s", host_to_isolate)
                    self.wazuh.isolate_agent(wazuh_agent_id)
                    self._isolated_hosts.add(host_to_isolate)
                    hosts_isolated += 1
                    self._log_decision("AUTO_ISOLATE", host_to_isolate, f"Agent {wazuh_agent_id}")
                except Exception as exc:
                    logger.error("Failed to isolate host %s: %s", host_to_isolate, exc)

        # Cleanup old alerts and stale correlations
        self._cleanup_old_alerts()
        if len(self._processed_correlations) > 500:
            sorted_keys = sorted(self._processed_correlations)
            self._processed_correlations = set(sorted_keys[-250:])

        self._events_processed += 1
        self._metrics.inc_events(1)

        result = {
            "alerts_sent": alerts_sent,
            "escalations": escalations,
            "ips_blocked": ips_blocked,
            "hosts_isolated": hosts_isolated,
        }

        if any(v > 0 for v in result.values()):
            self.report_to_supervisor({
                "type": "supervisor_report",
                **result,
            })

        return result

    # ------------------------------------------------------------------
    # Decision logging / تسجيل القرارات
    # ------------------------------------------------------------------
    def _log_decision(self, action: str, target: str, reason: str) -> None:
        """Log an autonomous decision to OpenSearch for audit trail."""
        decision = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_name": self.name,
            "action": action,
            "target": target,
            "reason": reason,
        }
        self._decision_log.append(decision)
        try:
            self.os_client.index_document(index="soc-decisions", document=decision)
            logger.info("📝 Decision logged: %s → %s (%s)", action, target, reason[:80])
        except Exception as exc:
            logger.error("Failed to log decision: %s", exc)


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
    supervisor = InfraSupervisor()
    supervisor.run_loop()
