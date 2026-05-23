"""
SOC Platform – Detection & Intelligence Supervisor
المشرف على وكلاء الكشف والاستخبارات

Managed workers:
  W13 (Anomaly Detection), W14 (ML Prediction), W15 (Kill Chain),
  W16 (Noise Reduction), W19 (Threat Feeds), W20 (IOC Aging),
  W21 (IOC Enrichment), W22 (Threat Hunting), W30 (Phishing),
  W31 (BEC), W35 (Honeypot), W38 (UEBA), W42 (Insider Threat),
  W43 (Secret Scanner)

Correlation rules:
  1. Anomaly + IOC match on same host         → CRITICAL (known threat)
  2. Enrichment confirms malicious IOC + alert → escalate severity
  3. Multiple anomalies across hosts           → campaign detection
  4. Honeypot hit + production traffic same IP → confirmed attacker
  5. UEBA + Insider DLP on same user           → compound insider risk

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
from shared.llm_client import LLMClient

logger = logging.getLogger("soc.supervisor.detection")

# Correlation time window (seconds)
_CORRELATION_WINDOW = 300  # 5 minutes
_CAMPAIGN_THRESHOLD = 3    # hosts with anomalies → campaign


class DetectionSupervisor(BaseAgent):
    """
    Detection & Intelligence Supervisor.
    Correlates events from detection and intel workers, escalates
    confirmed threats to the Commander.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="detection_supervisor",
            description="Correlates detection and intelligence events",
            interval_seconds=15,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        # Sliding windows keyed by host/user/ip
        self._recent_alerts: List[Dict[str, Any]] = []
        self._host_anomalies: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._ioc_matches: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._honeypot_ips: Set[str] = set()
        self._ueba_risks: Dict[str, float] = {}
        self._insider_risks: Dict[str, float] = {}
        self._escalated_keys: Dict[str, float] = {}
        self._escalate_cooldown = 300  # 5 min
        
        # Initialize LLM Client for RAG Analysis
        self._llm = LLMClient(config=self.config)

    # ------------------------------------------------------------------
    # Redis message handler
    # ------------------------------------------------------------------

    def _on_worker_message(self, message: dict) -> None:
        """Callback for messages from managed workers via Redis."""
        try:
            data = message if isinstance(message, dict) else json.loads(message)
            source = data.get("source_agent", data.get("agent_name", data.get("sender", "")))
            data["_received_at"] = time.time()
            data["_source"] = source
            self._recent_alerts.append(data)
            logger.debug("Received report from %s", source)
        except Exception as exc:
            logger.error("Failed to parse worker message: %s", exc)

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> List[Dict[str, Any]]:
        """Drain the in-memory buffer of worker reports."""
        now = time.time()
        # Prune stale entries (> 10 min old)
        self._recent_alerts = [
            a for a in self._recent_alerts
            if now - a.get("_received_at", 0) < 600
        ]
        batch = list(self._recent_alerts)
        self._recent_alerts.clear()
        return batch

    # ------------------------------------------------------------------
    # Analyze – correlation engine
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        now = time.time()

        for alert in data:
            source = alert.get("_source", "")
            host = alert.get("host", alert.get("agent_name", ""))
            severity_raw = alert.get("severity", "MEDIUM")
            severity = self._parse_severity(severity_raw)
            alert_type = alert.get("type", alert.get("rule", ""))
            src_ip = alert.get("src_ip", alert.get("source_ip", ""))

            # Categorize by source agent type
            if "anomaly" in source.lower() or "w13" in source.lower():
                self._host_anomalies[host].append({"time": now, "alert": alert})
            elif "threat_feed" in source.lower() or "w19" in source.lower():
                if "ioc" in str(alert).lower():
                    for h in self._host_anomalies:
                        self._ioc_matches[h].append({"time": now, "ioc_alert": alert})
            elif "honeypot" in source.lower() or "w35" in source.lower():
                if src_ip:
                    self._honeypot_ips.add(src_ip)
            elif "ueba" in source.lower() or "w38" in source.lower():
                user = alert.get("user", host)
                self._ueba_risks[user] = alert.get("risk_score", 0)
            elif "insider" in source.lower() or "w42" in source.lower():
                user = alert.get("user", host)
                self._insider_risks[user] = alert.get("risk_score", 0)

            # Always forward HIGH/CRITICAL
            if severity >= Severity.HIGH:
                findings.append({
                    "type": "worker_alert",
                    "source": source,
                    "severity": severity,
                    "host": host,
                    "details": alert,
                })

        # ── Correlation Rule 1: Anomaly + IOC match ──
        for host, anomalies in self._host_anomalies.items():
            recent_anomalies = [a for a in anomalies if now - a["time"] < _CORRELATION_WINDOW]
            ioc_hits = [m for m in self._ioc_matches.get(host, [])
                        if now - m["time"] < _CORRELATION_WINDOW]
            if recent_anomalies and ioc_hits:
                key = f"anomaly_ioc:{host}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "KNOWN_THREAT_CONFIRMED",
                        "severity": Severity.CRITICAL,
                        "host": host,
                        "details": f"Anomaly detected on {host} matches known IOC from threat feed",
                        "anomaly_count": len(recent_anomalies),
                        "ioc_count": len(ioc_hits),
                    })

        # ── Correlation Rule 3: Campaign detection ──
        hosts_with_anomalies = set()
        for host, anomalies in self._host_anomalies.items():
            if any(now - a["time"] < _CORRELATION_WINDOW for a in anomalies):
                hosts_with_anomalies.add(host)
        if len(hosts_with_anomalies) >= _CAMPAIGN_THRESHOLD:
            key = "campaign:" + ",".join(sorted(hosts_with_anomalies)[:5])
            if self._should_escalate(key, now):
                findings.append({
                    "type": "CAMPAIGN_DETECTED",
                    "severity": Severity.CRITICAL,
                    "details": f"Anomalies on {len(hosts_with_anomalies)} hosts indicate possible campaign",
                    "affected_hosts": list(hosts_with_anomalies)[:20],
                })

        # ── Correlation Rule 4: Honeypot IP in production ──
        for alert in data:
            src_ip = alert.get("src_ip", alert.get("source_ip", ""))
            if src_ip and src_ip in self._honeypot_ips:
                host = alert.get("host", "")
                key = f"honeypot_prod:{src_ip}:{host}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "HONEYPOT_IP_IN_PRODUCTION",
                        "severity": Severity.CRITICAL,
                        "host": host,
                        "src_ip": src_ip,
                        "details": f"IP {src_ip} seen in honeypot is now active in production on {host}",
                    })

        # ── Correlation Rule 5: UEBA + Insider threat ──
        for user in set(self._ueba_risks) & set(self._insider_risks):
            combined = self._ueba_risks[user] + self._insider_risks[user]
            if combined > 120:
                key = f"insider_ueba:{user}"
                if self._should_escalate(key, now):
                    findings.append({
                        "type": "COMPOUND_INSIDER_RISK",
                        "severity": Severity.CRITICAL,
                        "user": user,
                        "ueba_score": self._ueba_risks[user],
                        "dlp_score": self._insider_risks[user],
                        "details": f"User {user} has compound risk: UEBA={self._ueba_risks[user]}, DLP={self._insider_risks[user]}",
                    })

        # Prune old data
        self._prune_windows(now)
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        for f in findings:
            severity = f.get("severity", Severity.MEDIUM)
            actions.append({"action": "escalate_to_commander", "finding": f})
            if severity >= Severity.CRITICAL:
                actions.append({"action": "log_correlation", "finding": f})
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
                    # Perform RAG AI Analysis before escalating
                    ai_analysis = self._llm.rag_analyze_alert(f, self.os_client)
                    
                    payload = {
                        "supervisor": self.name,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": f.get("type", "detection_alert"),
                        "severity": f.get("severity", Severity.MEDIUM).name
                            if hasattr(f.get("severity"), "name")
                            else str(f.get("severity")),
                        "host": f.get("host", ""),
                        "details": f.get("details", ""),
                        "ai_analysis": ai_analysis,
                    }
                    self.redis_bus.publish(
                        "soc:supervisor-to-commander", payload,
                        sender=self.name, message_type="escalation",
                    )
                    results["escalated"] += 1

                elif action["action"] == "log_correlation":
                    doc = {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "supervisor": self.name,
                        "correlation_type": f.get("type"),
                        "severity": str(f.get("severity")),
                        "details": f.get("details"),
                        "host": f.get("host", ""),
                    }
                    self.os_client.index_document("soc-correlations", doc)
                    results["logged"] += 1
            except Exception as exc:
                logger.error("Action failed: %s", exc)

        if results["escalated"]:
            logger.info("Cycle: escalated %d, logged %d correlations",
                        results["escalated"], results["logged"])
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _should_escalate(self, key: str, now: float) -> bool:
        last = self._escalated_keys.get(key, 0)
        if now - last < self._escalate_cooldown:
            return False
        self._escalated_keys[key] = now
        return True

    def _prune_windows(self, now: float) -> None:
        cutoff = now - _CORRELATION_WINDOW * 2
        for host in list(self._host_anomalies):
            self._host_anomalies[host] = [
                a for a in self._host_anomalies[host] if a["time"] > cutoff
            ]
            if not self._host_anomalies[host]:
                del self._host_anomalies[host]
        for host in list(self._ioc_matches):
            self._ioc_matches[host] = [
                m for m in self._ioc_matches[host] if m["time"] > cutoff
            ]
            if not self._ioc_matches[host]:
                del self._ioc_matches[host]
        # Prune escalation cooldowns
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
        """Subscribe to the detection supervisor Redis channel before main loop."""
        self.redis_bus.subscribe(self.supervisor_channel, self._on_worker_message)
        super().run_loop()


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
    agent = DetectionSupervisor()
    agent.run_loop()
