"""
SOC Platform - Worker Agent W46: System Health Monitor
وكيل مراقبة صحة النظام

Monitors the health of all SOC platform components:
- OpenSearch cluster health
- Wazuh manager daemon status
- Suricata IDS running status
- Zeek NSM running status
- Kafka consumer group lag
- MISP platform availability
- AI agent heartbeats

Sends alerts when any component is down and produces a daily health summary.

Interval: 60 seconds
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.wazuh_client import WazuhClient

logger = logging.getLogger("soc.agent.w46_system_health")


class SystemHealthAgent(BaseAgent):
    """
    System Health Agent (W46) - monitors the SOC platform itself.
    وكيل صحة النظام - يراقب منصة مركز العمليات الأمنية نفسها

    The simplest agent: checks each component's availability and sends
    alerts if anything is unreachable or degraded.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w46_system_health",
            description="SOC Platform Health Monitor - monitors all SOC components",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )
        self._wazuh: Optional[WazuhClient] = None
        self._http = httpx.Client(timeout=10, verify=False)

        # Track last daily summary time (epoch)
        self._last_daily_summary: float = 0.0
        # Daily summary interval: 24 hours
        self._daily_interval = 86400

        # Component status history for trending
        self._status_history: list[dict[str, Any]] = []
        self._max_history = 1440  # Keep ~24 hours of 60s checks

        # Agent heartbeat tracking: agent_name -> last_seen_epoch
        self._agent_heartbeats: dict[str, float] = {}
        self._heartbeat_timeout = 300  # 5 minutes without heartbeat = stale

    @property
    def wazuh(self) -> WazuhClient:
        """Lazy-initialize Wazuh client."""
        if self._wazuh is None:
            self._wazuh = WazuhClient(self.config)
        return self._wazuh

    # ------------------------------------------------------------------
    # Collect: check all components / جمع: فحص جميع المكونات
    # ------------------------------------------------------------------

    def collect(self) -> dict[str, Any]:
        """
        Check health of every SOC component.

        Returns:
            Dict with component name -> health status dict.
        """
        checks: dict[str, Any] = {}

        # 1. OpenSearch cluster health
        checks["opensearch"] = self._check_opensearch()

        # 2. Wazuh manager status
        checks["wazuh"] = self._check_wazuh()

        # 3. Suricata (check via process or log freshness)
        checks["suricata"] = self._check_service_via_opensearch(
            index="filebeat-suricata-*",
            service_name="Suricata",
            max_age_minutes=5,
        )

        # 4. Zeek (check via log freshness)
        checks["zeek"] = self._check_service_via_opensearch(
            index="filebeat-zeek-*",
            service_name="Zeek",
            max_age_minutes=5,
        )

        # 5. Kafka lag (check via OpenSearch or direct)
        checks["kafka"] = self._check_kafka()

        # 6. MISP availability
        checks["misp"] = self._check_misp()

        # 7. AI agent heartbeats
        checks["agent_heartbeats"] = self._check_agent_heartbeats()

        checks["timestamp"] = datetime.now(timezone.utc).isoformat()
        return checks

    def _check_opensearch(self) -> dict[str, Any]:
        """Check OpenSearch cluster health."""
        try:
            return self.os_client.health_check()
        except Exception as exc:
            logger.error("OpenSearch health check failed: %s", exc)
            return {"healthy": False, "error": str(exc)}

    def _check_wazuh(self) -> dict[str, Any]:
        """Check Wazuh manager daemon status."""
        try:
            return self.wazuh.health_check()
        except Exception as exc:
            logger.error("Wazuh health check failed: %s", exc)
            return {"healthy": False, "error": str(exc)}

    def _check_service_via_opensearch(
        self,
        index: str,
        service_name: str,
        max_age_minutes: int = 5,
    ) -> dict[str, Any]:
        """
        Check if a service is producing logs by looking at recent events
        in its OpenSearch index.
        """
        try:
            events = self.os_client.get_events_since(
                index=index, minutes=max_age_minutes, size=1
            )
            is_active = len(events) > 0
            return {
                "healthy": is_active,
                "service": service_name,
                "recent_events": len(events),
                "check_method": "log_freshness",
            }
        except Exception as exc:
            logger.warning("%s health check failed: %s", service_name, exc)
            return {
                "healthy": False,
                "service": service_name,
                "error": str(exc),
                "check_method": "log_freshness",
            }

    def _check_kafka(self) -> dict[str, Any]:
        """
        Check Kafka health by looking for consumer lag metrics in OpenSearch
        or attempting a direct connection.
        """
        try:
            # Check if Kafka metrics are flowing into OpenSearch
            events = self.os_client.get_events_since(
                index="metricbeat-*",
                minutes=5,
                query={"match": {"metricset.name": "consumergroup"}},
                size=1,
            )
            if events:
                return {"healthy": True, "check_method": "metrics"}

            # Fallback: try direct HTTP (if Kafka REST proxy is available)
            kafka_url = self._agent_config.get("kafka_rest_url", "http://kafka:8082")
            resp = self._http.get(f"{kafka_url}/brokers", timeout=5)
            return {
                "healthy": resp.status_code == 200,
                "check_method": "rest_proxy",
            }
        except Exception as exc:
            return {
                "healthy": False,
                "error": str(exc),
                "check_method": "fallback",
            }

    def _check_misp(self) -> dict[str, Any]:
        """Check MISP availability via its API."""
        try:
            misp_cfg = self.config.misp
            resp = self._http.get(
                f"{misp_cfg.url}/servers/getPyMISPVersion.json",
                headers={"Authorization": misp_cfg.api_key},
                timeout=10,
            )
            return {
                "healthy": resp.status_code == 200,
                "status_code": resp.status_code,
            }
        except Exception as exc:
            return {"healthy": False, "error": str(exc)}

    def _check_agent_heartbeats(self) -> dict[str, Any]:
        """Check all registered AI agent heartbeats via Redis."""
        stale_agents: list[str] = []
        active_agents: list[str] = []
        now = time.time()

        try:
            # Read heartbeat keys from Redis
            keys = self.redis_bus.client.keys("soc:heartbeat:*")
            for key in keys:
                agent_name = key.split(":")[-1] if isinstance(key, str) else key.decode().split(":")[-1]
                heartbeat = self.redis_bus.get_state(key)
                if heartbeat and isinstance(heartbeat, dict):
                    last_seen = heartbeat.get("timestamp", 0)
                    if now - last_seen > self._heartbeat_timeout:
                        stale_agents.append(agent_name)
                    else:
                        active_agents.append(agent_name)
        except Exception as exc:
            logger.warning("Agent heartbeat check failed: %s", exc)
            return {"healthy": False, "error": str(exc)}

        return {
            "healthy": len(stale_agents) == 0,
            "active_agents": active_agents,
            "stale_agents": stale_agents,
        }

    # ------------------------------------------------------------------
    # Analyze: identify problems / تحليل: تحديد المشاكل
    # ------------------------------------------------------------------

    def analyze(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Analyze component health data and identify problems.

        Args:
            data: Component health status dict from collect().

        Returns:
            List of finding dicts with component, status, details.
        """
        findings: list[dict[str, Any]] = []

        for component, status in data.items():
            if component == "timestamp":
                continue

            if isinstance(status, dict) and not status.get("healthy", True):
                findings.append({
                    "component": component,
                    "status": "unhealthy",
                    "details": status,
                })

        # Track status for daily summary
        summary_entry = {
            "timestamp": time.time(),
            "total_components": len(data) - 1,  # Exclude 'timestamp' key
            "unhealthy_count": len(findings),
            "unhealthy_components": [f["component"] for f in findings],
        }
        self._status_history.append(summary_entry)
        if len(self._status_history) > self._max_history:
            self._status_history = self._status_history[-self._max_history:]

        return findings

    # ------------------------------------------------------------------
    # Decide: determine alerts / قرار: تحديد التنبيهات
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Decide what alerts to generate based on findings.

        Args:
            findings: List of unhealthy component findings.

        Returns:
            List of action dicts (alerts to send).
        """
        actions: list[dict[str, Any]] = []

        for finding in findings:
            component = finding["component"]
            details = finding["details"]

            # Determine severity based on component criticality
            if component in ("opensearch", "wazuh"):
                severity = Severity.CRITICAL
            elif component in ("suricata", "zeek"):
                severity = Severity.HIGH
            elif component == "agent_heartbeats":
                severity = Severity.MEDIUM
            else:
                severity = Severity.MEDIUM

            actions.append({
                "type": "alert",
                "severity": severity,
                "title": f"SOC Component Down: {component.upper()}",
                "details": {
                    "component": component,
                    "error": details.get("error", "Component unhealthy"),
                    "check_details": details,
                },
            })

        # Check if daily summary is due
        now = time.time()
        if now - self._last_daily_summary >= self._daily_interval:
            actions.append({
                "type": "daily_summary",
            })

        return actions

    # ------------------------------------------------------------------
    # Act: send alerts / تنفيذ: إرسال التنبيهات
    # ------------------------------------------------------------------

    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Execute decided actions (send alerts, generate summary).

        Args:
            actions: List of action dicts.

        Returns:
            Summary of actions taken.
        """
        alerts_sent = 0
        summary_generated = False

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

            elif action["type"] == "daily_summary":
                self._send_daily_summary()
                summary_generated = True
                self._last_daily_summary = time.time()

        # Update events processed
        self._events_processed += 1
        self._metrics.inc_events(1)

        # Report to supervisor
        if alerts_sent > 0 or summary_generated:
            self.report_to_supervisor({
                "type": "health_report",
                "alerts_sent": alerts_sent,
                "summary_generated": summary_generated,
            })

        return {
            "alerts_sent": alerts_sent,
            "summary_generated": summary_generated,
        }

    # ------------------------------------------------------------------
    # Daily summary / الملخص اليومي
    # ------------------------------------------------------------------

    def _send_daily_summary(self) -> None:
        """Generate and send a daily SOC health summary."""
        if not self._status_history:
            return

        total_checks = len(self._status_history)
        unhealthy_checks = sum(
            1 for s in self._status_history if s["unhealthy_count"] > 0
        )
        uptime_pct = (
            ((total_checks - unhealthy_checks) / total_checks * 100)
            if total_checks > 0
            else 0
        )

        # Find most frequently unhealthy components
        component_failures: dict[str, int] = {}
        for entry in self._status_history:
            for comp in entry.get("unhealthy_components", []):
                component_failures[comp] = component_failures.get(comp, 0) + 1

        # Sort by failure count
        top_failures = sorted(
            component_failures.items(), key=lambda x: x[1], reverse=True
        )[:5]

        summary_details = {
            "period": "24h",
            "total_checks": total_checks,
            "healthy_checks": total_checks - unhealthy_checks,
            "unhealthy_checks": unhealthy_checks,
            "uptime_percentage": f"{uptime_pct:.1f}%",
            "top_failures": {comp: count for comp, count in top_failures},
        }

        severity = Severity.INFO if uptime_pct >= 99 else (
            Severity.LOW if uptime_pct >= 95 else Severity.MEDIUM
        )

        self.alerter.send_alert(
            severity=severity,
            title="Daily SOC Health Summary",
            details=summary_details,
            agent_name=self.name,
            force=True,  # Always send daily summary (bypass rate limit)
        )

        # Log summary to OpenSearch
        try:
            self.os_client.index_document(
                index="soc-health-summary",
                document={
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    **summary_details,
                },
            )
        except Exception as exc:
            logger.error("Failed to log daily summary: %s", exc)

        # Clear history after summary
        self._status_history.clear()

        logger.info("Daily health summary sent: uptime=%.1f%%", uptime_pct)


# ---------------------------------------------------------------------------
# Entry point for standalone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = SystemHealthAgent()
    agent.run_loop()
