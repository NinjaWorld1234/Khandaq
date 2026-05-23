"""
SOC Platform - Worker Agent W44: API Security Monitor
وكيل مراقبة أمن واجهات البرمجة

Detects API abuse patterns from web server logs (Wazuh):
- Rate limit violations (>1000 req/hour from single source)
- Unauthorized API access (401/403 responses)
- API key abuse (same key from multiple IPs)
- Unusual API endpoints accessed
- Large response sizes (data scraping)
- GraphQL introspection queries
- API versioning attacks (accessing deprecated endpoints)

Interval: 60 seconds
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w44_api_security")

# Deprecated API versions that should no longer be in use
_DEPRECATED_VERSIONS = {"v1", "v0", "v2.0-beta", "v1.0", "v1.1"}

# Endpoints that are high-value targets for enumeration
_SENSITIVE_ENDPOINTS = {
    "/api/users", "/api/admin", "/api/config", "/api/tokens",
    "/api/keys", "/api/secrets", "/api/export", "/api/backup",
    "/api/internal", "/api/debug", "/api/swagger", "/api/graphql",
}

_GRAPHQL_INTROSPECTION_KEYWORDS = {"__schema", "__type", "introspectionquery"}


class APISecurityAgent(BaseAgent):
    """
    API Security Monitor (W44).
    Monitors web server / API gateway logs for abuse patterns.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w44_api_security",
            description="Monitors API access patterns and detects abuse",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )

        # Thresholds
        self._rate_limit_threshold: int = self._agent_config.get("rate_limit_threshold", 1000)
        self._unauth_threshold: int = self._agent_config.get("unauth_threshold", 20)
        self._key_ip_threshold: int = self._agent_config.get("key_ip_threshold", 3)
        self._large_response_bytes: int = self._agent_config.get("large_response_bytes", 10_000_000)
        self._scraping_count: int = self._agent_config.get("scraping_count", 50)

        # State tracking across cycles
        self._ip_request_counts: Dict[str, int] = defaultdict(int)
        self._key_to_ips: Dict[str, Set[str]] = defaultdict(set)
        self._ip_unauth_counts: Dict[str, int] = defaultdict(int)
        self._last_reset: float = time.time()

        # Cooldown cache to prevent duplicate alerts
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown: int = 600

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[List[Dict[str, Any]]]:
        """Fetch web server / API gateway logs from Wazuh alerts."""
        query = {
            "bool": {
                "should": [
                    {"match": {"rule.groups": "web"}},
                    {"match": {"rule.groups": "nginx"}},
                    {"match": {"rule.groups": "apache"}},
                    {"match": {"data.url": "/api/"}},
                ],
                "minimum_should_match": 1,
            }
        }
        try:
            events = self.os_client.get_events_since(
                index="wazuh-alerts-*", minutes=2, query=query, size=5000,
            )
            # Reset hourly counters every 60 minutes
            if time.time() - self._last_reset > 3600:
                self._ip_request_counts.clear()
                self._key_to_ips.clear()
                self._ip_unauth_counts.clear()
                self._last_reset = time.time()
            return events
        except Exception as exc:
            logger.error("Failed to collect API events: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze API logs for abuse patterns."""
        findings: List[Dict[str, Any]] = []
        large_response_ips: Dict[str, int] = defaultdict(int)

        for event in data:
            src_ip = event.get("data", {}).get("srcip", event.get("agent", {}).get("ip", "unknown"))
            url = event.get("data", {}).get("url", "")
            status_code = str(event.get("data", {}).get("status", ""))
            api_key = event.get("data", {}).get("api_key", event.get("data", {}).get("id", ""))
            response_size = int(event.get("data", {}).get("bytes", 0) or 0)
            request_body = event.get("data", {}).get("data", "").lower()

            # Update per-IP request counter
            self._ip_request_counts[src_ip] += 1

            # Track API key to IP mapping
            if api_key:
                self._key_to_ips[api_key].add(src_ip)

            # Rule 1: Unauthorized access tracking (401/403)
            if status_code in ("401", "403"):
                self._ip_unauth_counts[src_ip] += 1

            # Rule 2: Large response sizes (scraping detection)
            if response_size > self._large_response_bytes:
                large_response_ips[src_ip] += 1

            # Rule 3: GraphQL introspection queries
            if "/graphql" in url.lower() or "/api/graphql" in url.lower():
                if any(kw in request_body for kw in _GRAPHQL_INTROSPECTION_KEYWORDS):
                    findings.append({
                        "rule": "graphql_introspection",
                        "severity": Severity.MEDIUM,
                        "source_ip": src_ip,
                        "url": url,
                        "description": f"GraphQL introspection query from {src_ip}",
                    })

            # Rule 4: Deprecated API version access
            url_lower = url.lower()
            for version in _DEPRECATED_VERSIONS:
                if f"/api/{version}/" in url_lower or f"/{version}/api/" in url_lower:
                    findings.append({
                        "rule": "deprecated_api_version",
                        "severity": Severity.MEDIUM,
                        "source_ip": src_ip,
                        "url": url,
                        "version": version,
                        "description": f"Access to deprecated API {version} from {src_ip}: {url}",
                    })
                    break

            # Rule 5: Sensitive/unusual endpoint access
            for endpoint in _SENSITIVE_ENDPOINTS:
                if url_lower.startswith(endpoint):
                    findings.append({
                        "rule": "sensitive_endpoint",
                        "severity": Severity.LOW,
                        "source_ip": src_ip,
                        "url": url,
                        "description": f"Sensitive API endpoint accessed by {src_ip}: {url}",
                    })
                    break

        # Rule 6: Rate limit violations (aggregated check)
        for ip, count in self._ip_request_counts.items():
            if count >= self._rate_limit_threshold:
                findings.append({
                    "rule": "rate_limit_violation",
                    "severity": Severity.HIGH,
                    "source_ip": ip,
                    "request_count": count,
                    "threshold": self._rate_limit_threshold,
                    "description": f"Rate limit exceeded: {count} requests/hour from {ip}",
                })

        # Rule 7: API key used from multiple IPs
        for key, ips in self._key_to_ips.items():
            if len(ips) >= self._key_ip_threshold:
                findings.append({
                    "rule": "api_key_abuse",
                    "severity": Severity.HIGH,
                    "api_key": key[:8] + "***",
                    "source_ips": list(ips),
                    "unique_ips": len(ips),
                    "description": f"API key {key[:8]}*** used from {len(ips)} different IPs",
                })

        # Unauthorized access threshold
        for ip, count in self._ip_unauth_counts.items():
            if count >= self._unauth_threshold:
                findings.append({
                    "rule": "unauthorized_access_flood",
                    "severity": Severity.HIGH,
                    "source_ip": ip,
                    "unauth_count": count,
                    "description": f"Excessive unauthorized attempts: {count} 401/403 responses for {ip}",
                })

        # Data scraping detection via large responses
        for ip, count in large_response_ips.items():
            if count >= self._scraping_count:
                findings.append({
                    "rule": "data_scraping",
                    "severity": Severity.CRITICAL,
                    "source_ip": ip,
                    "large_responses": count,
                    "description": f"Possible data scraping: {count} large responses sent to {ip}",
                })

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Determine actions for each finding, with cooldown deduplication."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            alert_key = f"{finding['rule']}:{finding.get('source_ip', finding.get('api_key', ''))}"
            last = self._alerted_cache.get(alert_key, 0.0)
            if now - last < self._alert_cooldown:
                continue

            actions.append({
                "type": "alert",
                "severity": finding["severity"],
                "title": f"API Security: {finding['rule'].replace('_', ' ').title()}",
                "details": {k: v for k, v in finding.items() if k != "severity"},
                "alert_key": alert_key,
            })

            if finding["severity"] >= Severity.HIGH:
                actions.append({"type": "escalate", "finding": finding})

            actions.append({"type": "log_incident", "finding": finding})

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alert, escalation, and logging actions."""
        alerts_sent = 0
        escalations = 0
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
                    self._alerted_cache[action["alert_key"]] = time.time()

            elif action["type"] == "escalate":
                self.report_to_supervisor({
                    "type": "api_security_escalation",
                    **action["finding"],
                })
                escalations += 1

            elif action["type"] == "log_incident":
                try:
                    finding = action["finding"]
                    self.os_client.index_document(
                        index="soc-api-security-incidents",
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name,
                            "rule": finding["rule"],
                            "severity": finding["severity"].name,
                            "source_ip": finding.get("source_ip"),
                            "description": finding["description"],
                        },
                    )
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log API security incident: %s", exc)

        # Prune expired cooldown entries
        cutoff = time.time() - self._alert_cooldown * 2
        self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent:
            self.report_to_supervisor({
                "type": "api_security_summary",
                "alerts_sent": alerts_sent,
                "escalations": escalations,
                "incidents_logged": incidents_logged,
            })

        return {"alerts_sent": alerts_sent, "escalations": escalations, "incidents_logged": incidents_logged}


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
    agent = APISecurityAgent()
    agent.run_loop()
