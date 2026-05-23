"""
SOC Platform - Worker Agent W32: WAF / Web Anomaly Detection
وكيل كشف شذوذ جدار حماية تطبيقات الويب

Monitors web server access logs from Wazuh (Apache/Nginx) and detects:
- Unusual HTTP methods (PUT, DELETE, TRACE, OPTIONS)
- Large number of 4xx errors from single IP (scanning)
- 5xx error spikes (exploitation attempts)
- Unusual User-Agent strings (sqlmap, nikto, dirbuster, gobuster)
- Path traversal attempts (../ patterns)
- Unusually large POST requests
- High request rate from single IP (>100 requests/min)

Interval: 60 seconds | Supervisor: soc:network-supervisor
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w32_waf")

# ---------------------------------------------------------------------------
# Detection constants
# ---------------------------------------------------------------------------

_UNUSUAL_METHODS: set[str] = {"PUT", "DELETE", "TRACE", "OPTIONS", "PATCH", "CONNECT"}

_SCANNER_UA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"sqlmap", r"nikto", r"dirbuster", r"gobuster", r"wfuzz", r"ffuf",
        r"nmap", r"masscan", r"nuclei", r"burpsuite", r"hydra",
        r"python-requests", r"curl/", r"wget/", r"zgrab", r"scanbot",
        r"acunetix", r"nessus", r"openvas", r"arachni",
    ]
]

_PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e[/%5c])", re.IGNORECASE)

# Thresholds
_4XX_THRESHOLD = 50       # errors per IP per window
_5XX_SPIKE_THRESHOLD = 20  # total 5xx in window
_RATE_THRESHOLD = 100      # requests per IP per minute
_LARGE_POST_BYTES = 1_000_000  # 1 MB


class WAFAnomalyAgent(BaseAgent):
    """WAF / Web Anomaly Detection Agent (W32)."""

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w32_waf_anomaly",
            description="Detects anomalous patterns in WAF / web server logs",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:network-supervisor",
        )
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")
        self._ip_whitelist: set[str] = set(self._agent_config.get("ip_whitelist", []))

        # Baseline tracking across cycles
        self._baseline_5xx_rate: float = 0.0
        self._baseline_samples: int = 0

        self._alerted_cache: dict[str, float] = {}
        self._alert_cooldown = 300

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[list[dict[str, Any]]]:
        """Fetch web server access log events from Wazuh."""
        try:
            query = {
                "bool": {
                    "should": [
                        {"match_phrase": {"rule.groups": "web"}},
                        {"match_phrase": {"rule.groups": "apache"}},
                        {"match_phrase": {"rule.groups": "nginx"}},
                        {"match_phrase": {"rule.groups": "access_log"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2, query=query, size=2000,
            )
            logger.debug("Collected %d web access events", len(events))
            return events
        except Exception as exc:
            logger.error("Failed to collect web events: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Aggregate and detect anomalies across all web events."""
        findings: list[dict[str, Any]] = []
        ip_4xx: dict[str, int] = defaultdict(int)
        ip_requests: dict[str, int] = defaultdict(int)
        total_5xx = 0

        for event in data:
            d = event.get("data", {})
            src_ip = d.get("srcip", "")
            method = d.get("method", "").upper()
            status = str(d.get("status", d.get("response_code", "")))
            uri = d.get("url", d.get("uri", ""))
            ua = d.get("user_agent", d.get("agent", ""))
            content_len = int(d.get("content_length", 0) or 0)

            if src_ip in self._ip_whitelist:
                continue

            ip_requests[src_ip] += 1

            # 1. Unusual HTTP method
            if method in _UNUSUAL_METHODS:
                findings.append({
                    "type": "unusual_method", "severity": Severity.MEDIUM,
                    "source_ip": src_ip, "method": method, "uri": uri,
                })

            # 2. Status code tracking
            if status.startswith("4"):
                ip_4xx[src_ip] += 1
            if status.startswith("5"):
                total_5xx += 1

            # 3. Scanner User-Agent
            if ua:
                for pat in _SCANNER_UA_PATTERNS:
                    if pat.search(ua):
                        findings.append({
                            "type": "scanner_detected", "severity": Severity.MEDIUM,
                            "source_ip": src_ip, "user_agent": ua[:200],
                            "scanner": pat.pattern,
                        })
                        break

            # 4. Path traversal
            if _PATH_TRAVERSAL_RE.search(uri):
                findings.append({
                    "type": "path_traversal", "severity": Severity.HIGH,
                    "source_ip": src_ip, "uri": uri[:300],
                })

            # 5. Large POST body
            if method == "POST" and content_len > _LARGE_POST_BYTES:
                findings.append({
                    "type": "large_post", "severity": Severity.MEDIUM,
                    "source_ip": src_ip, "uri": uri[:200],
                    "content_length": content_len,
                })

        # 6. 4xx error flood per IP
        for ip, count in ip_4xx.items():
            if count >= _4XX_THRESHOLD:
                findings.append({
                    "type": "4xx_flood", "severity": Severity.HIGH,
                    "source_ip": ip, "error_count": count,
                    "description": f"{count} client errors from {ip} in 2 min",
                })

        # 7. 5xx spike detection (vs rolling baseline)
        self._update_baseline(total_5xx)
        if total_5xx >= _5XX_SPIKE_THRESHOLD and total_5xx > self._baseline_5xx_rate * 3:
            findings.append({
                "type": "5xx_spike", "severity": Severity.HIGH,
                "total_5xx": total_5xx, "baseline": round(self._baseline_5xx_rate, 1),
                "description": f"5xx spike: {total_5xx} errors (baseline {self._baseline_5xx_rate:.1f})",
            })

        # 8. High request rate
        for ip, count in ip_requests.items():
            if count >= _RATE_THRESHOLD:
                findings.append({
                    "type": "high_rate", "severity": Severity.HIGH,
                    "source_ip": ip, "request_count": count,
                    "description": f"{count} requests from {ip} in 2 min",
                })

        # Deduplicate scanner / method hits per IP
        findings = self._deduplicate(findings)

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    def _update_baseline(self, current_5xx: int) -> None:
        """Exponentially weighted moving average for 5xx baseline."""
        alpha = 0.1
        if self._baseline_samples == 0:
            self._baseline_5xx_rate = float(current_5xx)
        else:
            self._baseline_5xx_rate = alpha * current_5xx + (1 - alpha) * self._baseline_5xx_rate
        self._baseline_samples += 1

    @staticmethod
    def _deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Keep one finding per (type, source_ip) pair."""
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for f in findings:
            key = f"{f['type']}:{f.get('source_ip', 'global')}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        now = time.time()
        for f in findings:
            key = f"waf:{f['type']}:{f.get('source_ip', 'global')}"
            if now - self._alerted_cache.get(key, 0) < self._alert_cooldown:
                continue
            actions.append({
                "type": "alert", "severity": f["severity"],
                "title": f"Web Anomaly: {f['type'].replace('_', ' ').title()}",
                "details": {k: v for k, v in f.items() if k not in ("severity",)},
                "alert_key": key,
            })
            actions.append({"type": "log_incident", "finding": f})
        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        alerts_sent, logged = 0, 0
        for action in actions:
            if action["type"] == "alert":
                sent = self.alerter.send_alert(
                    severity=action["severity"], title=action["title"],
                    details=action["details"], agent_name=self.name,
                )
                if sent:
                    alerts_sent += 1
                    self._alerted_cache[action["alert_key"]] = time.time()
            elif action["type"] == "log_incident":
                try:
                    f = action["finding"]
                    self.os_client.index_document("soc-waf-incidents", {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent_name": self.name, "type": f["type"],
                        "severity": f["severity"].name,
                        "source_ip": f.get("source_ip", ""),
                        "details": f.get("description", ""),
                    })
                    logged += 1
                except Exception as exc:
                    logger.error("Failed to log WAF incident: %s", exc)
        if alerts_sent:
            self.report_to_supervisor({
                "type": "waf_report", "alerts_sent": alerts_sent,
                "incidents_logged": logged,
            })
        return {"alerts_sent": alerts_sent, "incidents_logged": logged}


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
    agent = WAFAnomalyAgent()
    agent.run_loop()
