"""
W14 - ML-based Threat Prediction Agent
Uses statistical models (pure Python, no numpy) to predict threats before
they materialise.

Tracks time-series of:
  - Alert volume per category
  - Connection volume per host
  - Failed login attempts
  - DNS query patterns

Calculates 7-day moving averages / standard deviations and detects:
  - Rising alert counts / acceleration in suspicious events
  - Likely attack windows (time-of-day patterns)
  - Hosts likely to be compromised (anomaly scoring)
  - Users at risk (behavioural drift)
"""

import time
import math
import logging
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
from datetime import datetime, timezone
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("W14-MLPrediction")

WINDOW_SIZE = 2016       # 7 days of 5-minute buckets (7*24*60/5)
Z_SCORE_THRESHOLD = 3.0  # Standard deviations for anomaly
TREND_SLOPE_THRESHOLD = 0.15  # Normalised slope for trend detection
MIN_SAMPLES = 12         # Minimum data points before predicting


def _mean(values: List[float]) -> float:
    """Calculate arithmetic mean."""
    return sum(values) / len(values) if values else 0.0


def _stddev(values: List[float], avg: Optional[float] = None) -> float:
    """Calculate population standard deviation."""
    if len(values) < 2:
        return 0.0
    m = avg if avg is not None else _mean(values)
    variance = sum((x - m) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def _linear_slope(values: List[float]) -> float:
    """Compute simple linear regression slope (normalised by mean)."""
    n = len(values)
    if n < 3:
        return 0.0
    x_mean = (n - 1) / 2.0
    y_mean = _mean(values)
    if y_mean == 0:
        return 0.0
    num = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
    den = sum((i - x_mean) ** 2 for i in range(n))
    return (num / den) / y_mean if den else 0.0


class MLPredictionAgent(BaseAgent):
    """Predicts future attacks from statistical trend analysis."""

    def __init__(self):
        super().__init__(
            name="W14_MLPrediction",
            description="Predicts future attacks based on statistical trend analysis",
            interval_seconds=300,
            supervisor_channel="soc:detection-supervisor",
        )
        # Time-series stores: key -> deque of (timestamp, value) tuples
        self._alert_series: Dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
        self._conn_series: Dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
        self._login_series: Dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
        self._dns_series: Dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
        # Hourly attack frequency histogram (0-23)
        self._hourly_histogram: Dict[str, List[int]] = defaultdict(lambda: [0] * 24)

    def collect(self) -> Dict[str, Any]:
        """Gather alert counts, connection volumes, failed logins, DNS queries."""
        result: Dict[str, Any] = {"alerts": [], "connections": [], "logins": [], "dns": []}
        try:
            result["alerts"] = self.os_client.get_events_since(
                "soc-alerts-*", minutes=6,
                query={"bool": {"must": [{"exists": {"field": "severity"}}]}},
                size=2000,
            )
        except Exception as e:
            logger.error("Failed to collect alerts: %s", e)
        try:
            result["connections"] = self.os_client.get_events_since(
                "zeek-conn-*", minutes=6,
                query={"bool": {"must": [{"exists": {"field": "id.orig_h"}}]}},
                size=2000,
            )
        except Exception as e:
            logger.error("Failed to collect connections: %s", e)
        try:
            result["logins"] = self.os_client.get_events_since(
                "wazuh-alerts-*", minutes=6,
                query={"bool": {"must": [{"term": {"rule.groups": "authentication_failed"}}]}},
                size=1000,
            )
        except Exception as e:
            logger.error("Failed to collect logins: %s", e)
        try:
            result["dns"] = self.os_client.get_events_since(
                "zeek-dns-*", minutes=6,
                query={"bool": {"must": [{"exists": {"field": "query"}}]}},
                size=2000,
            )
        except Exception as e:
            logger.error("Failed to collect DNS queries: %s", e)
        return result

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Update time-series, compute Z-scores and trend slopes."""
        findings: List[Dict[str, Any]] = []
        now = time.time()

        # --- 1. Alert volume per category ---
        cat_counts: Dict[str, int] = defaultdict(int)
        for alert in data.get("alerts", []):
            category = alert.get("rule", {}).get("groups", ["unknown"])[0] if isinstance(
                alert.get("rule"), dict) else alert.get("agent_name", "unknown")
            cat_counts[category] += 1
            hour = datetime.now(timezone.utc).hour
            self._hourly_histogram[category][hour] += 1

        for category, count in cat_counts.items():
            self._alert_series[category].append((now, float(count)))
            finding = self._evaluate_series(self._alert_series[category], category, "alert_volume")
            if finding:
                findings.append(finding)

        # --- 2. Connection volume per host ---
        host_conns: Dict[str, int] = defaultdict(int)
        for conn in data.get("connections", []):
            host = conn.get("id.orig_h", "unknown")
            host_conns[host] += 1

        for host, count in host_conns.items():
            self._conn_series[host].append((now, float(count)))
            finding = self._evaluate_series(self._conn_series[host], host, "conn_volume")
            if finding:
                finding["host"] = host
                findings.append(finding)

        # --- 3. Failed login attempts per user/host ---
        login_counts: Dict[str, int] = defaultdict(int)
        for login in data.get("logins", []):
            user = login.get("data", {}).get("dstuser", "") or login.get("agent", {}).get("name", "unknown")
            login_counts[user] += 1

        for user, count in login_counts.items():
            self._login_series[user].append((now, float(count)))
            finding = self._evaluate_series(self._login_series[user], user, "failed_logins")
            if finding:
                finding["user"] = user
                findings.append(finding)

        # --- 4. DNS query volume per domain ---
        domain_counts: Dict[str, int] = defaultdict(int)
        for dns in data.get("dns", []):
            query_name = dns.get("query", "")
            parts = query_name.split(".")
            root = ".".join(parts[-2:]) if len(parts) >= 2 else query_name
            domain_counts[root] += 1

        for domain, count in domain_counts.items():
            self._dns_series[domain].append((now, float(count)))
            finding = self._evaluate_series(self._dns_series[domain], domain, "dns_pattern")
            if finding:
                findings.append(finding)

        # --- 5. Attack-window prediction (time-of-day) ---
        for category, histogram in self._hourly_histogram.items():
            total = sum(histogram)
            if total < 50:
                continue
            avg_hourly = total / 24.0
            peak_hour = max(range(24), key=lambda h: histogram[h])
            if histogram[peak_hour] > avg_hourly * 3:
                current_hour = datetime.now(timezone.utc).hour
                hours_until = (peak_hour - current_hour) % 24
                if 0 < hours_until <= 4:
                    findings.append({
                        "type": "attack_window_prediction", "severity": Severity.MEDIUM,
                        "entity": category, "peak_hour_utc": peak_hour,
                        "hours_until": hours_until,
                        "details": (f"Category '{category}' peaks at {peak_hour}:00 UTC "
                                    f"({hours_until}h from now). Prepare defences."),
                    })

        return findings

    def _evaluate_series(self, series: deque, entity: str, metric_type: str) -> Optional[Dict[str, Any]]:
        """Compute Z-score and trend for a time-series. Return a finding if anomalous."""
        if len(series) < MIN_SAMPLES:
            return None

        values = [v for _, v in series]
        current = values[-1]
        avg = _mean(values[:-1])
        sd = _stddev(values[:-1], avg)

        z_score = (current - avg) / sd if sd > 0 else 0.0
        slope = _linear_slope(values[-min(len(values), 24):])  # recent 24 buckets

        if z_score > Z_SCORE_THRESHOLD:
            severity = Severity.CRITICAL if z_score > 5.0 else Severity.HIGH
            return {
                "type": f"{metric_type}_anomaly", "severity": severity,
                "entity": entity, "z_score": round(z_score, 2),
                "current": current, "baseline_avg": round(avg, 2),
                "details": f"{metric_type} anomaly for '{entity}': z={z_score:.2f} (curr={current}, avg={avg:.1f})",
            }

        if slope > TREND_SLOPE_THRESHOLD and len(values) >= MIN_SAMPLES:
            return {
                "type": f"{metric_type}_rising_trend", "severity": Severity.MEDIUM,
                "entity": entity, "slope": round(slope, 4),
                "details": f"Rising trend in {metric_type} for '{entity}': slope={slope:.4f}",
            }

        return None

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Decide on alerts and escalations for predictions."""
        actions: List[Dict[str, Any]] = []
        for f in findings:
            actions.append({"action": "alert", "data": f})
            if f["severity"] >= Severity.HIGH:
                actions.append({"action": "escalate", "data": f})
            # Index prediction to dedicated index for dashboards
            actions.append({"action": "index_prediction", "data": f})
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alerts, escalations, and prediction indexing."""
        results = {"alerts": 0, "escalations": 0, "predictions_indexed": 0}
        for action in actions:
            try:
                if action["action"] == "alert":
                    d = action["data"]
                    self.alerter.send_alert(
                        severity=d["severity"],
                        title=f"Prediction: {d['type']}",
                        details={"entity": d.get("entity", ""), "info": d["details"]},
                        agent_name=self.name,
                    )
                    results["alerts"] += 1
                elif action["action"] == "escalate":
                    self.report_to_supervisor(action["data"])
                    results["escalations"] += 1
                elif action["action"] == "index_prediction":
                    doc = {**action["data"], "timestamp": datetime.now(timezone.utc).isoformat(),
                           "agent": self.name, "severity": action["data"]["severity"].name}
                    self.os_client.index_document("soc-predictions", doc)
                    results["predictions_indexed"] += 1
            except Exception as e:
                logger.error("Prediction action failed: %s", e)
        return results


if __name__ == "__main__":
    agent = MLPredictionAgent()
    agent.run_loop()
