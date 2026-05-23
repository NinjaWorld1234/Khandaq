# SOC Platform - Worker Agent W13: Statistical Anomaly Detection
# وكيل الكشف عن الشذوذ الإحصائي
"""
Statistical Anomaly Detection Agent
====================================

Uses the OpenSearch Anomaly Detection plugin API to create and monitor
detectors for key security metrics:

1. **Login count** per user per hour
2. **Network bytes transferred** per host
3. **DNS queries** per host
4. **Process creation rate** per host
5. **Failed auth attempts** per source IP

Also implements local statistical analysis methods:

- **Z-score** calculation for numeric fields
- **IQR (Interquartile Range)** method for outlier detection
- **Baseline learning period**: 7 days before alerting

Severity mapping (based on anomaly grade):
    - grade > 0.9 → CRITICAL
    - grade > 0.7 → HIGH
    - grade > 0.5 → MEDIUM
    - grade < 0.5 → INFO

Interval: 300 seconds (5 minutes)
"""

from __future__ import annotations

import datetime
import logging
import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w13_anomaly_detection")

# ---------------------------------------------------------------------------
# Constants / ثوابت
# ---------------------------------------------------------------------------

WAZUH_ALERTS_INDEX = "wazuh-alerts-*"

# Baseline learning period before anomalies trigger alerts (days)
# فترة التعلم الأساسية قبل أن تُطلق الشذوذات تنبيهات
BASELINE_LEARNING_DAYS = 7

# Z-score thresholds / عتبات الدرجة المعيارية
ZSCORE_CRITICAL = 4.0
ZSCORE_HIGH = 3.0
ZSCORE_MEDIUM = 2.5
ZSCORE_LOW = 2.0

# IQR multiplier for outlier detection / مُضاعف المدى الربيعي
IQR_MULTIPLIER = 1.5
IQR_EXTREME_MULTIPLIER = 3.0


# ---------------------------------------------------------------------------
# Anomaly Detector definitions / تعريفات كاشفات الشذوذ
# ---------------------------------------------------------------------------
@dataclass
class DetectorDefinition:
    """Defines an OpenSearch Anomaly Detection detector configuration."""
    name: str
    description: str
    index: str
    time_field: str
    feature_name: str
    feature_field: str
    aggregation: str  # "count", "sum", "avg", "max"
    category_field: Optional[str] = None
    detection_interval_minutes: int = 10
    window_delay_minutes: int = 2


DEFAULT_DETECTORS: list[DetectorDefinition] = [
    DetectorDefinition(
        name="soc-login-count-per-user",
        description="Detects abnormal login frequency per user per hour",
        index="wazuh-alerts-*",
        time_field="timestamp",
        feature_name="login_count",
        feature_field="data.dstuser",
        aggregation="count",
        category_field="data.dstuser",
        detection_interval_minutes=60,
    ),
    DetectorDefinition(
        name="soc-network-bytes-per-host",
        description="Detects abnormal network traffic volume per host",
        index="wazuh-alerts-*",
        time_field="timestamp",
        feature_name="network_bytes",
        feature_field="data.bytes",
        aggregation="sum",
        category_field="agent.name",
        detection_interval_minutes=10,
    ),
    DetectorDefinition(
        name="soc-dns-queries-per-host",
        description="Detects abnormal DNS query rates per host",
        index="wazuh-alerts-*",
        time_field="timestamp",
        feature_name="dns_query_count",
        feature_field="data.dns.query",
        aggregation="count",
        category_field="agent.name",
        detection_interval_minutes=10,
    ),
    DetectorDefinition(
        name="soc-process-creation-rate",
        description="Detects abnormal process creation rates per host",
        index="wazuh-alerts-*",
        time_field="timestamp",
        feature_name="process_creation_count",
        feature_field="data.win.system.eventID",
        aggregation="count",
        category_field="agent.name",
        detection_interval_minutes=10,
    ),
    DetectorDefinition(
        name="soc-failed-auth-per-ip",
        description="Detects abnormal failed authentication attempts per source IP",
        index="wazuh-alerts-*",
        time_field="timestamp",
        feature_name="failed_auth_count",
        feature_field="data.srcip",
        aggregation="count",
        category_field="data.srcip",
        detection_interval_minutes=10,
    ),
]


class AnomalyDetectionAgent(BaseAgent):
    """
    Statistical Anomaly Detection Agent.
    وكيل الكشف عن الشذوذ الإحصائي باستخدام OpenSearch وأساليب إحصائية محلية
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w13_anomaly_detection",
            description="Statistical Anomaly Detection – OpenSearch AD plugin + local Z-score/IQR",
            interval_seconds=300,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )

        # Detector ID registry: detector_name → OpenSearch detector_id
        self._detector_ids: dict[str, str] = {}
        self._detectors_initialized: bool = False

        # Agent start time – used to enforce baseline learning period
        self._start_time: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)

        # Historical data store for local statistical analysis
        # { metric_key: [value1, value2, ...] }
        self._baseline_data: dict[str, list[float]] = defaultdict(list)
        self._max_baseline_points: int = self._agent_config.get(
            "max_baseline_points", 10080,
        )

        # Track last processed anomaly timestamp per detector
        self._last_anomaly_check: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Severity mapping / تحديد مستوى الخطورة
    # ------------------------------------------------------------------
    @staticmethod
    def grade_to_severity(grade: float) -> Severity:
        """Map an anomaly grade (0.0–1.0) to an alert severity level."""
        if grade > 0.9:
            return Severity.CRITICAL
        elif grade > 0.7:
            return Severity.HIGH
        elif grade > 0.5:
            return Severity.MEDIUM
        else:
            return Severity.INFO

    @staticmethod
    def zscore_to_severity(zscore: float) -> Severity:
        """Map a Z-score to an alert severity level."""
        abs_z = abs(zscore)
        if abs_z >= ZSCORE_CRITICAL:
            return Severity.CRITICAL
        elif abs_z >= ZSCORE_HIGH:
            return Severity.HIGH
        elif abs_z >= ZSCORE_MEDIUM:
            return Severity.MEDIUM
        elif abs_z >= ZSCORE_LOW:
            return Severity.LOW
        else:
            return Severity.INFO

    # ------------------------------------------------------------------
    # Statistical helpers / مساعدات إحصائية
    # ------------------------------------------------------------------
    @staticmethod
    def calculate_zscore(value: float, data: list[float]) -> Optional[float]:
        """
        Calculate the Z-score for a value given a dataset.
        Z-score = (value - mean) / standard_deviation
        Returns None if there isn't enough data or stddev is zero.
        """
        if len(data) < 10:
            return None

        mean = statistics.mean(data)
        try:
            stdev = statistics.stdev(data)
        except statistics.StatisticsError:
            return None

        if stdev == 0:
            return 0.0 if value == mean else None

        return (value - mean) / stdev

    @staticmethod
    def calculate_iqr_bounds(
        data: list[float],
    ) -> Optional[tuple[float, float, float, float]]:
        """
        Calculate IQR-based outlier bounds.
        Returns (lower_bound, upper_bound, lower_extreme, upper_extreme)
        or None if insufficient data.
        """
        if len(data) < 20:
            return None

        sorted_data = sorted(data)
        n = len(sorted_data)
        q1 = sorted_data[n // 4]
        q3 = sorted_data[(3 * n) // 4]
        iqr = q3 - q1

        lower_bound = q1 - IQR_MULTIPLIER * iqr
        upper_bound = q3 + IQR_MULTIPLIER * iqr
        lower_extreme = q1 - IQR_EXTREME_MULTIPLIER * iqr
        upper_extreme = q3 + IQR_EXTREME_MULTIPLIER * iqr

        return lower_bound, upper_bound, lower_extreme, upper_extreme

    def _is_in_learning_period(self) -> bool:
        """Check if the agent is still within the baseline learning period."""
        elapsed = datetime.datetime.now(datetime.timezone.utc) - self._start_time
        return elapsed.days < BASELINE_LEARNING_DAYS

    # ------------------------------------------------------------------
    # OpenSearch Anomaly Detection API helpers
    # مساعدات واجهة كشف الشذوذ في OpenSearch
    # ------------------------------------------------------------------
    def _create_detector(self, detector_def: DetectorDefinition) -> Optional[str]:
        """Create an anomaly detection detector in OpenSearch."""
        if detector_def.aggregation == "count":
            agg_body = {"value_count": {"field": detector_def.feature_field}}
        elif detector_def.aggregation == "sum":
            agg_body = {"sum": {"field": detector_def.feature_field}}
        elif detector_def.aggregation == "avg":
            agg_body = {"avg": {"field": detector_def.feature_field}}
        elif detector_def.aggregation == "max":
            agg_body = {"max": {"field": detector_def.feature_field}}
        else:
            agg_body = {"value_count": {"field": detector_def.feature_field}}

        body: dict[str, Any] = {
            "name": detector_def.name,
            "description": detector_def.description,
            "time_field": detector_def.time_field,
            "indices": [detector_def.index],
            "feature_attributes": [{
                "feature_name": detector_def.feature_name,
                "feature_enabled": True,
                "aggregation_query": {detector_def.feature_name: agg_body},
            }],
            "detection_interval": {
                "period": {"interval": detector_def.detection_interval_minutes, "unit": "Minutes"},
            },
            "window_delay": {
                "period": {"interval": detector_def.window_delay_minutes, "unit": "Minutes"},
            },
        }
        if detector_def.category_field:
            body["category_field"] = [detector_def.category_field]

        try:
            resp = self.os_client.client.transport.perform_request(
                "POST", "/_plugins/_anomaly_detection/detectors", body=body,
            )
            detector_id = resp.get("_id", "")
            logger.info("✅ Created anomaly detector: %s (id=%s)", detector_def.name, detector_id)
            return detector_id
        except Exception as exc:
            logger.warning("Failed to create detector '%s': %s – looking for existing", detector_def.name, exc)
            return self._find_existing_detector(detector_def.name)

    def _find_existing_detector(self, name: str) -> Optional[str]:
        """Find an existing detector by name."""
        try:
            resp = self.os_client.client.transport.perform_request(
                "POST", "/_plugins/_anomaly_detection/detectors/_search",
                body={"query": {"match": {"name": name}}},
            )
            hits = resp.get("hits", {}).get("hits", [])
            if hits:
                detector_id = hits[0]["_id"]
                logger.info("Found existing detector: %s (id=%s)", name, detector_id)
                return detector_id
        except Exception as exc:
            logger.error("Failed to search for detector '%s': %s", name, exc)
        return None

    def _start_detector(self, detector_id: str) -> bool:
        """Start a detector for real-time anomaly detection."""
        try:
            self.os_client.client.transport.perform_request(
                "POST", f"/_plugins/_anomaly_detection/detectors/{detector_id}/_start",
            )
            logger.info("▶️  Started detector: %s", detector_id)
            return True
        except Exception as exc:
            logger.warning("Failed to start detector %s: %s", detector_id, exc)
            return False

    def _initialize_detectors(self) -> None:
        """Create and start all anomaly detectors."""
        for detector_def in DEFAULT_DETECTORS:
            detector_id = self._create_detector(detector_def)
            if detector_id:
                self._detector_ids[detector_def.name] = detector_id
                self._start_detector(detector_id)
                self._last_anomaly_check[detector_def.name] = (
                    datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                )
        self._detectors_initialized = True
        logger.info("Detector initialization complete – %d active", len(self._detector_ids))

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> dict[str, Any]:
        """
        Collect anomaly results from OpenSearch AD and current metric
        counts for local statistical analysis.
        """
        if not self._detectors_initialized:
            try:
                self._initialize_detectors()
            except Exception as exc:
                logger.error("Detector initialization failed: %s", exc)

        data: dict[str, Any] = {"anomaly_results": {}, "local_metrics": {}}

        # 1. Get anomaly results from OpenSearch for each detector
        for det_name, det_id in self._detector_ids.items():
            last_check = self._last_anomaly_check.get(det_name, "now-10m")
            try:
                body = {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"detector_id": det_id}},
                                {"range": {"data_start_time": {"gte": last_check}}},
                                {"range": {"anomaly_grade": {"gt": 0}}},
                            ],
                        }
                    },
                    "size": 50,
                    "sort": [{"data_start_time": {"order": "desc"}}],
                }
                resp = self.os_client.search(index=".opendistro-anomaly-results*", body=body, size=50)
                data["anomaly_results"][det_name] = [
                    hit["_source"] for hit in resp.get("hits", {}).get("hits", [])
                ]
            except Exception as exc:
                logger.error("Anomaly result fetch for '%s' failed: %s", det_name, exc)
                data["anomaly_results"][det_name] = []

            self._last_anomaly_check[det_name] = (
                datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            )

        # 2. Get current metric counts for local stats
        local_metric_queries = {
            "auth_failures_per_5m": {"match": {"rule.groups": "authentication_failed"}},
            "process_creation_per_5m": {"term": {"data.win.system.eventID": "1"}},
        }
        for metric_name, query in local_metric_queries.items():
            try:
                count = self.os_client.count(
                    index=WAZUH_ALERTS_INDEX,
                    query={"bool": {"must": [
                        {"range": {"@timestamp": {"gte": "now-5m"}}},
                        query,
                    ]}},
                )
                data["local_metrics"][metric_name] = float(count)
            except Exception as exc:
                logger.error("Local metric '%s' query failed: %s", metric_name, exc)

        return data

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: Any) -> list[dict[str, Any]]:
        """Analyze anomaly results and local metrics for findings."""
        findings: list[dict[str, Any]] = []

        # --- OpenSearch AD results ---
        for det_name, results in data.get("anomaly_results", {}).items():
            for result in results:
                anomaly_grade = float(result.get("anomaly_grade", 0))
                confidence = float(result.get("confidence", 0))
                severity = self.grade_to_severity(anomaly_grade)
                if severity == Severity.INFO:
                    continue

                entity = result.get("entity", [])
                entity_name = (
                    ", ".join(f"{e.get('name', '?')}={e.get('value', '?')}" for e in entity)
                    if entity else "global"
                )

                findings.append({
                    "type": "opensearch_anomaly",
                    "detector_name": det_name,
                    "anomaly_grade": anomaly_grade,
                    "confidence": confidence,
                    "entity": entity_name,
                    "data_start_time": result.get("data_start_time", ""),
                    "data_end_time": result.get("data_end_time", ""),
                    "severity": severity,
                })

        # --- Local Z-score and IQR analysis ---
        for metric_name, current_value in data.get("local_metrics", {}).items():
            # Append to baseline
            self._baseline_data[metric_name].append(current_value)
            if len(self._baseline_data[metric_name]) > self._max_baseline_points:
                self._baseline_data[metric_name] = self._baseline_data[metric_name][
                    -self._max_baseline_points:
                ]

            if self._is_in_learning_period():
                logger.debug(
                    "Learning period active for %s – value=%.0f, samples=%d",
                    metric_name, current_value, len(self._baseline_data[metric_name]),
                )
                continue

            baseline = self._baseline_data[metric_name]

            # Z-score
            zscore = self.calculate_zscore(current_value, baseline)
            if zscore is not None and abs(zscore) >= ZSCORE_LOW:
                severity = self.zscore_to_severity(zscore)
                if severity not in (Severity.INFO, Severity.LOW):
                    findings.append({
                        "type": "zscore_anomaly",
                        "metric": metric_name,
                        "current_value": current_value,
                        "zscore": round(zscore, 3),
                        "mean": round(statistics.mean(baseline), 3),
                        "stdev": round(statistics.stdev(baseline), 3),
                        "baseline_size": len(baseline),
                        "severity": severity,
                    })

            # IQR
            iqr_result = self.calculate_iqr_bounds(baseline)
            if iqr_result:
                lower, upper, lower_ext, upper_ext = iqr_result
                if current_value > upper_ext or current_value < lower_ext:
                    sev = Severity.CRITICAL
                elif current_value > upper or current_value < lower:
                    sev = Severity.HIGH
                else:
                    sev = None

                if sev:
                    findings.append({
                        "type": "iqr_outlier",
                        "metric": metric_name,
                        "current_value": current_value,
                        "iqr_lower": round(lower, 3),
                        "iqr_upper": round(upper, 3),
                        "iqr_extreme_lower": round(lower_ext, 3),
                        "iqr_extreme_upper": round(upper_ext, 3),
                        "baseline_size": len(baseline),
                        "severity": sev,
                    })

        return findings

    # ------------------------------------------------------------------
    # Decide / قرار
    # ------------------------------------------------------------------
    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Map findings to alert actions."""
        actions: list[dict[str, Any]] = []

        for finding in findings:
            ftype = finding["type"]
            severity = finding.get("severity", Severity.MEDIUM)

            if ftype == "opensearch_anomaly":
                actions.append({
                    "alert": True,
                    "severity": severity,
                    "title": f"📊 ANOMALY DETECTED: {finding['detector_name']}",
                    "details": {
                        "detector_name": finding["detector_name"],
                        "anomaly_grade": finding["anomaly_grade"],
                        "confidence": finding["confidence"],
                        "entity": finding["entity"],
                        "data_start_time": finding["data_start_time"],
                        "data_end_time": finding["data_end_time"],
                        "mitre_tactic": "Discovery",
                    },
                })

            elif ftype == "zscore_anomaly":
                actions.append({
                    "alert": True,
                    "severity": severity,
                    "title": f"📈 Z-SCORE ANOMALY: {finding['metric']}",
                    "details": {
                        "metric": finding["metric"],
                        "current_value": finding["current_value"],
                        "zscore": finding["zscore"],
                        "mean": finding["mean"],
                        "stdev": finding["stdev"],
                        "baseline_size": finding["baseline_size"],
                        "method": "zscore",
                    },
                })

            elif ftype == "iqr_outlier":
                actions.append({
                    "alert": True,
                    "severity": severity,
                    "title": f"📊 IQR OUTLIER: {finding['metric']}",
                    "details": {
                        "metric": finding["metric"],
                        "current_value": finding["current_value"],
                        "iqr_lower": finding["iqr_lower"],
                        "iqr_upper": finding["iqr_upper"],
                        "iqr_extreme_lower": finding["iqr_extreme_lower"],
                        "iqr_extreme_upper": finding["iqr_extreme_upper"],
                        "baseline_size": finding["baseline_size"],
                        "method": "iqr",
                    },
                })

        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """Execute alert actions."""
        alerts_sent = 0

        for action in actions:
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

        self._events_processed += 1
        self._metrics.inc_events(1)

        if alerts_sent:
            self.report_to_supervisor({
                "type": "anomaly_report",
                "alerts_sent": alerts_sent,
            })

        return {"alerts_sent": alerts_sent}


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
    agent = AnomalyDetectionAgent()
    agent.run_loop()
