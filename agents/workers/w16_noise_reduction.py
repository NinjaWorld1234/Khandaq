"""
W16 - Alert Noise Reduction Agent
Reduces false positives and alert fatigue by:

  1. Grouping duplicate alerts (same rule + host within 5 minutes)
  2. Tracking false-positive rates per rule ID
  3. Auto-suppressing rules with >90% FP rate (after 100 samples)
  4. Deduplicating same alert from multiple sources
  5. Priority scoring: severity adjusted by asset criticality, time-of-day,
     and historical accuracy
  6. Outputting cleaned alert stream to soc-filtered-alerts index
"""

import time
import threading
import logging
import hashlib
from typing import Dict, Any, List, Set
from collections import defaultdict
from datetime import datetime, timezone
from shared.base_agent import BaseAgent

logger = logging.getLogger("W16-NoiseReduction")

DEDUP_WINDOW = 300         # 5 minutes
FP_SAMPLE_THRESHOLD = 100  # Minimum samples before auto-suppression
FP_RATE_SUPPRESS = 0.90    # 90% false-positive rate → suppress
SEVERITY_MAP = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Critical assets get a severity boost
CRITICAL_ASSETS = {
    "dc01", "dc02", "exchange", "sql-prod", "web-prod",
    "firewall", "vpn-gateway", "radius", "pki-ca",
}
# Business-hours multiplier (UTC): alerts outside hours get slight reduction
BUSINESS_HOURS = range(7, 19)


def _alert_fingerprint(alert: Dict[str, Any]) -> str:
    """Generate a deduplication fingerprint for an alert."""
    rule_id = str((alert.get("rule") or {}).get("id", "") if isinstance(alert.get("rule"), dict)
                  else alert.get("rule_id", ""))
    host = str((alert.get("agent") or {}).get("name", "") if isinstance(alert.get("agent"), dict)
               else alert.get("host", "unknown"))
    title = str(alert.get("title") or ((alert.get("rule") or {}).get("description", "")
                if isinstance(alert.get("rule"), dict) else ""))
    raw = f"{rule_id}:{host}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _extract_rule_id(alert: Dict[str, Any]) -> str:
    """Extract the rule ID from an alert."""
    if isinstance(alert.get("rule"), dict):
        return str(alert["rule"].get("id", "unknown"))
    return str(alert.get("rule_id", "unknown"))


def _extract_host(alert: Dict[str, Any]) -> str:
    """Extract the host name from an alert."""
    if isinstance(alert.get("agent"), dict):
        return alert["agent"].get("name", "unknown")
    return alert.get("host", alert.get("dest_ip", "unknown"))


class NoiseReductionAgent(BaseAgent):
    """Filters, deduplicates, and re-scores alerts to reduce noise."""

    def __init__(self):
        super().__init__(
            name="W16_NoiseReduction",
            description="Suppresses false positives and tunes alert thresholds dynamically",
            interval_seconds=30,
            supervisor_channel="soc:detection-supervisor",
        )
        # rule_id -> {"total": int, "false_positives": int}
        self._fp_tracker: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "false_positives": 0})
        # Suppressed rule IDs
        self._suppressed_rules: Set[str] = set()
        # Recent fingerprints for dedup: fingerprint -> expiry_timestamp
        self._seen_fingerprints: Dict[str, float] = {}
        # Stats for supervisor reporting
        self._cycle_stats = {"total": 0, "deduped": 0, "suppressed": 0, "emitted": 0}
        self._processed_feedback_ids: Dict[str, float] = {}
        self._cache_lock = threading.Lock()

    def collect(self) -> Dict[str, Any]:
        """Fetch raw alerts and dismissed-alert feedback."""
        result: Dict[str, Any] = {"alerts": [], "feedback": []}
        try:
            result["alerts"] = self.os_client.get_events_since(
                "soc-alerts-*", minutes=1,
                query={"bool": {"must": [{"exists": {"field": "title"}}]}},
                size=10000,
            )
        except Exception as e:
            logger.error("Failed to collect alerts: %s", e)
        try:
            result["alerts"] += self.os_client.get_events_since(
                "wazuh-alerts-*", minutes=1,
                query={"bool": {"must": [{"exists": {"field": "rule.id"}}]}},
                size=10000,
            )
        except Exception as e:
            logger.error("Failed to collect Wazuh alerts: %s", e)
        # Collect analyst feedback (dismissed = false positive)
        try:
            result["feedback"] = self.os_client.get_events_since(
                "soc-alert-feedback", minutes=10,
                query={"bool": {"must": [{"exists": {"field": "rule_id"}}]}},
                size=10000,
            )
        except Exception:
            pass  # Feedback index may not exist yet
        return result

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Deduplicate, suppress, and re-score alerts."""
        now = time.time()
        current_hour = datetime.now(timezone.utc).hour
        findings: List[Dict[str, Any]] = []

        # --- Process analyst feedback to update FP rates ---
        for fb in data.get("feedback", []):
            try:
                fb_id = str(fb.get("_id", fb.get("id", "")))
                if not fb_id:
                    fb_id = hashlib.sha256(str(fb).encode()).hexdigest()
                
                with self._cache_lock:
                    if fb_id in self._processed_feedback_ids:
                        continue
                    self._processed_feedback_ids[fb_id] = now + 3600  # 1 hour memory
                
                rule_id = str(fb.get("rule_id", ""))
                disposition = fb.get("disposition", "").lower()
                if rule_id:
                    if disposition in ("false_positive", "dismissed", "benign"):
                        with self._cache_lock:
                            self._fp_tracker[rule_id]["false_positives"] += 1
            except Exception as e:
                logger.warning("Error processing feedback: %s", e)

        # --- Check which rules should be suppressed ---
        for rule_id, stats in self._fp_tracker.items():
            try:
                if stats["total"] >= FP_SAMPLE_THRESHOLD:
                    fp_rate = stats["false_positives"] / stats["total"]
                    if fp_rate >= FP_RATE_SUPPRESS and rule_id not in self._suppressed_rules:
                        with self._cache_lock:

                            self._suppressed_rules.add(rule_id)
                        logger.warning("Auto-suppressing rule %s (FP rate: %.1f%% over %d samples)",
                                       rule_id, fp_rate * 100, stats["total"])
            except Exception as e:
                logger.warning("Error checking rule suppression for %s: %s", rule_id, e)

        # Prune expired fingerprints and feedback
        with self._cache_lock:
            self._seen_fingerprints = {fp: exp for fp, exp in self._seen_fingerprints.items() if exp > now}
            self._processed_feedback_ids = {k: exp for k, exp in self._processed_feedback_ids.items() if exp > now}

        # --- Process each alert ---
        stats = {"total": 0, "deduped": 0, "suppressed": 0, "emitted": 0}
        alerts = data.get("alerts", [])
        stats["total"] = len(alerts)

        for alert in alerts:
            try:
                rule_id = _extract_rule_id(alert)
                host = _extract_host(alert)
                fingerprint = _alert_fingerprint(alert)

                # 1. Auto-suppress high-FP rules (flag them instead of dropping)
                is_suppressed = rule_id in self._suppressed_rules
                if is_suppressed:
                    stats["suppressed"] += 1

                # 2. Deduplicate (same fingerprint within window)
                if fingerprint in self._seen_fingerprints:
                    stats["deduped"] += 1
                    continue
                with self._cache_lock:

                    self._seen_fingerprints[fingerprint] = now + DEDUP_WINDOW

                # 3. Track for FP analysis
                with self._cache_lock:

                    self._fp_tracker[rule_id]["total"] += 1

                # 4. Priority scoring
                base_severity = self._get_severity(alert)
                adjusted = 0 if is_suppressed else self._score_priority(base_severity, host, rule_id, current_hour)

                findings.append({
                    "type": "filtered_alert",
                    "original": alert,
                    "rule_id": rule_id,
                    "host": host,
                    "fingerprint": fingerprint,
                    "original_severity": base_severity,
                    "adjusted_severity": adjusted,
                    "fp_rate": self._get_fp_rate(rule_id),
                })
                stats["emitted"] += 1
            except Exception as e:
                logger.warning("Error processing alert: %s", e)

        with self._cache_lock:

            self._cycle_stats = stats
        if stats["total"] > 0:
            logger.info("Noise reduction: %d total → %d emitted (%d deduped, %d suppressed)",
                        stats["total"], stats["emitted"], stats["deduped"], stats["suppressed"])
        return findings

    def _get_severity(self, alert: Dict[str, Any]) -> int:
        """Extract numeric severity from an alert."""
        if isinstance(alert.get("rule"), dict):
            level = int(alert["rule"].get("level", 3))
            if level >= 12:
                return 4
            elif level >= 8:
                return 3
            elif level >= 5:
                return 2
            elif level >= 3:
                return 1
            return 0
        sev_name = str(alert.get("severity", "LOW")).upper()
        return SEVERITY_MAP.get(sev_name, 1)

    def _get_fp_rate(self, rule_id: str) -> float:
        """Get the current false-positive rate for a rule."""
        stats = self._fp_tracker.get(rule_id)
        if not stats or stats["total"] == 0:
            return 0.0
        return stats["false_positives"] / stats["total"]

    def _score_priority(self, base_severity: int, host: str, rule_id: str, hour: int) -> int:
        """Adjust severity based on asset criticality, time-of-day, and FP history."""
        score = float(base_severity)

        # Boost for critical assets
        host_lower = host.lower()
        if any(asset in host_lower for asset in CRITICAL_ASSETS):
            score += 0.5

        # Reduce slightly outside business hours (for non-critical)
        if hour not in BUSINESS_HOURS and score < 3:
            score -= 0.3

        # Reduce for rules with moderate FP history
        fp_rate = self._get_fp_rate(rule_id)
        if fp_rate > 0.5:
            score -= 0.5
        elif fp_rate > 0.3:
            score -= 0.2

        return max(0, min(4, round(score)))

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build actions: index cleaned alerts and report stats."""
        actions: List[Dict[str, Any]] = []
        for f in findings:
            actions.append({"action": "index_filtered", "data": f})
        # Report cycle stats periodically
        if self._cycle_stats["total"] > 0:
            actions.append({"action": "report_stats", "data": self._cycle_stats})
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Index filtered alerts and report stats."""
        results = {"indexed": 0, "reported": False}
        batch: List[Dict[str, Any]] = []

        for action in actions:
            try:
                if action["action"] == "index_filtered":
                    f = action["data"]
                    severity_names = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
                    doc = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "rule_id": f["rule_id"],
                        "host": f["host"],
                        "fingerprint": f["fingerprint"],
                        "original_severity": severity_names.get(f["original_severity"], "LOW"),
                        "adjusted_severity": severity_names.get(f["adjusted_severity"], "LOW"),
                        "fp_rate": round(f["fp_rate"], 3),
                        "title": (f["original"].get("title", "")
                                  or ((f["original"].get("rule") or {}).get("description", "") if isinstance(f["original"].get("rule"), dict) else "")),
                        "original_alert": f["original"],
                    }
                    batch.append(doc)

                elif action["action"] == "report_stats":
                    self.report_to_supervisor({
                        "type": "noise_reduction_stats",
                        **action["data"],
                        "suppressed_rules": list(self._suppressed_rules)[:20],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    results["reported"] = True
            except Exception as e:
                logger.error("Noise reduction action failed: %s", e)

        # Bulk-index filtered alerts
        if batch:
            try:
                success, errors = self.os_client.bulk_index("soc-filtered-alerts", batch)
                results["indexed"] = success
                if errors:
                    logger.warning("Bulk index had %d errors", len(errors))
            except Exception as e:
                logger.error("Bulk index of filtered alerts failed: %s", e)
                
        self._events_processed += len(batch)
        self._metrics.inc_events(len(batch))

        return results


if __name__ == "__main__":
    agent = NoiseReductionAgent()
    agent.run_loop()
