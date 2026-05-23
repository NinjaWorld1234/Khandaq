"""
W15 - Kill Chain Correlation Agent
Maps alerts to MITRE ATT&CK kill-chain stages and correlates them by host,
time window, and related IOCs to detect multi-stage intrusions.

Kill-chain stages:
  1. Reconnaissance   2. Weaponization   3. Delivery
  4. Exploitation     5. Installation    6. C2
  7. Actions on Objectives

Severity escalation:
  3+ stages on same host in 4 hours → CRITICAL (active intrusion)
  2 stages → HIGH
  1 stage  → MEDIUM
"""

import time
import logging
import hashlib
from typing import Dict, Any, List, Set, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timezone
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("W15-KillChain")

CORRELATION_WINDOW_MIN = 240  # 4 hours

# Mapping of alert keywords / rule groups → kill-chain stage
STAGE_MAP: Dict[str, List[str]] = {
    "reconnaissance": [
        "port_scan", "nmap", "masscan", "recon", "discovery", "enumeration",
        "ping_sweep", "network_scan", "service_scan", "dns_enumeration",
    ],
    "weaponization": [
        "phishing_craft", "exploit_kit", "payload_gen", "macro_builder",
        "dropper_creation", "weaponize", "maldoc",
    ],
    "delivery": [
        "phishing", "spearphishing", "malicious_email", "drive_by",
        "usb_insertion", "watering_hole", "malicious_attachment", "spam",
    ],
    "exploitation": [
        "exploit", "cve", "buffer_overflow", "rce", "injection",
        "privilege_escalation", "priv_esc", "zero_day", "vulnerability",
    ],
    "installation": [
        "malware", "trojan", "backdoor", "persistence", "registry_run",
        "scheduled_task", "service_install", "rootkit", "implant", "dropper",
    ],
    "command_and_control": [
        "c2", "c&c", "beacon", "callback", "dns_tunnel", "covert_channel",
        "reverse_shell", "rat", "exfil_dns", "tor_traffic",
    ],
    "actions_on_objectives": [
        "exfiltration", "data_theft", "ransomware", "encrypt", "wiper",
        "credential_dump", "lateral_movement", "data_staging", "destruction",
    ],
}

STAGE_ORDER = [
    "reconnaissance", "weaponization", "delivery",
    "exploitation", "installation", "command_and_control",
    "actions_on_objectives",
]


def _classify_stage(alert: Dict[str, Any]) -> Optional[str]:
    """Determine the kill-chain stage for an alert based on keywords."""
    searchable = " ".join([
        str(alert.get("rule", {}).get("description", "")),
        str(alert.get("title", "")),
        str(alert.get("agent_name", "")),
        " ".join(alert.get("rule", {}).get("groups", []) if isinstance(alert.get("rule"), dict) else []),
        str(alert.get("details", "")),
        str(alert.get("type", "")),
    ]).lower()

    for stage, keywords in STAGE_MAP.items():
        if any(kw in searchable for kw in keywords):
            return stage
    return None


def _extract_iocs(alert: Dict[str, Any]) -> Set[str]:
    """Extract IOCs (IPs, domains) from an alert for cross-stage correlation."""
    iocs: Set[str] = set()
    for field in ("src_ip", "dest_ip", "id.orig_h", "id.resp_h", "source_ip",
                  "destination_ip", "domain", "query", "url"):
        val = alert.get(field) or alert.get("data", {}).get(field, "")
        if val and isinstance(val, str) and len(val) > 3:
            iocs.add(val.lower())
    return iocs


class KillChainAgent(BaseAgent):
    """Correlates alerts across MITRE ATT&CK kill-chain stages."""

    def __init__(self):
        super().__init__(
            name="W15_KillChain",
            description="Correlates events to MITRE ATT&CK kill chain stages",
            interval_seconds=120,
            supervisor_channel="soc:detection-supervisor",
        )
        # Persistent history: host → list of {stage, timestamp, iocs, alert_summary}
        self._host_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # Track already-reported intrusion hashes to avoid duplicates
        self._reported: Dict[str, float] = {}
        self._report_cooldown = 1800  # 30 minutes

    def collect(self) -> List[Dict[str, Any]]:
        """Fetch recent alerts from all SOC indices."""
        try:
            wazuh = self.os_client.get_events_since(
                "wazuh-alerts-*", minutes=CORRELATION_WINDOW_MIN,
                query={"bool": {"must": [{"exists": {"field": "rule.description"}}]}},
                size=3000,
            )
        except Exception as e:
            logger.error("Failed to fetch Wazuh alerts: %s", e)
            wazuh = []
        try:
            soc = self.os_client.get_events_since(
                "soc-alerts-*", minutes=CORRELATION_WINDOW_MIN,
                query={"bool": {"must": [{"exists": {"field": "title"}}]}},
                size=2000,
            )
        except Exception as e:
            logger.error("Failed to fetch SOC alerts: %s", e)
            soc = []
        return wazuh + soc

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classify alerts into stages and correlate by host + IOCs."""
        findings: List[Dict[str, Any]] = []
        now = time.time()
        cutoff = now - (CORRELATION_WINDOW_MIN * 60)

        # Prune stale history entries
        for host in list(self._host_history.keys()):
            self._host_history[host] = [
                e for e in self._host_history[host] if e["timestamp"] > cutoff
            ]
            if not self._host_history[host]:
                del self._host_history[host]

        # Classify new alerts and add to host history
        for alert in data:
            stage = _classify_stage(alert)
            if not stage:
                continue

            host = (alert.get("agent", {}).get("name", "")
                    or alert.get("id.resp_h", "")
                    or alert.get("dest_ip", "unknown"))
            iocs = _extract_iocs(alert)
            ts_str = alert.get("@timestamp") or alert.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
            except (ValueError, AttributeError):
                ts = now

            entry = {
                "stage": stage,
                "timestamp": ts,
                "iocs": iocs,
                "summary": str(alert.get("rule", {}).get("description", alert.get("title", "")))[:120],
            }

            # Avoid duplicate entries in the same bucket
            existing_stages = {e["stage"] for e in self._host_history[host]
                               if abs(e["timestamp"] - ts) < 60}
            if stage not in existing_stages:
                self._host_history[host].append(entry)

        # Evaluate each host for kill-chain progression
        for host, entries in self._host_history.items():
            stages_seen: Dict[str, Dict[str, Any]] = {}
            all_iocs: Set[str] = set()

            for entry in entries:
                s = entry["stage"]
                if s not in stages_seen or entry["timestamp"] > stages_seen[s]["timestamp"]:
                    stages_seen[s] = entry
                all_iocs.update(entry["iocs"])

            stage_count = len(stages_seen)
            if stage_count == 0:
                continue

            # Check IOC overlap across stages for stronger correlation
            ioc_overlap = False
            if stage_count >= 2:
                per_stage_iocs = [e["iocs"] for e in stages_seen.values()]
                for i, iocs_a in enumerate(per_stage_iocs):
                    for iocs_b in per_stage_iocs[i + 1:]:
                        if iocs_a & iocs_b:
                            ioc_overlap = True
                            break

            # Determine severity
            if stage_count >= 3:
                severity = Severity.CRITICAL
            elif stage_count == 2:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            # Boost severity if IOCs overlap across stages
            if ioc_overlap and severity < Severity.CRITICAL:
                severity = Severity(min(severity + 1, Severity.CRITICAL))

            # Only report if not recently reported for this host+stage combo
            report_key = hashlib.sha256(
                f"{host}:{sorted(stages_seen.keys())}".encode()
            ).hexdigest()[:16]
            last_reported = self._reported.get(report_key, 0)
            if (now - last_reported) < self._report_cooldown and stage_count < 3:
                continue

            # Build ordered timeline
            timeline = []
            for stage_name in STAGE_ORDER:
                if stage_name in stages_seen:
                    e = stages_seen[stage_name]
                    timeline.append({
                        "stage": stage_name,
                        "time": datetime.fromtimestamp(e["timestamp"], tz=timezone.utc).isoformat(),
                        "summary": e["summary"],
                    })

            findings.append({
                "type": "kill_chain_progression",
                "severity": severity,
                "host": host,
                "stage_count": stage_count,
                "stages": sorted(stages_seen.keys(), key=lambda s: STAGE_ORDER.index(s)),
                "ioc_overlap": ioc_overlap,
                "shared_iocs": list(all_iocs)[:20],
                "timeline": timeline,
                "details": (f"Host '{host}': {stage_count} kill-chain stage(s) detected — "
                            f"{', '.join(sorted(stages_seen.keys(), key=lambda s: STAGE_ORDER.index(s)))}"
                            f"{' (IOC correlation)' if ioc_overlap else ''}"),
            })
            self._reported[report_key] = now

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Decide on alerting, escalation, and timeline indexing."""
        actions: List[Dict[str, Any]] = []
        for f in findings:
            actions.append({"action": "alert", "data": f})
            if f["severity"] >= Severity.HIGH:
                actions.append({"action": "escalate", "data": f})
            actions.append({"action": "index_timeline", "data": f})
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send alerts, escalate, and index timeline data."""
        results = {"alerts": 0, "escalations": 0, "timelines": 0}
        for action in actions:
            try:
                if action["action"] == "alert":
                    d = action["data"]
                    self.alerter.send_alert(
                        severity=d["severity"],
                        title=f"Kill Chain: {d['stage_count']} stages on {d['host']}",
                        details={"host": d["host"], "stages": ", ".join(d["stages"]),
                                 "ioc_overlap": d["ioc_overlap"], "info": d["details"]},
                        agent_name=self.name,
                    )
                    results["alerts"] += 1
                elif action["action"] == "escalate":
                    self.report_to_supervisor(action["data"])
                    results["escalations"] += 1
                elif action["action"] == "index_timeline":
                    doc = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent": self.name,
                        "host": action["data"]["host"],
                        "stage_count": action["data"]["stage_count"],
                        "stages": action["data"]["stages"],
                        "timeline": action["data"]["timeline"],
                        "severity": action["data"]["severity"].name,
                    }
                    self.os_client.index_document("soc-kill-chain", doc)
                    results["timelines"] += 1
            except Exception as e:
                logger.error("Kill-chain action failed: %s", e)
        return results


if __name__ == "__main__":
    agent = KillChainAgent()
    agent.run_loop()
