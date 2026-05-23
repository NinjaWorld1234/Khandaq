"""
W11 - DDoS Detection Agent
Detects volumetric, protocol, and application-layer DDoS attacks by
querying Zeek conn.log and Suricata alerts from OpenSearch.

Attack types detected:
  1. SYN flood (>1000 SYN packets/sec to a single host)
  2. UDP flood (high-volume UDP traffic)
  3. HTTP flood (>500 requests/sec to a web server)
  4. DNS amplification (large DNS responses from many sources)
  5. Slowloris (many half-open connections)
  6. Volumetric attacks (>1 Gbps traffic spike)
"""

import time
import logging
import hashlib
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict
from datetime import datetime, timezone
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("W11-DDoSDetection")

# Thresholds
SYN_FLOOD_PPS = 1000          # SYN packets per second
UDP_FLOOD_MBPS = 500          # Megabits per second of UDP
HTTP_FLOOD_RPS = 500          # HTTP requests per second
DNS_AMP_SOURCES = 20          # Distinct sources sending large DNS replies
DNS_AMP_RESP_BYTES = 512      # Minimum DNS response size for amplification
SLOWLORIS_HALF_OPEN = 200     # Half-open connections to single dest
VOLUMETRIC_GBPS = 1.0         # Gigabits per second overall
BASELINE_EWMA_ALPHA = 0.3    # Exponential weighted moving average factor


class DDoSDetectionAgent(BaseAgent):
    """Detects DDoS attacks across network traffic."""

    def __init__(self):
        super().__init__(
            name="W11_DDoSDetection",
            description="Detects volumetric, protocol, and application layer DDoS attacks",
            interval_seconds=30,
            supervisor_channel="soc:network-supervisor",
        )
        # Per-destination traffic baselines: dest_ip -> {"bytes_avg", "pps_avg"}
        self._baselines: Dict[str, Dict[str, float]] = {}
        # Track IPs already under rate-limiting to avoid duplicate actions
        self._rate_limited: Dict[str, float] = {}
        self._rate_limit_ttl = 300  # seconds before re-alerting

    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Zeek conn.log and Suricata alerts from the last 1 minute."""
        conn_query = {"bool": {"must": [{"exists": {"field": "id.resp_h"}}]}}
        suricata_query = {
            "bool": {"must": [
                {"term": {"event_type": "alert"}},
                {"exists": {"field": "dest_ip"}},
            ]}
        }
        try:
            conns = self.os_client.get_events_since("zeek-conn-*", minutes=1, query=conn_query, size=5000)
            suricata = self.os_client.get_events_since("suricata-*", minutes=1, query=suricata_query, size=1000)
            return conns + suricata
        except Exception as e:
            logger.error("Failed to collect DDoS data: %s", e)
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run all six DDoS detection rules against collected data."""
        findings: List[Dict[str, Any]] = []
        if not data:
            return findings

        interval = max(self.interval_seconds, 1)

        # Aggregate metrics per destination
        dest_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "syn_count": 0, "udp_bytes": 0, "http_reqs": 0,
            "dns_resp_sources": set(), "dns_large_bytes": 0,
            "half_open": 0, "total_bytes": 0, "sources": set(),
        })

        for event in data:
            dest_ip = event.get("id.resp_h") or event.get("dest_ip", "")
            src_ip = event.get("id.orig_h") or event.get("src_ip", "unknown")
            proto = (event.get("proto") or event.get("app_proto") or "").lower()
            conn_state = event.get("conn_state", "")
            resp_bytes = int(event.get("resp_bytes", 0) or 0)
            orig_bytes = int(event.get("orig_bytes", 0) or 0)
            total = resp_bytes + orig_bytes
            service = (event.get("service") or "").lower()
            resp_p = int(event.get("id.resp_p", 0) or 0)

            if not dest_ip:
                continue

            s = dest_stats[dest_ip]
            s["total_bytes"] += total
            s["sources"].add(src_ip)

            # SYN detection: Zeek conn_state S0 = SYN sent, no reply
            if conn_state in ("S0", "S1", "SH", "SHR") and proto == "tcp":
                s["syn_count"] += 1

            # UDP volume
            if proto == "udp":
                s["udp_bytes"] += total

            # HTTP requests (ports 80/443 or service http/ssl)
            if resp_p in (80, 443, 8080, 8443) or service in ("http", "ssl"):
                s["http_reqs"] += 1

            # DNS amplification: large DNS responses from many sources
            if (service == "dns" or resp_p == 53) and resp_bytes > DNS_AMP_RESP_BYTES:
                s["dns_resp_sources"].add(src_ip)
                s["dns_large_bytes"] += resp_bytes

            # Slowloris: half-open TCP connections
            if conn_state in ("S0", "S1") and proto == "tcp":
                s["half_open"] += 1

        # Evaluate rules per destination
        for dest_ip, s in dest_stats.items():
            src_count = len(s["sources"])
            syn_pps = s["syn_count"] / interval
            udp_mbps = (s["udp_bytes"] * 8) / (interval * 1_000_000)
            http_rps = s["http_reqs"] / interval
            total_gbps = (s["total_bytes"] * 8) / (interval * 1_000_000_000)

            # Update baseline with EWMA
            baseline = self._baselines.get(dest_ip, {"bytes_avg": float(s["total_bytes"]), "pps_avg": 0.0})
            baseline["bytes_avg"] = (BASELINE_EWMA_ALPHA * s["total_bytes"]
                                     + (1 - BASELINE_EWMA_ALPHA) * baseline["bytes_avg"])
            self._baselines[dest_ip] = baseline

            # Rule 1 — SYN flood
            if syn_pps > SYN_FLOOD_PPS:
                findings.append({
                    "type": "syn_flood", "severity": Severity.CRITICAL,
                    "dest_ip": dest_ip, "syn_pps": round(syn_pps, 1),
                    "source_count": src_count,
                    "details": f"SYN flood: {syn_pps:.0f} SYN/s → {dest_ip} from {src_count} sources",
                })

            # Rule 2 — UDP flood
            if udp_mbps > UDP_FLOOD_MBPS:
                findings.append({
                    "type": "udp_flood", "severity": Severity.HIGH,
                    "dest_ip": dest_ip, "udp_mbps": round(udp_mbps, 1),
                    "details": f"UDP flood: {udp_mbps:.0f} Mbps → {dest_ip}",
                })

            # Rule 3 — HTTP flood
            if http_rps > HTTP_FLOOD_RPS:
                findings.append({
                    "type": "http_flood", "severity": Severity.HIGH,
                    "dest_ip": dest_ip, "http_rps": round(http_rps, 1),
                    "details": f"HTTP flood: {http_rps:.0f} req/s → {dest_ip}",
                })

            # Rule 4 — DNS amplification
            if len(s["dns_resp_sources"]) > DNS_AMP_SOURCES:
                findings.append({
                    "type": "dns_amplification", "severity": Severity.HIGH,
                    "dest_ip": dest_ip, "reflector_count": len(s["dns_resp_sources"]),
                    "amp_bytes": s["dns_large_bytes"],
                    "details": (f"DNS amplification: {len(s['dns_resp_sources'])} reflectors, "
                                f"{s['dns_large_bytes']} bytes → {dest_ip}"),
                })

            # Rule 5 — Slowloris
            if s["half_open"] > SLOWLORIS_HALF_OPEN:
                findings.append({
                    "type": "slowloris", "severity": Severity.MEDIUM,
                    "dest_ip": dest_ip, "half_open": s["half_open"],
                    "details": f"Slowloris: {s['half_open']} half-open connections → {dest_ip}",
                })

            # Rule 6 — Volumetric
            if total_gbps > VOLUMETRIC_GBPS:
                findings.append({
                    "type": "volumetric", "severity": Severity.CRITICAL,
                    "dest_ip": dest_ip, "gbps": round(total_gbps, 2),
                    "details": f"Volumetric attack: {total_gbps:.2f} Gbps → {dest_ip}",
                })

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build action list: alert, escalate, and trigger rate limiting."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for f in findings:
            dest_ip = f["dest_ip"]
            actions.append({"action": "alert", "data": f})

            # Escalate HIGH and CRITICAL
            if f["severity"] >= Severity.HIGH:
                actions.append({"action": "escalate", "data": f})

            # Rate-limit if critical and not already limited recently
            last_limited = self._rate_limited.get(dest_ip, 0)
            if f["severity"] >= Severity.HIGH and (now - last_limited) > self._rate_limit_ttl:
                actions.append({
                    "action": "rate_limit",
                    "dest_ip": dest_ip,
                    "attack_type": f["type"],
                })
                self._rate_limited[dest_ip] = now

        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alerting, escalation, and rate-limiting actions."""
        results = {"alerts_sent": 0, "escalations": 0, "rate_limits": 0}
        for action in actions:
            try:
                if action["action"] == "alert":
                    d = action["data"]
                    self.alerter.send_alert(
                        severity=d["severity"],
                        title=f"DDoS: {d['type'].replace('_', ' ').title()}",
                        details={"dest_ip": d["dest_ip"], "info": d["details"]},
                        agent_name=self.name,
                    )
                    results["alerts_sent"] += 1

                elif action["action"] == "escalate":
                    self.report_to_supervisor(action["data"])
                    results["escalations"] += 1

                elif action["action"] == "rate_limit":
                    ar_doc = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent": self.name,
                        "action": "rate_limit",
                        "dest_ip": action["dest_ip"],
                        "attack_type": action["attack_type"],
                        "command": "firewall-drop",
                        "status": "requested",
                    }
                    self.os_client.index_document("soc-active-response", ar_doc)
                    logger.warning("Rate-limit requested for %s (%s)", action["dest_ip"], action["attack_type"])
                    results["rate_limits"] += 1
            except Exception as e:
                logger.error("Action failed: %s", e)

        if results["alerts_sent"]:
            logger.info("DDoS cycle: %d alerts, %d escalations, %d rate-limits",
                        results["alerts_sent"], results["escalations"], results["rate_limits"])
        return results


if __name__ == "__main__":
    agent = DDoSDetectionAgent()
    agent.run_loop()
