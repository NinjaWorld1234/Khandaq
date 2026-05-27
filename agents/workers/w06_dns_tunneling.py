# SOC Platform - Worker Agent W06: DNS Tunneling
# وكيل كشف الاختراق وتهريب البيانات عبر DNS
"""
DNS Tunneling Agent
===================

Monitors DNS queries for tunneling patterns (Data Exfiltration & C2 over DNS).
Analyzes Zeek DNS logs via OpenSearch for:
1. High entropy subdomains (e.g., base64.evil.com).
2. Unusually long DNS queries.
3. Suspicious QType queries (TXT, NULL).
4. High volumes of unique subdomains queried under a single root domain (e.g., iodine, dnscat2).

Interval: 60 seconds
"""

from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.worker.w06_dns_tunneling")


def calculate_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


class DNSTunnelingAgent(BaseAgent):
    """
    DNS Tunneling Agent - Detects data exfiltration and C2 over DNS.
    وكيل كشف تهريب البيانات عبر بروتوكول DNS
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w06_dns_tunneling",
            description="Monitors DNS queries for tunneling patterns and DGA.",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self.whitelist = self._agent_config.get(
            "whitelist",
            ["google.com", "microsoft.com", "windowsupdate.com", "amazon.com", "apple.com", "cloudflare.com"]
        )

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Zeek DNS logs."""
        query = {
            "bool": {
                "must": [
                    {"exists": {"field": "query"}},
                ]
            }
        }
        try:
            return self.os_client.get_events_since(
                index="zeek-dns-*",
                minutes=2,
                query=query,
                size=10000
            )
        except Exception as e:
            logger.error("Failed to collect Zeek DNS events: %s", e)
            return []

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify tunneling patterns and DGA domains."""
        findings = []
        domain_counts: Dict[str, Dict[str, Any]] = {}

        for event in data:
            try:
                query_name = str(event.get("query") or "").lower()
                qtype = str(event.get("qtype_name") or "")
                src_ip = str(event.get("id.orig_h") or "unknown")

                if not query_name or any(query_name == w or query_name.endswith("." + w) for w in self.whitelist):
                    continue

                # Split domain to identify subdomains and root
                parts = query_name.split('.')
                if len(parts) >= 2:
                    root_domain = f"{parts[-2]}.{parts[-1]}"
                    subdomain = ".".join(parts[:-2])
                else:
                    root_domain = query_name
                    subdomain = ""

                # Track unique subdomains per root domain for volumetric analysis
                if root_domain not in domain_counts:
                    domain_counts[root_domain] = {"src": src_ip, "subdomains": set()}
                if subdomain:
                    domain_counts[root_domain]["subdomains"].add(subdomain)

                # Rule 1: High entropy subdomain (often base64 or encrypted data)
                if subdomain and len(subdomain) > 10:
                    entropy = calculate_entropy(subdomain)
                    if entropy > 3.8:
                        findings.append({
                            "type": "high_entropy_dns",
                            "severity": Severity.HIGH,
                            "domain": query_name,
                            "src_ip": src_ip,
                            "details": f"High entropy ({entropy:.2f}) DNS query: {query_name}"
                        })

                # Rule 2: Long domain names (Tunneling limits to ~253 chars, but > 60 is suspicious)
                if len(query_name) > 60:
                    findings.append({
                        "type": "long_dns_query",
                        "severity": Severity.MEDIUM,
                        "domain": query_name,
                        "src_ip": src_ip,
                        "details": f"Unusually long DNS query ({len(query_name)} chars): {query_name}"
                    })

                # Rule 3: TXT / NULL records (Often used for large C2 payload delivery)
                if qtype in ["TXT", "NULL"]:
                    findings.append({
                        "type": "suspicious_dns_qtype",
                        "severity": Severity.LOW,
                        "domain": query_name,
                        "qtype": qtype,
                        "src_ip": src_ip,
                        "details": f"Suspicious DNS query type {qtype} for {query_name}"
                    })

            except Exception as e:
                logger.warning("Error analyzing DNS event: %s", e)

        # Rule 4: High volume of unique subdomains (Classic DNS Tunneling / DGA exfiltration pattern)
        for root_domain, info in domain_counts.items():
            try:
                if len(info["subdomains"]) > 30:
                    findings.append({
                        "type": "dns_tunneling_suspected",
                        "severity": Severity.CRITICAL,
                        "domain": root_domain,
                        "src_ip": info["src"],
                        "count": len(info["subdomains"]),
                        "details": f"Suspected DNS Tunneling: {len(info['subdomains'])} unique subdomains queried for {root_domain}"
                    })
            except Exception as e:
                logger.warning("Error analyzing DNS tunneling count: %s", e)

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    # ------------------------------------------------------------------
    # Decide / قرار
    # ------------------------------------------------------------------
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Formulate alert and escalation actions."""
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"🌐 DNS Anomaly: {finding['type']}",
                "details": {
                    "src_ip": finding.get("src_ip", "Network"),
                    "domain": finding.get("domain", "Unknown"),
                    "details": finding["details"]
                },
            }
            actions.append({"action": "alert", "data": alert})

            if finding["severity"] in (Severity.HIGH, Severity.CRITICAL):
                actions.append({
                    "action": "escalate",
                    "data": {
                        "type": "dns_tunneling_report",
                        "severity": finding["severity"],
                        "title": alert["title"],
                        "details": alert["details"]
                    }
                })

        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Dispatch alerts and supervisor reports."""
        results = {"alerts_sent": 0, "escalated": 0}

        for action in actions:
            if action["action"] == "alert":
                alert_data = action["data"]
                sent = self.alerter.send_alert(
                    severity=alert_data["severity"],
                    title=alert_data["title"],
                    details=alert_data["details"],
                    agent_name=self.name
                )
                if sent:
                    results["alerts_sent"] += 1
                    self._metrics.inc_alerts(alert_data["severity"].name)

            elif action["action"] == "escalate":
                self.report_to_supervisor(action["data"])
                results["escalated"] += 1

        return results


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
    agent = DNSTunnelingAgent()
    agent.run_loop()
