import logging
import math
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("W06-DNSTunneling")

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [ float(s.count(c)) / len(s) for c in dict.fromkeys(list(s)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

class DNSTunnelingAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="W06_DNSTunneling",
            description="Monitors DNS queries for tunneling patterns and DGA",
            interval_seconds=60,
            supervisor_channel="soc:network-supervisor"
        )
        self.whitelist = ["google.com", "microsoft.com", "windowsupdate.com", "amazon.com", "apple.com"]

    def collect(self) -> List[Dict[str, Any]]:
        # Fetch Zeek dns.log
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "query"}},
                    ]
                }
            }
        }
        try:
            return self.os_client.get_events_since(
                index="zeek-dns-*",
                minutes=2,
                query=query
            )
        except Exception as e:
            logger.error(f"Failed to collect events: {e}")
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        domain_counts = {}
        
        for event in data:
            try:
                query_name = event.get("query", "").lower()
                qtype = event.get("qtype_name", "")
                src_ip = event.get("id.orig_h", "unknown")

                if not query_name or any(query_name.endswith(w) for w in self.whitelist):
                    continue
                    
                # Split domain
                parts = query_name.split('.')
                if len(parts) >= 2:
                    root_domain = f"{parts[-2]}.{parts[-1]}"
                    subdomain = ".".join(parts[:-2])
                else:
                    root_domain = query_name
                    subdomain = ""

                # Track unique subdomains per root domain
                if root_domain not in domain_counts:
                    domain_counts[root_domain] = {"src": src_ip, "subdomains": set()}
                if subdomain:
                    domain_counts[root_domain]["subdomains"].add(subdomain)

                # Rule 1: High entropy subdomain
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

                # Rule 2: Long domain names
                if len(query_name) > 60:
                    findings.append({
                        "type": "long_dns_query",
                        "severity": Severity.MEDIUM,
                        "domain": query_name,
                        "src_ip": src_ip,
                        "details": f"Unusually long DNS query ({len(query_name)} chars): {query_name}"
                    })

                # Rule 3: TXT/NULL records
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
                logger.error(f"Error analyzing event: {e}")
                
        # Rule 4: High volume of unique subdomains (Data exfiltration pattern)
        for root_domain, info in domain_counts.items():
            if len(info["subdomains"]) > 30:
                findings.append({
                    "type": "dns_tunneling_suspected",
                    "severity": Severity.CRITICAL,
                    "domain": root_domain,
                    "src_ip": info["src"],
                    "count": len(info["subdomains"]),
                    "details": f"Suspected DNS Tunneling: {len(info['subdomains'])} unique subdomains queried for {root_domain}"
                })

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"DNS Anomaly: {finding['type']}",
                "details": finding["details"],
                "agent_name": finding.get("src_ip", "Network")
            }
            actions.append({"action": "alert", "data": alert})
            
            if finding["severity"] in [Severity.HIGH, Severity.CRITICAL]:
                actions.append({"action": "escalate", "data": finding})
                
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"alerts_sent": 0, "escalations": 0}
        for action in actions:
            if action["action"] == "alert":
                alert_data = action["data"]
                self.alerter.send_alert(
                    severity=alert_data["severity"],
                    title=alert_data["title"],
                    details=alert_data["details"],
                    agent_name=alert_data["agent_name"]
                )
                results["alerts_sent"] += 1
            elif action["action"] == "escalate":
                self.report_to_supervisor(action["data"])
                results["escalations"] += 1
        return results

if __name__ == "__main__":
    agent = DNSTunnelingAgent()
    agent.run_loop()
