import logging
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("W08-DataExfiltration")

class DataExfiltrationAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="W08_DataExfiltration",
            description="Monitors outbound data volume for exfiltration",
            interval_seconds=120,
            supervisor_channel="soc:network-supervisor"
        )
        self.whitelist_ips = ["8.8.8.8", "8.8.4.4"] # Example whitelist
        self.single_transfer_threshold = 500 * 1024 * 1024 # 500MB

    def collect(self) -> List[Dict[str, Any]]:
        # Fetch Zeek conn.log
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "orig_bytes"}},
                        {"exists": {"field": "resp_bytes"}},
                    ]
                }
            }
        }
        try:
            return self.os_client.get_events_since(
                index="zeek-conn-*",
                minutes=2,
                query=query
            )
        except Exception as e:
            logger.error(f"Failed to collect events: {e}")
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        host_bytes_out = {}
        
        for event in data:
            try:
                src_ip = event.get("id.orig_h")
                dst_ip = event.get("id.resp_h")
                orig_bytes = event.get("orig_bytes", 0)
                resp_bytes = event.get("resp_bytes", 0)

                # Skip internal traffic
                if dst_ip and (dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or 
                               (dst_ip.startswith("172.") and int(dst_ip.split('.')[1]) in range(16, 32))):
                    continue

                if dst_ip in self.whitelist_ips:
                    continue

                if not src_ip:
                    continue

                if src_ip not in host_bytes_out:
                    host_bytes_out[src_ip] = 0
                host_bytes_out[src_ip] += orig_bytes

                # Rule 1: Single large transfer
                if orig_bytes > self.single_transfer_threshold:
                    findings.append({
                        "type": "large_single_transfer",
                        "severity": Severity.HIGH,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "bytes": orig_bytes,
                        "details": f"Large single transfer of {orig_bytes / (1024*1024):.2f} MB to {dst_ip}"
                    })

                # Rule 2: Upload > Download unusual ratio
                if orig_bytes > (10 * 1024 * 1024) and orig_bytes > (resp_bytes * 5):
                    findings.append({
                        "type": "unusual_upload_ratio",
                        "severity": Severity.MEDIUM,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "orig_bytes": orig_bytes,
                        "resp_bytes": resp_bytes,
                        "details": f"Unusual upload ratio to {dst_ip} (Up: {orig_bytes}, Down: {resp_bytes})"
                    })

            except Exception as e:
                logger.error(f"Error analyzing event: {e}")

        # Rule 3: Cumulative transfer anomaly (simplified without actual ML baseline for now)
        for src_ip, total_bytes in host_bytes_out.items():
            if total_bytes > (100 * 1024 * 1024): # Over 100MB in 2 minutes is suspicious
                findings.append({
                    "type": "high_cumulative_transfer",
                    "severity": Severity.HIGH,
                    "src_ip": src_ip,
                    "bytes": total_bytes,
                    "details": f"High cumulative data transfer from {src_ip}: {total_bytes / (1024*1024):.2f} MB"
                })

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"Data Exfiltration: {finding['type']}",
                "details": finding["details"],
                "agent_name": finding["src_ip"]
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
    agent = DataExfiltrationAgent()
    agent.run_loop()
