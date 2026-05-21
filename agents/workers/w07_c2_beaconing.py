import time
import logging
import numpy as np
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("W07-C2Beaconing")

class C2BeaconingAgent(BaseAgent):
    def __init__(self, supervisor_queue):
        super().__init__(
            name="W07_C2Beaconing",
            description="Monitors connections for periodic beaconing patterns indicative of C2",
            supervisor_queue=supervisor_queue,
            interval_seconds=120
        )
        self.config = SOCConfig()
        self.min_connections = 10

    def collect(self) -> List[Dict[str, Any]]:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "id.orig_h"}},
                        {"exists": {"field": "id.resp_h"}},
                    ]
                }
            }
        }
        try:
            # We need a longer window to detect periodic connections
            return self.os_client.get_events_since(
                index="zeek-conn-*",
                minutes=60,
                query=query
            )
        except Exception as e:
            logger.error(f"Failed to collect events: {e}")
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        connections = {}

        # Group connections by src->dst pair
        for event in data:
            try:
                src_ip = event.get("id.orig_h")
                dst_ip = event.get("id.resp_h")
                ts = event.get("ts") # Zeek timestamp in epoch
                
                # Ignore internal traffic for C2 checks (assume internal is 10.x, 192.168.x, 172.16.x)
                if dst_ip and (dst_ip.startswith("10.") or dst_ip.startswith("192.168.") or 
                               (dst_ip.startswith("172.") and int(dst_ip.split('.')[1]) in range(16, 32))):
                    continue

                if not src_ip or not dst_ip or not ts:
                    continue

                pair_key = f"{src_ip}->{dst_ip}"
                if pair_key not in connections:
                    connections[pair_key] = []
                connections[pair_key].append(float(ts))

            except Exception as e:
                logger.error(f"Error parsing event: {e}")

        # Analyze intervals
        for pair_key, timestamps in connections.items():
            if len(timestamps) < self.min_connections:
                continue

            timestamps.sort()
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            mean_interval = np.mean(intervals)
            std_dev = np.std(intervals)
            
            if mean_interval == 0:
                continue
                
            variance_pct = (std_dev / mean_interval) * 100
            src_ip, dst_ip = pair_key.split("->")

            if variance_pct < 10:
                findings.append({
                    "type": "c2_regular_beaconing",
                    "severity": Severity.CRITICAL,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "mean_interval_sec": mean_interval,
                    "variance_pct": variance_pct,
                    "connection_count": len(timestamps),
                    "details": f"Highly regular beaconing detected to {dst_ip} (interval: {mean_interval:.1f}s, variance: {variance_pct:.1f}%)"
                })
            elif variance_pct < 20:
                findings.append({
                    "type": "c2_jittered_beaconing",
                    "severity": Severity.HIGH,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "mean_interval_sec": mean_interval,
                    "variance_pct": variance_pct,
                    "connection_count": len(timestamps),
                    "details": f"Jittered beaconing detected to {dst_ip} (interval: {mean_interval:.1f}s, variance: {variance_pct:.1f}%)"
                })

        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"C2 Beaconing: {finding['type']}",
                "details": finding["details"],
                "agent_name": finding["src_ip"]
            }
            actions.append({"action": "alert", "data": alert})
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
    agent = C2BeaconingAgent(supervisor_queue="soc:network-supervisor")
    agent.start_in_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
