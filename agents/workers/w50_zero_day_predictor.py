import logging
from typing import Any, Dict, List, Optional
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("W50-ZeroDayPredictor")

class ZeroDayPredictorAgent(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w50_zero_day_predictor",
            description="Analyzes unknown/failed attack signatures to predict Zero-Day exploits.",
            interval_seconds=3600, # Run hourly to correlate low-severity anomalies
            config=config,
            supervisor_channel="soc:detection-supervisor"
        )
        self.anomaly_threshold = 5

    def collect(self) -> List[Dict[str, Any]]:
        # Fetch Wazuh alerts that are anomalies but not explicitly matched to a severe known rule
        # e.g., frequent application crashes, unrecognized binaries executed but blocked, etc.
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": 3, "lte": 6}}}, # Low/Medium severity
                    ],
                    "should": [
                        {"match": {"rule.description": "segfault"}},
                        {"match": {"rule.description": "unknown binary"}},
                        {"match": {"rule.description": "heap corruption"}},
                    ],
                    "minimum_should_match": 1
                }
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                minutes=60,
                query=query
            )
        except Exception as e:
            logger.error(f"Failed to collect anomaly events: {e}")
            return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        host_anomalies = {}

        for event in data:
            try:
                host = event.get("agent", {}).get("name", "unknown")
                desc = event.get("rule", {}).get("description", "Unknown anomaly")
                if host not in host_anomalies:
                    host_anomalies[host] = []
                host_anomalies[host].append(desc)
            except Exception as e:
                logger.error(f"Error parsing event: {e}")

        for host, anomalies in host_anomalies.items():
            if len(anomalies) >= self.anomaly_threshold:
                findings.append({
                    "type": "potential_zero_day_recon",
                    "severity": Severity.HIGH,
                    "host": host,
                    "anomaly_count": len(anomalies),
                    "details": f"High volume of unusual system faults ({len(anomalies)}) on {host}. This pattern often precedes a Zero-Day exploit attempt. Faults: {list(set(anomalies))[:3]}"
                })
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"Zero-Day Prediction: {finding['type']}",
                "details": finding["details"],
                "agent_name": "W50_ZeroDayPredictor"
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
    agent = ZeroDayPredictorAgent()
    agent.run_loop()
