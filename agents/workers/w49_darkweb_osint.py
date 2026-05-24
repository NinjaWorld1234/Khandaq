import time
import logging
import requests
from typing import Any, Dict, List, Optional
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("W49-DarkWebOSINT")

class DarkWebOSINTAgent(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w49_darkweb_osint",
            description="Monitors OSINT feeds for corporate leaks using AlienVault OTX API.",
            interval_seconds=3600, # Run once an hour
            config=config,
            supervisor_channel="soc:detection-supervisor"
        )
        self.keywords = ["khandaq", "khandaq.local", "vip@khandaq.com"]
        # Simulated Open CTI / AlienVault Pulses endpoint
        self.otx_api_url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        self.api_key = self._agent_config.get("otx_api_key", "")

    def collect(self) -> List[Dict[str, Any]]:
        findings = []
        if not self.api_key:
            logger.debug("No OTX API key configured. Simulating OSINT fetch instead.")
            # Simulate a leak for testing if no API key
            findings.append({
                "source": "Pastebin_Simulated",
                "content": "Hackers selling access to khandaq.local admin panel",
                "timestamp": time.time()
            })
            return findings

        try:
            headers = {"X-OTX-API-KEY": self.api_key}
            response = requests.get(self.otx_api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for pulse in data.get("results", []):
                    findings.append({
                        "source": f"AlienVault OTX Pulse: {pulse.get('id')}",
                        "content": str(pulse.get('description', '')) + " " + str(pulse.get('name', '')),
                        "timestamp": time.time()
                    })
        except Exception as e:
            logger.error(f"Failed to fetch OTX pulses: {e}")
            
        return findings

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for item in data:
            content_lower = item.get("content", "").lower()
            for kw in self.keywords:
                if kw in content_lower:
                    findings.append({
                        "type": "DATA_LEAK_DETECTED",
                        "severity": Severity.CRITICAL,
                        "host": "External (OSINT)",
                        "details": f"Corporate keyword '{kw}' found in {item['source']}. Content snippet: {item['content'][:100]}",
                        "response": "FORCE_PASSWORD_RESET"
                    })
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"OSINT Leak: {finding['type']}",
                "details": finding["details"],
                "agent_name": "W49_DarkWebOSINT"
            }
            actions.append({"action": "alert", "data": alert})
            actions.append({"action": "escalate", "data": finding})
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"escalated": 0, "alerts_sent": 0}
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
                results["escalated"] += 1
        return results

if __name__ == "__main__":
    agent = DarkWebOSINTAgent()
    agent.run_loop()
