import time
import logging
from typing import Dict, Any, List
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("W21-IOCEnrichment")

class IOCEnrichmentAgent(BaseAgent):
    def __init__(self, supervisor_queue):
        super().__init__(
            name="W21_IOCEnrichment",
            description="Enriches IOCs using external APIs",
            supervisor_queue=supervisor_queue,
            interval_seconds=120
        )
        self.config = SOCConfig()

    def collect(self) -> List[Dict[str, Any]]:
        # Fetch unenriched IOCs from OpenSearch
        return []

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {}

if __name__ == "__main__":
    agent = IOCEnrichmentAgent(supervisor_queue="soc:detection-supervisor")
    agent.start_in_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
