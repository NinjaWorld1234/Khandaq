import json
import logging
import threading
from typing import Dict, Any, List, Optional
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.ai_client import AIClient
from config.system_prompts import CYBERLLAMA_TACTICAL_PROMPT

logger = logging.getLogger("TacticalAnalyst")

class TacticalAnalyst(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None):
        super().__init__(
            name="TacticalAnalyst_WhiteRabbitNeo",
            description="Performs deep technical malware and MITRE ATT&CK analysis using WhiteRabbitNeo",
            interval_seconds=10,
            config=config,
            supervisor_channel="soc:tactical-analysis"
        )
        self.pending_tasks = [] 
        self._lock = threading.Lock()
        self.ai_client = AIClient(role="tactical", config=config)
        self._cache_lock = threading.Lock()

    def collect(self) -> List[Dict[str, Any]]:
        with self._lock:
            tasks = self.pending_tasks.copy()
            with self._cache_lock:

                self.pending_tasks.clear()
        return tasks

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for task in data:
            # Mistral already summarized it in task["summary"] and attached raw data in task["raw_data"]
            try:
                raw_data_json = json.dumps(task.get('raw_data'), default=str)
            except Exception as e:
                logger.error(f"Failed to serialize raw_data: {e}")
                continue
                
            prompt = f"Analyze this incident:\nSummary: {task.get('summary')}\nRaw Data:\n{raw_data_json}"
            
            # Phase 6: Zero Trust - Inject reputation warnings
            confidence_warning = task.get("confidence_warning")
            if confidence_warning:
                prompt += f"\n\n[WARNING]: {confidence_warning}\nTake this low reputation into account and verify the findings extremely carefully before recommending any drastic actions."
            
            logger.info("Sending incident to WhiteRabbitNeo for tactical MITRE analysis...")
            try:
                response = self.ai_client.generate(prompt, system_prompt=CYBERLLAMA_TACTICAL_PROMPT, json_mode=True)
            except Exception as e:
                logger.error(f"WhiteRabbitNeo generation failed: {e}")
                continue
                
            parsed = self.ai_client.extract_json(response)
            
            # Attach original summary
            parsed["original_summary"] = task.get("summary")
            findings.append(parsed)
            
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            if finding.get("error"):
                logger.error(f"WhiteRabbitNeo Analysis Error: {finding}")
                continue
                
            if finding.get("escalate_to_commander", False):
                actions.append({"action": "escalate", "data": finding})
            else:
                logger.info(f"Tactical analysis complete, no escalation needed. Tactic: {finding.get('mitre_tactic')}")
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"escalated_to_commander": 0}
        for action in actions:
            try:
                if action.get("action") == "escalate":
                    self.redis_bus.publish("soc:supervisor-to-commander", action["data"], sender=self.name, message_type="tactical_escalation")
                    results["escalated_to_commander"] += 1
            except Exception as e:
                logger.error(f"Failed to escalate to commander: {e}")
        return results

    def handle_worker_message(self, message: dict):
        try:
            payload = message.get("payload", {})
            with self._lock:
                with self._cache_lock:

                    self.pending_tasks.append(payload)
        except Exception as e:
            logger.error(f"Failed parsing tactical task: {e}")

    def run_loop(self):
        self.redis_bus.subscribe(self.supervisor_channel, self.handle_worker_message)
        super().run_loop()

if __name__ == "__main__":
    agent = TacticalAnalyst()
    agent.run_loop()
