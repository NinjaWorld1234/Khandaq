import json
import logging
import threading
from typing import Dict, Any, List, Optional
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.ai_client import AIClient
from config.system_prompts import MISTRAL_ROUTER_PROMPT

logger = logging.getLogger("NetworkSupervisor")


class NetworkSupervisor(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None):
        super().__init__(
            name="NetworkSupervisor_Mistral",
            description="Supervises network agents and uses Mistral AI for context compression and routing",
            interval_seconds=10,
            config=config,
            supervisor_channel="soc:network-supervisor"
        )
        self.recent_alerts: list[dict] = []  # Keep a sliding window of alerts in memory
        self._lock = threading.Lock()
        self.ai_client = AIClient(role="router", config=config)
        self._cache_lock = threading.Lock()

    def collect(self) -> List[Dict[str, Any]]:
        # Supervisor mostly reacts to sub-agent messages via pub/sub, not polling,
        # but we use collect to process the internal buffer of received alerts.
        with self._lock:
            alerts_to_process = self.recent_alerts.copy()
            with self._cache_lock:

                self.recent_alerts.clear()  # Clear the buffer safely
        return alerts_to_process

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not data:
            return []

        # Convert the batch of alerts into a JSON string for Mistral
        try:
            alerts_json = json.dumps(data, default=str)
        except Exception as e:
            logger.error(f"Failed to serialize alerts for Mistral: {e}")
            return []

        prompt = f"Analyze the following batch of network security alerts:\n```json\n{alerts_json}\n```"

        logger.info(f"Sending {len(data)} alerts to Mistral Router for compression and routing...")
        try:
            response = self.ai_client.generate(prompt, system_prompt=MISTRAL_ROUTER_PROMPT, json_mode=True)
        except Exception as e:
            logger.error(f"Mistral generation failed: {e}")
            return []

        parsed_response = self.ai_client.extract_json(response)

        # Attach the original data so it can be forwarded
        parsed_response["original_alerts_count"] = len(data)
        parsed_response["raw_data"] = data

        return [parsed_response]

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for finding in findings:
            try:
                if finding.get("error"):
                    logger.error(f"Mistral Routing Error: {finding}")
                    continue
    
                route = finding.get("route_to", "discard").lower()
                if route == "tactical":
                    actions.append({"action": "route_tactical", "data": finding})
                elif route == "commander":
                    actions.append({"action": "route_commander", "data": finding})
                else:
                    logger.info(f"Mistral discarded batch. Summary: {finding.get('summary')}")
            except Exception as e:
                logger.warning("Error processing finding in decide: %s", e)
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"routed_tactical": 0, "routed_commander": 0}
        for action in actions:
            try:
                payload = action.get("data", {})
                action_type = action.get("action")
                try:
                    if action_type == "route_tactical":
                        self.redis_bus.publish("soc:tactical-analysis", payload, sender=self.name,
                                               message_type="compressed_tactical")
                        results["routed_tactical"] += 1
                    elif action_type == "route_commander":
                        self.redis_bus.publish("soc:supervisor-to-commander", payload,
                                               sender=self.name, message_type="compressed_strategic")
                        results["routed_commander"] += 1
                except Exception as e:
                    logger.error(f"Failed to route action {action_type} to redis: {e}")
            except Exception as e:
                logger.warning("Error processing action in act: %s", e)
        return results

    def handle_worker_message(self, message: dict):
        try:
            payload = message.get("payload") or {}
            source = message.get("sender") or payload.get("agent_name", "unknown")
            logger.info(f"Received alert from {source}")
            alert_data = payload
            alert_data["agent_source"] = source
            with self._lock:
                with self._cache_lock:

                    self.recent_alerts.append(alert_data)
        except Exception as e:
            logger.error(f"Failed parsing worker message: {e}")

    def run_loop(self):
        # Subscribe to worker channel
        self.redis_bus.subscribe(self.supervisor_channel, self.handle_worker_message)
        # Call base run_loop
        super().run_loop()


if __name__ == "__main__":
    agent = NetworkSupervisor()
    agent.run_loop()
