"""
SOC Platform – AI Strategic Commander (Qwen-2.5)
The supreme AI coordinator that receives escalations from Mistral Routers
and CyberLlama tactical analysts to make strategic response decisions.
"""

import json
import logging
import time
import os
import requests
import threading
from typing import Any, Dict, List, Optional

from memory.memory_service import CyberMemory
from shared.decision_fusion import DecisionFusionEngine
from shared.trust_engine import TrustEngine
from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.ai_client import AIClient
from config.system_prompts import QWEN_COMMANDER_PROMPT

logger = logging.getLogger("soc.commander")

class CommanderAgent(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="CommanderAgent_Qwen",
            description="Supreme SOC coordinator powered by Qwen-2.5",
            interval_seconds=10,
            config=config,
            supervisor_channel="soc:supervisor-to-commander"
        )
        self.ai_client = AIClient(role="commander", config=config)
        self.pending_reports = []
        self._lock = threading.Lock()
        self._total_decisions = 0
        self._cache_lock = threading.Lock()
        
        # Initialize Cyber Memory Engine
        self.memory = CyberMemory()
        
        # Initialize Decision Fusion Engine
        self.fusion_engine = DecisionFusionEngine()
        
        # Initialize Zero Trust Engine
        self.trust_engine = TrustEngine()

    def handle_worker_message(self, message: dict) -> None:
        try:
            payload = message.get("payload", {})
            with self._lock:
                with self._cache_lock:

                    self.pending_reports.append(payload)
            logger.info(f"Received strategic report: {payload.get('type', 'unknown')}")
        except Exception as exc:
            logger.error("Failed to parse incoming report: %s", exc)

    def collect(self) -> List[Dict[str, Any]]:
        with self._lock:
            batch = list(self.pending_reports)
            with self._cache_lock:

                self.pending_reports.clear()
        return batch

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not data:
            return []

        # 1. Collective Reasoning: Calculate consensus and trigger debate if necessary
        consensus_score, needs_debate = self.fusion_engine.calculate_consensus(data)
        
        if needs_debate:
            consensus_score = self.fusion_engine.trigger_debate(data, self.ai_client)
            
        # 2. Dynamic Trust Penalty
        trust_actions = []
        for report in data:
            src_ip = report.get("src_ip")
            user = report.get("user")
            summary = report.get("summary", report.get("incident_summary", "Malicious Activity"))
            
            if src_ip:
                res = self.trust_engine.penalize(src_ip, consensus_score, summary)
                if res.get("action"):
                    trust_actions.append(res["action"])
            if user:
                res = self.trust_engine.penalize(user, consensus_score, summary)
                if res.get("action"):
                    trust_actions.append(res["action"])
            
        # Build context for Qwen
        context = {
            "timestamp": time.time(),
            "active_reports": data,
            "fused_threat_score": consensus_score,
            "debate_triggered": needs_debate,
            "zero_trust_automated_actions": trust_actions
        }
        
        # Inject Cyber Memory Context
        try:
            query_text = json.dumps(data)
            # Truncate query to avoid overly large embeddings
            if len(query_text) > 1000:
                query_text = query_text[:1000]
                
            historical = self.memory.search_similar_incidents(query_text, limit=3)
            if historical:
                context["historical_similar_incidents"] = historical
                logger.info(f"Injected {len(historical)} historical incidents into Commander's context.")
        except Exception as mem_err:
            logger.error(f"Failed to query Cyber Memory: {mem_err}")
        try:
            context_json = json.dumps(context, default=str)
        except Exception as e:
            logger.error(f"Failed to serialize context for Qwen: {e}")
            return []
            
        prompt = f"Analyze the current War-room context and provide strategic decisions:\n```json\n{context_json}\n```"
        logger.info(f"Commander Qwen analyzing {len(data)} aggregated reports...")
        
        try:
            response = self.ai_client.generate(prompt, system_prompt=QWEN_COMMANDER_PROMPT, json_mode=True)
        except Exception as e:
            logger.error(f"Qwen generation failed: {e}")
            return []
            
        decision = self.ai_client.extract_json(response)
        
        return [decision]

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        actions = []
        for decision in findings:
            try:
                if decision.get("error"):
                    logger.error(f"Qwen Generation Error: {decision}")
                    continue
                    
                logger.critical(f"STRATEGIC ASSESSMENT: {decision.get('incident_summary')}")
                logger.critical(f"OVERALL SEVERITY: {decision.get('overall_severity')}")
                
                # Store the decision in Cyber Memory for future reference
                try:
                    self.memory.store_incident(decision)
                except Exception as mem_err:
                    logger.error(f"Failed to store decision in Cyber Memory: {mem_err}")
                
                for action in decision.get("actions", []):
                    try:
                        actions.append(action)
                    except Exception as e:
                        logger.warning("Error processing action in decide: %s", e)
            except Exception as e:
                logger.warning("Error processing decision in decide: %s", e)
                
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"executed": 0}
        for action in actions:
            try:
                action_type = action.get("type")
                target = action.get("target")
                reason = action.get("reason")
                
                logger.info(f"Submitting PROPOSED_ACTION: {action_type} on {target} to Execution Layer.")
                
                payload = {
                    "action_id": f"act_{int(time.time()*1000)}",
                    "timestamp": time.time(),
                    "source": self.name,
                    "action_type": action_type,
                    "target": target,
                    "reason": reason,
                    "status": "PENDING_APPROVAL"
                }
                
                self.redis_bus.publish("soc:proposed-actions", payload, sender=self.name, message_type="PROPOSED_ACTION")
                
                results["executed"] += 1
                self._total_decisions += 1
            except Exception as e:
                logger.warning("Error executing action in act: %s", e)
            
        return results

    def run_loop(self):
        self.redis_bus.subscribe(self.supervisor_channel, self.handle_worker_message)
        # Also subscribe to the tactical channel just in case tactical agent sends direct escalations
        self.redis_bus.subscribe("soc:tactical-analysis", self.handle_worker_message)
        super().run_loop()

if __name__ == "__main__":
    agent = CommanderAgent()
    agent.run_loop()
