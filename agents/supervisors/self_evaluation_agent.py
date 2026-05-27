"""
SOC Platform - Self Evaluation Agent
Listens to HITL feedback (Approvals/Rejections) and dynamically adjusts the reputation/weight
of the AI agents. This implements a basic Reinforcement Learning (RL) feedback loop.
"""

import time
import logging
import threading
from typing import List, Dict, Any, Optional

from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.evaluator")

class SelfEvaluationAgent(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="self_evaluation_agent",
            description="Adjusts AI agent weights based on human feedback (RL)",
            interval_seconds=10,
            config=config,
            supervisor_channel="soc:ai-feedback"
        )
        self.pending_feedback = []
        self._lock = threading.Lock()
        
        # RL Parameters
        self.MAX_WEIGHT = 2.0
        self.MIN_WEIGHT = 0.1
        self.PENALTY_STEP = 0.1 # Deducted on rejection
        self.REWARD_STEP = 0.05 # Added on approval

    def handle_worker_message(self, message: dict) -> None:
        try:
            payload = message.get("payload", {})
            if not payload:
                return
            with self._lock:
                self.pending_feedback.append(payload)
        except Exception as exc:
            logger.error("Failed to parse feedback message: %s", exc)

    def collect(self) -> List[Dict[str, Any]]:
        with self._lock:
            batch = list(self.pending_feedback)
            self.pending_feedback.clear()
        return batch

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not data:
            return []
            
        findings = []
        for feedback in data:
            source = feedback.get("source_role", "unknown")
            status = feedback.get("status")
            
            if source == "unknown":
                continue
                
            # Current Reputation
            current_weight_str = None
            if hasattr(self, 'redis_bus') and self.redis_bus.redis_client:
                try:
                    current_weight_str = self.redis_bus.redis_client.hget("soc:agent_reputation", source)
                except Exception as e:
                    logger.warning(f"Failed to fetch reputation from Redis: {e}")
            
            # Defaults if missing
            if current_weight_str is None:
                if source == "commander": current_weight = 1.5
                elif source == "supervisor": current_weight = 1.2
                else: current_weight = 1.0
            else:
                current_weight = float(current_weight_str)
                
            new_weight = current_weight
            
            if status == "rejected":
                new_weight = max(self.MIN_WEIGHT, current_weight - self.PENALTY_STEP)
                logger.warning(f"📉 Agent '{source}' PENALIZED. Weight dropped from {current_weight:.2f} to {new_weight:.2f}. Reason: {feedback.get('reason')}")
            elif status == "approved":
                new_weight = min(self.MAX_WEIGHT, current_weight + self.REWARD_STEP)
                logger.info(f"📈 Agent '{source}' REWARDED. Weight increased from {current_weight:.2f} to {new_weight:.2f}.")
                
            findings.append({
                "source": source,
                "new_weight": new_weight,
                "status": status
            })
            
        return findings

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Format for Redis update
        return findings

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"weights_updated": 0, "stats_updated": 0}
        
        for action in actions:
            try:
                source = action.get("source")
                new_weight = action.get("new_weight")
                status = action.get("status") # We need to pass status from analyze to act
                if not source or new_weight is None:
                    continue
                
                if hasattr(self, 'redis_bus') and self.redis_bus.redis_client:
                    r = self.redis_bus.redis_client
                    # 1. Update reputation weight
                    r.hset("soc:agent_reputation", source, str(new_weight))
                    results["weights_updated"] += 1
                    
                    # 2. Update historical stats
                    stats_key = f"soc:agent_stats:{source}"
                    
                    if status == "approved":
                        r.hincrby(stats_key, "correct", 1)
                    elif status == "rejected":
                        r.hincrby(stats_key, "incorrect", 1)
                        
                    r.hincrby(stats_key, "total_decisions", 1)
                    
                    # 3. Calculate and store accuracy percentage
                    correct = int(r.hget(stats_key, "correct") or 0)
                    total = int(r.hget(stats_key, "total_decisions") or 0)
                    accuracy_pct = (correct / total * 100) if total > 0 else 100.0
                    r.hset(stats_key, "accuracy_pct", str(round(accuracy_pct, 2)))
                    
                    results["stats_updated"] += 1
                else:
                    logger.warning("Redis client unavailable. Cannot update reputation/stats.")
            except Exception as e:
                logger.error(f"Error updating agent reputation: {e}")
                
        return results

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = SelfEvaluationAgent()
    agent.run_loop()
