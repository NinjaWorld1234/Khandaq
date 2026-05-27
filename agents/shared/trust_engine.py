"""
SOC Platform - Dynamic Trust Engine (Zero Trust)
Manages behavioral trust scores for entities (IPs, Users) using Redis as a ledger.
"""

import os
import time
import logging
from typing import List, Dict, Any, Optional

import redis

logger = logging.getLogger("soc.trust")

class TrustEngine:
    def __init__(self):
        self.max_score = 100.0
        self.recovery_rate = 1.0 # points per hour
        
        # Thresholds
        self.THRESHOLD_WARN = 80.0
        self.THRESHOLD_MFA = 70.0      # Require MFA below this
        self.THRESHOLD_MONITOR = 50.0
        self.THRESHOLD_ISOLATE = 25.0
        
        # Connect to Redis
        redis_host = os.environ.get("REDIS_HOST", "redis-ai")
        redis_port = int(os.environ.get("REDIS_PORT", 6379))
        redis_password = os.environ.get("REDIS_PASSWORD", "Ch@ngeMe_Redis_AI_2024!")
        
        try:
            self.redis_client = redis.Redis(
                host=redis_host, 
                port=redis_port, 
                password=redis_password,
                decode_responses=True
            )
            self.redis_client.ping()
            self.enabled = True
            logger.info("✅ Connected to Redis Trust Ledger successfully.")
        except Exception as e:
            logger.error(f"❌ Failed to connect to Redis Trust Ledger: {e}")
            self.enabled = False

    def _get_key(self, entity: str) -> str:
        return f"soc:trust:{entity}"
        
    def _get_last_updated_key(self, entity: str) -> str:
        return f"soc:trust:{entity}:last_updated"

    def get_score(self, entity: str) -> float:
        """Retrieves the current trust score, applying time-based recovery."""
        if not self.enabled or not entity:
            return self.max_score
            
        key = self._get_key(entity)
        time_key = self._get_last_updated_key(entity)
        
        try:
            score_str = self.redis_client.get(key)
            time_str = self.redis_client.get(time_key)
            
            if score_str is None:
                return self.max_score
                
            score = float(score_str)
            last_updated = float(time_str) if time_str else time.time()
            
            # Apply recovery
            hours_passed = (time.time() - last_updated) / 3600.0
            if hours_passed > 0:
                recovered_score = min(self.max_score, score + (hours_passed * self.recovery_rate))
                
                # Update if recovery happened
                if recovered_score > score:
                    self.redis_client.set(key, recovered_score)
                    self.redis_client.set(time_key, time.time())
                return recovered_score
                
            return score
        except Exception as e:
            logger.error(f"Error getting trust score for {entity}: {e}")
            return self.max_score

    def penalize(self, entity: str, threat_score: float, reason: str = "") -> Dict[str, Any]:
        """
        Deducts points based on threat_score and returns threshold actions if crossed.
        """
        if not self.enabled or not entity:
            return {"action": None}
            
        # Current score
        current_score = self.get_score(entity)
        
        # Calculate penalty. A threat_score of 100 = 40 point penalty (adjustable).
        penalty = (threat_score / 100.0) * 40.0 
        new_score = max(0.0, current_score - penalty)
        
        key = self._get_key(entity)
        time_key = self._get_last_updated_key(entity)
        
        try:
            self.redis_client.set(key, new_score)
            self.redis_client.set(time_key, time.time())
            logger.warning(f"Trust penalty applied to {entity}. Score dropped from {current_score:.1f} to {new_score:.1f}. Reason: {reason}")
        except Exception as e:
            logger.error(f"Error setting trust score for {entity}: {e}")
            return {"action": None}
            
        # Determine Zero Trust Action (escalating severity)
        action = None
        if current_score >= self.THRESHOLD_ISOLATE and new_score < self.THRESHOLD_ISOLATE:
            # CRITICAL: Score < 25 → Isolate/Disable
            action = {
                "type": "isolate_host" if "." in entity else "disable_user",
                "target": entity,
                "reason": f"Zero Trust Threshold Breached (<25). Last offense: {reason}"
            }
        elif current_score >= self.THRESHOLD_MONITOR and new_score < self.THRESHOLD_MONITOR:
            # HIGH: Score < 50 → Enhanced Monitoring
            action = {
                "type": "monitor_step_up",
                "target": entity,
                "reason": f"Trust Score fell below 50. Initiating enhanced monitoring. Reason: {reason}"
            }
        elif current_score >= self.THRESHOLD_MFA and new_score < self.THRESHOLD_MFA:
            # MEDIUM: Score < 70 → Require MFA
            action = {
                "type": "require_mfa",
                "target": entity,
                "reason": f"Trust Score fell below 70. Requiring multi-factor authentication. Reason: {reason}"
            }
            logger.warning(f"🔐 MFA Required for {entity}: Trust score {new_score:.1f} < 70.0")
            
        return {
            "entity": entity,
            "old_score": current_score,
            "new_score": new_score,
            "action": action
        }
