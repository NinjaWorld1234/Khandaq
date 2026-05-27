"""
SOC Platform - Decision Fusion Engine (Collective Reasoning)
Aggregates threat scores from multiple agents using Weighted Voting and triggers Debates.
"""

import logging
import os
import redis
from typing import List, Dict, Any, Tuple

logger = logging.getLogger("soc.fusion")

class DecisionFusionEngine:
    def __init__(self):
        # Default Weights (fallback)
        self.default_weights = {
            "commander": 1.5,
            "supervisor": 1.2,
            "tactical": 1.0,
            "router": 0.8
        }
        
        # Threshold for variance that triggers a debate
        self.debate_variance_threshold = 30.0
        
        # Redis Connection for dynamic weights
        redis_host = os.environ.get("REDIS_HOST", "redis-ai")
        redis_port = int(os.environ.get("REDIS_PORT", 6379))
        redis_password = os.environ.get("REDIS_PASSWORD", "Ch@ngeMe_Redis_AI_2024!")
        
        try:
            self.redis_client = redis.Redis(
                host=redis_host, port=redis_port, password=redis_password, decode_responses=True
            )
            self.redis_client.ping()
        except Exception:
            self.redis_client = None

    def _get_agent_weight(self, source: str) -> float:
        """Fetch dynamically adjusted weight from Redis, or use default."""
        if not self.redis_client:
            return self.default_weights.get(source, 1.0)
            
        try:
            weight_str = self.redis_client.hget("soc:agent_reputation", source)
            if weight_str:
                return float(weight_str)
        except Exception:
            pass
            
        return self.default_weights.get(source, 1.0)

    def calculate_consensus(self, reports: List[Dict[str, Any]]) -> Tuple[float, bool]:
        """
        Calculates the weighted average of threat scores.
        Returns (consensus_score, needs_debate)
        """
        if not reports:
            return 0.0, False
            
        total_weight = 0.0
        weighted_sum = 0.0
        scores = []
        
        for report in reports:
            # Extract score, defaulting to 50 if missing
            score = report.get("threat_score", 50.0)
            try:
                score = float(score)
            except (ValueError, TypeError):
                score = 50.0
                
            # Determine source weight dynamically
            source = report.get("source_role", "tactical")
            weight = self._get_agent_weight(source)
            
            weighted_sum += score * weight
            total_weight += weight
            scores.append(score)
            
        if total_weight == 0:
            return 0.0, False
            
        consensus_score = weighted_sum / total_weight
        
        # Calculate variance to see if agents strongly disagree
        max_score = max(scores)
        min_score = min(scores)
        variance = max_score - min_score
        
        needs_debate = variance > self.debate_variance_threshold
        
        if needs_debate:
            logger.warning(f"High variance detected in agent scores (Min: {min_score}, Max: {max_score}). Debate needed.")
        else:
            logger.info(f"Consensus reached. Score: {consensus_score:.2f}")
            
        return consensus_score, needs_debate

    def trigger_debate(self, reports: List[Dict[str, Any]], ai_client) -> float:
        """
        Multi-Round Debate Protocol / بروتوكول النقاش متعدد الجولات

        Round 1: Each agent presents its analysis and score.
        Round 2: Agents see each other's summaries and may revise their scores.
        Round 3: The Commander (Qwen) arbitrates the final score.

        This produces a higher-quality consensus than simple averaging.
        """
        logger.info("🗣️ Triggering Multi-Round AI Debate Protocol...")

        # ---------------------------------------------------------------
        # Round 1: Collect Individual Agent Positions
        # الجولة 1: جمع مواقف الوكلاء الفردية
        # ---------------------------------------------------------------
        agent_positions = []
        for i, report in enumerate(reports):
            score = report.get("threat_score", 50.0)
            try:
                score = float(score)
            except (ValueError, TypeError):
                score = 50.0

            position = {
                "agent_id": report.get("source_role", report.get("agent_name", f"agent_{i}")),
                "score": score,
                "summary": report.get("summary", report.get("incident_summary", "No analysis provided")),
                "iocs": report.get("iocs", []),
                "mitre_tactic": report.get("mitre_tactic", ""),
            }
            agent_positions.append(position)

        logger.info(f"  Round 1: Collected {len(agent_positions)} agent positions.")

        # ---------------------------------------------------------------
        # Round 2: Cross-Review — Each agent sees others' analyses
        # الجولة 2: المراجعة المتبادلة — كل وكيل يرى تحليلات الآخرين
        # ---------------------------------------------------------------
        cross_review_prompt = (
            "You are a SOC analyst reviewing other agents' analyses of the same incident.\n\n"
            "Here are ALL agent assessments:\n"
        )
        for pos in agent_positions:
            cross_review_prompt += (
                f"- **{pos['agent_id']}** scored {pos['score']}/100: "
                f"{pos['summary'][:200]}\n"
            )

        cross_review_prompt += (
            "\nBased on seeing all these perspectives, provide a revised threat score "
            "and explain your reasoning. Consider:\n"
            "1. Do any agents have evidence the others are missing?\n"
            "2. Is there a false-positive risk any agent identified?\n"
            "3. What's the most dangerous interpretation of the evidence?\n\n"
            "Return ONLY a JSON object: {\"revised_score\": <number>, \"reasoning\": \"<text>\"}"
        )

        revised_scores = []
        try:
            response = ai_client.generate(cross_review_prompt, json_mode=True)
            revision = ai_client.extract_json(response)
            revised_score = float(revision.get("revised_score", 50.0))
            revised_reasoning = revision.get("reasoning", "")
            revised_scores.append(revised_score)
            logger.info(f"  Round 2: Cross-review produced revised score: {revised_score:.1f}")
        except Exception as e:
            logger.warning(f"  Round 2 failed: {e}. Proceeding to arbitration.")
            revised_scores = [p["score"] for p in agent_positions]

        # ---------------------------------------------------------------
        # Round 3: Commander Arbitration — Final decision
        # الجولة 3: حكم القائد — القرار النهائي
        # ---------------------------------------------------------------
        arbitration_prompt = (
            "You are the Supreme Arbiter in a SOC war-room debate.\n\n"
            "=== ORIGINAL AGENT POSITIONS ===\n"
        )
        for pos in agent_positions:
            arbitration_prompt += (
                f"Agent '{pos['agent_id']}': Score={pos['score']}, "
                f"Analysis={pos['summary'][:150]}\n"
            )

        if revised_scores:
            arbitration_prompt += (
                f"\n=== CROSS-REVIEW RESULT ===\n"
                f"Revised average score after cross-review: {sum(revised_scores) / len(revised_scores):.1f}\n"
            )

        arbitration_prompt += (
            "\n=== YOUR TASK ===\n"
            "Weigh ALL evidence. Provide your final verdict:\n"
            "- If agents with higher reputation scores provide stronger evidence, weight accordingly.\n"
            "- If there are confirmed IOCs (IPs, hashes), lean towards the higher score.\n"
            "- If it looks like a false positive, explain why.\n\n"
            "Return ONLY a JSON: {\"resolved_threat_score\": <0-100>, \"debate_reasoning\": \"<text>\", "
            "\"confidence\": <0.0-1.0>}"
        )

        try:
            response = ai_client.generate(arbitration_prompt, json_mode=True)
            decision = ai_client.extract_json(response)

            resolved_score = float(decision.get("resolved_threat_score", 50.0))
            reasoning = decision.get("debate_reasoning", "No reasoning provided")
            confidence = float(decision.get("confidence", 0.5))

            logger.info(
                f"  Round 3: Commander verdict — Score: {resolved_score:.1f}, "
                f"Confidence: {confidence:.0%}. Reasoning: {reasoning[:120]}..."
            )

            # Publish debate results to Redis for audit trail
            if self.redis_client:
                try:
                    import json, time
                    debate_record = {
                        "timestamp": time.time(),
                        "agent_positions": agent_positions,
                        "revised_scores": revised_scores,
                        "final_score": resolved_score,
                        "confidence": confidence,
                        "reasoning": reasoning,
                    }
                    self.redis_client.lpush(
                        "soc:debate_history",
                        json.dumps(debate_record, default=str),
                    )
                    # Keep last 100 debates
                    self.redis_client.ltrim("soc:debate_history", 0, 99)
                except Exception:
                    pass

            return resolved_score
        except Exception as e:
            logger.error(f"Debate arbitration failed: {e}. Falling back to weighted consensus.")
            consensus, _ = self.calculate_consensus(reports)
            return consensus
