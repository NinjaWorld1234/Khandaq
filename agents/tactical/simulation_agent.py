"""
SOC Platform - Predictive Simulation Agent + MITRE ATT&CK Attack Trees
Monitors the Live Attack Graph (Neo4j) to predict the next lateral movement target
and proposes proactive immunization actions using both graph topology and MITRE
ATT&CK attack chain patterns.
"""

import os
import time
import json
import logging
import threading
from typing import List, Dict, Any, Optional

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

from shared.base_agent import BaseAgent
from shared.config import SOCConfig

try:
    from tactical.attack_trees import predict_next_stage
    ATTACK_TREES_AVAILABLE = True
except ImportError:
    try:
        from attack_trees import predict_next_stage
        ATTACK_TREES_AVAILABLE = True
    except ImportError:
        ATTACK_TREES_AVAILABLE = False
        logger = logging.getLogger("soc.simulation")  # Early init for warning

logger = logging.getLogger("soc.simulation")

class SimulationAgent(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="simulation_agent",
            description="Predicts lateral movement paths using Neo4j Attack Graph",
            interval_seconds=15,
            config=config,
            supervisor_channel="soc:tactical-analysis"
        )
        self.pending_reports = []
        self._lock = threading.Lock()
        
        if not NEO4J_AVAILABLE:
            logger.error("Neo4j Python driver not installed. Simulation Agent disabled.")
            self.enabled = False
            return
            
        self.enabled = True
        
        neo4j_uri = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
        neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
        neo4j_password = os.environ.get("NEO4J_PASSWORD", "Ch@ngeMe_Neo4j_2024!")
        
        try:
            self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            self.driver.verify_connectivity()
            logger.info("✅ Simulation Agent connected to Neo4j successfully.")
        except Exception as e:
            logger.error(f"❌ Simulation Agent failed to connect to Neo4j: {e}")
            self.enabled = False

    def handle_worker_message(self, message: dict) -> None:
        try:
            payload = message.get("payload", {})
            if not payload:
                return
            with self._lock:
                self.pending_reports.append(payload)
        except Exception as exc:
            logger.error("Failed to parse event for simulation: %s", exc)

    def collect(self) -> List[Dict[str, Any]]:
        with self._lock:
            batch = list(self.pending_reports)
            self.pending_reports.clear()
        return batch

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.enabled or not data:
            return []
            
        predictions = []
        
        # ============================================================
        # Phase 1: Neo4j Graph-Based Neighbor Analysis (existing)
        # تحليل الجيران في خريطة الهجوم
        # ============================================================
        with self.driver.session() as session:
            for report in data:
                src_ip = report.get("src_ip")
                dst_ip = report.get("dst_ip")
                
                target_ip = dst_ip or src_ip
                if not target_ip:
                    continue
                    
                try:
                    query = (
                        "MATCH (ip:IP {address: $target_ip})-[:SOURCE_OF|AFFECTED]-(a:Alert)-[:AFFECTED|SOURCE_OF]-(adj_ip:IP) "
                        "WHERE ip.address <> adj_ip.address "
                        "RETURN DISTINCT adj_ip.address AS risk_ip LIMIT 3"
                    )
                    
                    result = session.run(query, target_ip=target_ip)
                    
                    for record in result:
                        risk_ip = record["risk_ip"]
                        logger.warning(f"🔮 Predictive Simulation: {risk_ip} is adjacent to compromised node {target_ip}. Risk of Lateral Movement.")
                        
                        predictions.append({
                            "type": "graph_prediction",
                            "predicted_target": risk_ip,
                            "reason": f"Adjacent to compromised node {target_ip} in Attack Graph.",
                            "recommended_action": "monitor_step_up",
                            "severity": "HIGH",
                            "threat_score": 75.0,
                            "summary": f"[GRAPH] Lateral Movement threat towards {risk_ip}"
                        })
                except Exception as e:
                    logger.error(f"Error querying Neo4j for simulation: {e}")

        # ============================================================
        # Phase 2: MITRE ATT&CK Attack Tree Prediction (NEW)
        # تنبؤ بالمرحلة التالية بناءً على أشجار الهجوم
        # ============================================================
        if ATTACK_TREES_AVAILABLE:
            for report in data:
                try:
                    technique_id = report.get("mitre_technique_id")
                    event_type = report.get("type", report.get("event_type"))
                    target_ip = report.get("dst_ip") or report.get("src_ip") or report.get("target")

                    mitre_predictions = predict_next_stage(
                        current_technique_id=technique_id,
                        event_type=event_type,
                    )

                    for mp in mitre_predictions[:3]:  # Limit to top 3
                        predicted_stage = mp.get("predicted_stage", {})
                        confidence = mp.get("confidence", 0.5)
                        
                        logger.warning(
                            f"🌳 MITRE Prediction: After {mp.get('current_stage')}, "
                            f"expect '{predicted_stage.get('name')}' "
                            f"({predicted_stage.get('mitre_technique_id')}) "
                            f"— Confidence: {confidence:.0%}"
                        )

                        predictions.append({
                            "type": "mitre_prediction",
                            "predicted_target": target_ip or "network",
                            "reason": (
                                f"MITRE ATT&CK Chain '{mp.get('chain_name')}': "
                                f"After {mp.get('current_stage')}, "
                                f"next expected stage is '{predicted_stage.get('name')}' "
                                f"({predicted_stage.get('mitre_technique_id')}). "
                                f"Look for: {', '.join(predicted_stage.get('indicators', []))}"
                            ),
                            "recommended_action": mp.get("recommended_defense", "monitor_step_up"),
                            "severity": "CRITICAL" if confidence >= 0.8 else "HIGH",
                            "threat_score": round(confidence * 100, 1),
                            "mitre_chain": mp.get("chain_name"),
                            "mitre_technique": predicted_stage.get("mitre_technique_id"),
                            "steps_away": mp.get("steps_away"),
                            "summary": (
                                f"[MITRE] Predict '{predicted_stage.get('name')}' "
                                f"({predicted_stage.get('mitre_technique_id')}) — "
                                f"{confidence:.0%} confidence"
                            ),
                        })
                except Exception as e:
                    logger.error(f"Error in MITRE prediction: {e}")
        else:
            logger.debug("Attack Trees module not available, skipping MITRE prediction.")

        return predictions

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Forward predictions as proactive actions
        actions = []
        for pred in findings:
            action = {
                "type": pred.get("recommended_action", "monitor_step_up"),
                "target": pred.get("predicted_target"),
                "reason": pred.get("reason"),
                "source": "Predictive Simulation Agent"
            }
            actions.append(action)
        return actions

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"proactive_actions_sent": 0}
        
        for action in actions:
            try:
                # We send predictive actions to the proposed actions channel so HITL can review them
                payload = {
                    "action_id": f"sim_{int(time.time()*1000)}",
                    "timestamp": time.time(),
                    "source": self.name,
                    "action_type": action.get("type"),
                    "target": action.get("target"),
                    "reason": action.get("reason"),
                    "status": "PENDING_APPROVAL" # Sent to HITL
                }
                
                logger.info(f"Submitting PROACTIVE ACTION: {action.get('type')} on {action.get('target')} to Execution Layer.")
                self.redis_bus.publish("soc:proposed-actions", payload, sender=self.name, message_type="PROPOSED_ACTION")
                results["proactive_actions_sent"] += 1
            except Exception as e:
                logger.error(f"Error acting on simulation: {e}")
                
        return results

    def close(self):
        if self.enabled:
            self.driver.close()

    def run_loop(self):
        self.redis_bus.subscribe(self.supervisor_channel, self.handle_worker_message)
        try:
            super().run_loop()
        finally:
            self.close()

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = SimulationAgent()
    agent.run_loop()
