"""
SOC Platform - Graph Ingestion Agent + Critical Path Engine
Listens to SOC events and builds a Live Attack Graph in Neo4j.
Includes Critical Path analysis to detect attackers approaching Crown Jewels.
"""

import os
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

logger = logging.getLogger("soc.graph")

class GraphAgent(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="graph_agent",
            description="Builds Live Attack Graph in Neo4j",
            interval_seconds=5,
            config=config,
            supervisor_channel="soc:tactical-analysis"
        )
        self.pending_events = []
        self._lock = threading.Lock()
        
        if not NEO4J_AVAILABLE:
            logger.error("Neo4j Python driver not installed. Graph Agent disabled.")
            self.enabled = False
            return
            
        self.enabled = True
        
        neo4j_uri = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
        neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
        neo4j_password = os.environ.get("NEO4J_PASSWORD", "Ch@ngeMe_Neo4j_2024!")
        
        try:
            self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            self.driver.verify_connectivity()
            logger.info("✅ Connected to Neo4j Graph Database successfully.")
        except Exception as e:
            logger.error(f"❌ Failed to connect to Neo4j: {e}")
            self.enabled = False
            return

        # Crown Jewels — Critical Assets to protect
        # أصول حرجة — يمكن تعريفها من ENV أو من هنا
        crown_jewels_env = os.environ.get("CROWN_JEWELS", "")
        if crown_jewels_env:
            self.crown_jewels = [ip.strip() for ip in crown_jewels_env.split(",") if ip.strip()]
        else:
            # Default Crown Jewels (adjust per deployment)
            self.crown_jewels = [
                "10.0.1.1",       # Core Router/Firewall
                "10.0.1.10",      # Domain Controller
                "10.0.1.20",      # Database Server
                "10.0.1.30",      # SIEM/OpenSearch
                "192.168.1.1",    # Gateway
            ]

        # Initialize Crown Jewels in Neo4j
        self._init_crown_jewels_nodes()

    def handle_worker_message(self, message: dict) -> None:
        try:
            payload = message.get("payload", {})
            if not payload:
                return

            with self._lock:
                self.pending_events.append(payload)
            logger.debug(f"Received event for graph ingestion: {payload.get('type')}")
        except Exception as exc:
            logger.error("Failed to parse event for graph: %s", exc)

    def collect(self) -> List[Dict[str, Any]]:
        with self._lock:
            batch = list(self.pending_events)
            self.pending_events.clear()
        return batch

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Graph Agent doesn't "analyze" in the AI sense, it just prepares data for Neo4j
        return data

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return findings

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not self.enabled:
            return {"executed": 0}
            
        results = {"nodes_merged": 0, "edges_created": 0}
        
        with self.driver.session() as session:
            for event in actions:
                try:
                    # Extract common entities
                    src_ip = event.get("src_ip")
                    dst_ip = event.get("dst_ip")
                    user = event.get("user")
                    alert_type = event.get("type", "Unknown Alert")
                    
                    # Generate a unique ID for the alert if not provided
                    alert_id = event.get("id", event.get("action_id", str(hash(json.dumps(event)))))
                    
                    if not src_ip and not dst_ip and not user:
                        # Might be a commander action (target usually contains IP)
                        target = event.get("target")
                        if target:
                            dst_ip = target
                        else:
                            continue # Not enough data to graph
                        
                    # 1. Merge Alert Node
                    session.run(
                        "MERGE (a:Alert {id: $alert_id}) "
                        "SET a.type = $alert_type, a.timestamp = timestamp()",
                        alert_id=alert_id,
                        alert_type=alert_type
                    )
                    results["nodes_merged"] += 1
                    
                    # 2. Merge Source IP and Edge
                    if src_ip:
                        session.run(
                            "MERGE (ip:IP {address: $src_ip}) "
                            "WITH ip "
                            "MATCH (a:Alert {id: $alert_id}) "
                            "MERGE (ip)-[:SOURCE_OF]->(a)",
                            src_ip=src_ip, alert_id=alert_id
                        )
                        results["nodes_merged"] += 1
                        results["edges_created"] += 1
                        
                    # 3. Merge Destination IP and Edge
                    if dst_ip:
                        session.run(
                            "MERGE (ip:IP {address: $dst_ip}) "
                            "WITH ip "
                            "MATCH (a:Alert {id: $alert_id}) "
                            "MERGE (a)-[:AFFECTED]->(ip)",
                            dst_ip=dst_ip, alert_id=alert_id
                        )
                        results["nodes_merged"] += 1
                        results["edges_created"] += 1
                        
                    # 4. Merge User and Edge
                    if user:
                        session.run(
                            "MERGE (u:User {username: $user}) "
                            "WITH u "
                            "MATCH (a:Alert {id: $alert_id}) "
                            "MERGE (u)-[:TRIGGERED]->(a)",
                            user=user, alert_id=alert_id
                        )
                        results["nodes_merged"] += 1
                        results["edges_created"] += 1
                        
                except Exception as e:
                    logger.error(f"Error executing Cypher query: {e}")
        if results["nodes_merged"] > 0:
            # Run Critical Path analysis after each ingestion batch
            try:
                critical_findings = self.find_critical_paths()
                results["critical_paths_found"] = len(critical_findings)
            except Exception as e:
                logger.error(f"Critical path analysis failed: {e}")

        return results

    def close(self):
        if self.enabled:
            self.driver.close()

    def _init_crown_jewels_nodes(self):
        """Initialize Crown Jewel nodes in Neo4j with a :CrownJewel label."""
        try:
            with self.driver.session() as session:
                for cj_ip in self.crown_jewels:
                    session.run(
                        "MERGE (ip:IP {address: $ip}) "
                        "SET ip:CrownJewel, ip.is_critical = true",
                        ip=cj_ip,
                    )
                logger.info(f"👑 Initialized {len(self.crown_jewels)} Crown Jewel nodes in Neo4j.")
        except Exception as e:
            logger.error(f"Failed to initialize Crown Jewels: {e}")

    def find_critical_paths(self) -> List[Dict[str, Any]]:
        """
        Find shortest paths from known attacker IPs to Crown Jewels.
        اكتشاف أقصر مسار من IPs المهاجمين إلى الأصول الحرجة

        Returns a list of critical path findings.
        """
        findings = []
        if not self.enabled:
            return findings

        try:
            with self.driver.session() as session:
                # Find all IPs that have been SOURCE_OF an alert (potential attackers)
                # Then check if there's a short path to any Crown Jewel
                query = (
                    "MATCH (attacker:IP)-[:SOURCE_OF]->(a:Alert) "
                    "WHERE NOT attacker:CrownJewel "
                    "WITH DISTINCT attacker "
                    "MATCH (cj:CrownJewel) "
                    "WHERE attacker.address <> cj.address "
                    "MATCH path = shortestPath((attacker)-[*..6]-(cj)) "
                    "WITH attacker, cj, path, length(path) AS hops "
                    "WHERE hops <= 4 "
                    "RETURN attacker.address AS attacker_ip, "
                    "       cj.address AS crown_jewel, "
                    "       hops, "
                    "       [n IN nodes(path) | CASE WHEN n:IP THEN n.address "
                    "                                WHEN n:Alert THEN n.type "
                    "                                ELSE 'unknown' END] AS path_nodes "
                    "ORDER BY hops ASC "
                    "LIMIT 10"
                )

                result = session.run(query)

                for record in result:
                    attacker_ip = record["attacker_ip"]
                    crown_jewel = record["crown_jewel"]
                    hops = record["hops"]
                    path_nodes = record["path_nodes"]

                    severity = "CRITICAL" if hops <= 2 else "HIGH"
                    logger.critical(
                        f"🚨 CRITICAL PATH: Attacker {attacker_ip} is {hops} hop(s) "
                        f"away from Crown Jewel {crown_jewel}! Path: {' → '.join(str(n) for n in path_nodes)}"
                    )

                    finding = {
                        "type": "critical_path",
                        "attacker_ip": attacker_ip,
                        "crown_jewel": crown_jewel,
                        "hops": hops,
                        "path": path_nodes,
                        "severity": severity,
                        "recommended_action": "isolate_host" if hops <= 2 else "monitor_step_up",
                        "summary": f"[CRITICAL PATH] {attacker_ip} → {crown_jewel} ({hops} hops)",
                    }
                    findings.append(finding)

                    # Publish critical path alert to Commander
                    try:
                        self.redis_bus.publish(
                            "soc:supervisor-to-commander",
                            {
                                "source": self.name,
                                "payload": finding,
                            },
                            sender=self.name,
                            message_type="CRITICAL_PATH_ALERT",
                        )
                    except Exception as pub_err:
                        logger.error(f"Failed to publish critical path alert: {pub_err}")

        except Exception as e:
            logger.error(f"Error running critical path analysis: {e}")

        if findings:
            logger.warning(f"🔍 Found {len(findings)} critical path(s) to Crown Jewels.")
        return findings

    def run_loop(self):
        self.redis_bus.subscribe(self.supervisor_channel, self.handle_worker_message)
        # Also subscribe to commander actions to graph AI decisions
        self.redis_bus.subscribe("soc:proposed-actions", self.handle_worker_message)
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
    agent = GraphAgent()
    agent.run_loop()
