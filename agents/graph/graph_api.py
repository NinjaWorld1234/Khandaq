"""
SOC Platform — Graph API (Neo4j → Dashboard)
واجهة برمجية لتزويد Dashboard بخريطة الهجوم الحية

Endpoints:
    GET /api/graph/nodes       → كل العقد والحواف
    GET /api/graph/critical    → المسارات الحرجة إلى Crown Jewels
    GET /api/graph/stats       → إحصائيات الرسم البياني
"""

import os
import json
import logging
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc.graph_api")

app = FastAPI(
    title="Khandaq Attack Graph API",
    description="خريطة الهجوم الحية — واجهة Neo4j للـ Dashboard",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Neo4j Connection
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "Ch@ngeMe_Neo4j_2024!")

driver = None
if NEO4J_AVAILABLE:
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
        logger.info("✅ Graph API connected to Neo4j.")
    except Exception as e:
        logger.error(f"❌ Failed to connect to Neo4j: {e}")
        driver = None


# ---------------------------------------------------------------------------
# GET /api/graph/nodes — All nodes and edges for Cytoscape.js
# ---------------------------------------------------------------------------

@app.get("/api/graph/nodes")
def get_graph_nodes(limit: int = 200):
    """
    Returns nodes and edges in Cytoscape.js-compatible format.
    إرجاع العقد والحواف بتنسيق متوافق مع Cytoscape.js
    """
    if not driver:
        raise HTTPException(status_code=503, detail="Neo4j not available.")

    try:
        with driver.session() as session:
            # Fetch nodes
            node_result = session.run(
                "MATCH (n) "
                "RETURN elementId(n) AS id, labels(n) AS labels, properties(n) AS props "
                "LIMIT $limit",
                limit=limit,
            )
            nodes = []
            for record in node_result:
                node_labels = record["labels"]
                props = dict(record["props"])
                node_type = node_labels[0] if node_labels else "Unknown"

                # Determine display label
                if "IP" in node_labels:
                    label = props.get("address", "?")
                elif "User" in node_labels:
                    label = props.get("username", "?")
                elif "Alert" in node_labels:
                    label = props.get("type", "Alert")
                else:
                    label = str(props)

                nodes.append({
                    "data": {
                        "id": record["id"],
                        "label": label,
                        "type": node_type,
                        "is_critical": props.get("is_critical", False),
                        **props,
                    }
                })

            # Fetch edges
            edge_result = session.run(
                "MATCH (a)-[r]->(b) "
                "RETURN elementId(a) AS source, elementId(b) AS target, "
                "       type(r) AS rel_type "
                "LIMIT $limit",
                limit=limit * 2,
            )
            edges = []
            for record in edge_result:
                edges.append({
                    "data": {
                        "source": record["source"],
                        "target": record["target"],
                        "label": record["rel_type"],
                    }
                })

        return {"nodes": nodes, "edges": edges, "total_nodes": len(nodes), "total_edges": len(edges)}
    except Exception as e:
        logger.error(f"Error fetching graph: {e}")
        raise HTTPException(status_code=500, detail=f"Neo4j query failed: {e}")


# ---------------------------------------------------------------------------
# GET /api/graph/critical — Critical paths to Crown Jewels
# ---------------------------------------------------------------------------

@app.get("/api/graph/critical")
def get_critical_paths():
    """
    Find shortest paths from attacker IPs to Crown Jewels.
    اكتشاف أقصر مسار من المهاجمين إلى الأصول الحرجة
    """
    if not driver:
        raise HTTPException(status_code=503, detail="Neo4j not available.")

    try:
        with driver.session() as session:
            result = session.run(
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
                "LIMIT 20"
            )

            paths = []
            for record in result:
                hops = record["hops"]
                paths.append({
                    "attacker_ip": record["attacker_ip"],
                    "crown_jewel": record["crown_jewel"],
                    "hops": hops,
                    "path": record["path_nodes"],
                    "severity": "CRITICAL" if hops <= 2 else "HIGH",
                })

        return {"critical_paths": paths, "total": len(paths)}
    except Exception as e:
        logger.error(f"Error querying critical paths: {e}")
        raise HTTPException(status_code=500, detail=f"Critical path query failed: {e}")


# ---------------------------------------------------------------------------
# GET /api/graph/stats — Graph statistics
# ---------------------------------------------------------------------------

@app.get("/api/graph/stats")
def get_graph_stats():
    """
    Return node/edge counts and Crown Jewel status.
    إحصائيات الرسم البياني: عقد، حواف، أصول حرجة
    """
    if not driver:
        return {"nodes": 0, "edges": 0, "crown_jewels": 0, "attackers": 0, "status": "disconnected"}

    try:
        with driver.session() as session:
            counts = session.run(
                "MATCH (n) WITH count(n) AS nodes "
                "MATCH ()-[r]->() WITH nodes, count(r) AS edges "
                "OPTIONAL MATCH (cj:CrownJewel) WITH nodes, edges, count(cj) AS crown_jewels "
                "OPTIONAL MATCH (a:IP)-[:SOURCE_OF]->() WHERE NOT a:CrownJewel "
                "RETURN nodes, edges, crown_jewels, count(DISTINCT a) AS attackers"
            ).single()

        return {
            "nodes": counts["nodes"] if counts else 0,
            "edges": counts["edges"] if counts else 0,
            "crown_jewels": counts["crown_jewels"] if counts else 0,
            "attackers": counts["attackers"] if counts else 0,
            "status": "connected",
        }
    except Exception as e:
        logger.error(f"Error fetching graph stats: {e}")
        return {"nodes": 0, "edges": 0, "crown_jewels": 0, "attackers": 0, "status": "error"}


if __name__ == "__main__":
    uvicorn.run("graph_api:app", host="0.0.0.0", port=8082, reload=True)
