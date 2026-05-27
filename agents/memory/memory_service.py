"""
SOC Platform - Cyber Memory Engine
Provides semantic search capabilities for historical incidents using Qdrant.
"""

import os
import json
import uuid
import logging
from typing import List, Dict, Any, Optional

try:
    from qdrant_client import QdrantClient
    from qdrant_client.http.models import Distance, VectorParams, PointStruct
    from sentence_transformers import SentenceTransformer
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False

logger = logging.getLogger("soc.memory")

class CyberMemory:
    def __init__(self):
        if not QDRANT_AVAILABLE:
            logger.error("Qdrant Client or SentenceTransformers not installed. Memory Engine disabled.")
            self.enabled = False
            return
            
        self.enabled = True
        self.collection_name = "soc_incidents"
        
        # Initialize Embedding Model
        # Using a small, fast model suitable for CPU/offline usage
        try:
            logger.info("Loading SentenceTransformer model 'all-MiniLM-L6-v2'...")
            self.model = SentenceTransformer("all-MiniLM-L6-v2")
            self.vector_size = self.model.get_sentence_embedding_dimension()
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            self.enabled = False
            return
            
        # Initialize Qdrant Client
        qdrant_host = os.environ.get("QDRANT_HOST", "qdrant")
        qdrant_port = int(os.environ.get("QDRANT_PORT", 6333))
        
        try:
            # Connect to Qdrant
            self.client = QdrantClient(host=qdrant_host, port=qdrant_port)
            
            # Ensure collection exists
            collections = self.client.get_collections()
            collection_names = [c.name for c in collections.collections]
            
            if self.collection_name not in collection_names:
                logger.info(f"Creating new Qdrant collection: {self.collection_name}")
                self.client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(size=self.vector_size, distance=Distance.COSINE),
                )
        except Exception as e:
            logger.error(f"Failed to connect to Qdrant at {qdrant_host}:{qdrant_port}: {e}")
            self.enabled = False

    def embed_text(self, text: str) -> List[float]:
        """Convert text into vector embedding."""
        if not self.enabled or not text:
            return []
        
        # Encode returns a numpy array, convert to list of floats
        embedding = self.model.encode(text)
        return embedding.tolist()

    def store_incident(self, incident_data: Dict[str, Any]) -> bool:
        """Embed and store an incident into Qdrant."""
        if not self.enabled:
            return False
            
        try:
            # Create a rich text representation for embedding
            summary = incident_data.get("incident_summary", "")
            actions = json.dumps(incident_data.get("actions", []))
            text_to_embed = f"Incident Summary: {summary}. Actions Taken: {actions}"
            
            vector = self.embed_text(text_to_embed)
            if not vector:
                return False
                
            point_id = str(uuid.uuid4())
            
            point = PointStruct(
                id=point_id,
                vector=vector,
                payload=incident_data  # Store the full raw JSON as payload
            )
            
            self.client.upsert(
                collection_name=self.collection_name,
                wait=True,
                points=[point]
            )
            logger.info(f"Stored incident {point_id} in Cyber Memory.")
            return True
        except Exception as e:
            logger.error(f"Error storing incident in memory: {e}")
            return False

    def search_similar_incidents(self, query: str, limit: int = 3, score_threshold: float = 0.75) -> List[Dict[str, Any]]:
        """Search for historically similar incidents."""
        if not self.enabled or not query:
            return []
            
        try:
            vector = self.embed_text(query)
            if not vector:
                return []
                
            search_result = self.client.search(
                collection_name=self.collection_name,
                query_vector=vector,
                limit=limit,
                score_threshold=score_threshold
            )
            
            results = []
            for hit in search_result:
                # Add the similarity score to the payload
                hit_payload = hit.payload or {}
                hit_payload["_similarity_score"] = hit.score
                results.append(hit_payload)
                
            return results
        except Exception as e:
            logger.error(f"Error searching Cyber Memory: {e}")
            return []

    # ------------------------------------------------------------------
    # Memory Compression & TTL / ضغط الذاكرة والحذف الزمني
    # ------------------------------------------------------------------

    MAX_COLLECTION_SIZE = 50_000

    def cleanup_old_memories(self, max_age_days: int = 90) -> int:
        """Delete incident vectors older than max_age_days."""
        if not self.enabled:
            return 0
        import time as _time
        cutoff = _time.time() - (max_age_days * 86400)
        try:
            from qdrant_client.http.models import Filter, FieldCondition, Range
            self.client.delete(
                collection_name=self.collection_name,
                points_selector=Filter(must=[
                    FieldCondition(key="stored_at", range=Range(lt=cutoff))
                ]),
            )
            logger.info(f"🧹 Cleanup: removed incidents older than {max_age_days} days.")
            return 1
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
            return 0

    def compress_similar(self, threshold: float = 0.95, batch_size: int = 100) -> int:
        """Merge near-duplicate incidents (cosine > threshold)."""
        if not self.enabled:
            return 0
        try:
            points = self.client.scroll(
                collection_name=self.collection_name, limit=batch_size, with_vectors=True
            )[0]
            if len(points) < 2:
                return 0
            dupes = set()
            for i, pa in enumerate(points):
                if pa.id in dupes:
                    continue
                for pb in points[i + 1:]:
                    if pb.id in dupes:
                        continue
                    va, vb = pa.vector, pb.vector
                    if va and vb:
                        import numpy as np
                        sim = float(np.dot(va, vb)) / (float(np.linalg.norm(va)) * float(np.linalg.norm(vb)) + 1e-9)
                        if sim >= threshold:
                            dupes.add(pb.id)
            if dupes:
                self.client.delete(collection_name=self.collection_name, points_selector=list(dupes))
                logger.info(f"🗜️ Compressed {len(dupes)} near-duplicate incidents.")
            return len(dupes)
        except Exception as e:
            logger.error(f"Compression error: {e}")
            return 0

    def enforce_size_limit(self) -> int:
        """Delete oldest entries if collection exceeds MAX_COLLECTION_SIZE."""
        if not self.enabled:
            return 0
        try:
            info = self.client.get_collection(self.collection_name)
            size = info.points_count or 0
            if size <= self.MAX_COLLECTION_SIZE:
                return 0
            overflow = size - self.MAX_COLLECTION_SIZE
            logger.warning(f"⚠️ Memory overflow: {size} > {self.MAX_COLLECTION_SIZE}. Purging {overflow}.")
            oldest = self.client.scroll(collection_name=self.collection_name, limit=overflow, with_vectors=False)[0]
            ids = [p.id for p in oldest]
            if ids:
                self.client.delete(collection_name=self.collection_name, points_selector=ids)
            return len(ids)
        except Exception as e:
            logger.error(f"Size limit error: {e}")
            return 0



if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mem = CyberMemory()
    if mem.enabled:
        mem.store_incident({
            "incident_summary": "Detected lateral movement via RDP from 10.0.0.50 to 10.0.0.100.",
            "severity": "CRITICAL",
            "actions": [{"type": "isolate_host", "target": "10.0.0.50"}]
        })
        res = mem.search_similar_incidents("RDP lateral movement")
        print("Search Results:", json.dumps(res, indent=2))

