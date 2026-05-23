"""
SOC Platform - SecureBERT Client
عميل سيكيور بيرت للتحليل الأمني السريع

Provides fast, local NLP capabilities for cybersecurity logs:
- Generates vector embeddings for RAG and similarity search.
- Performs fast classification and entity extraction.
"""

import logging
from typing import Any, List, Optional
import os

try:
    from sentence_transformers import SentenceTransformer
    import torch
    HAS_ML = True
except ImportError:
    HAS_ML = False

logger = logging.getLogger("soc.securebert")

class SecureBERTClient:
    """
    Client for SecureBERT (or similar encoder models).
    عميل لنموذج SecureBERT للفلترة السريعة
    """

    _instance: Optional['SecureBERTClient'] = None

    def __init__(self, model_path: str = "/app/models/securebert"):
        """Initialize the model from a local offline directory."""
        self.model_path = model_path
        self.model = None
        self.device = "cuda" if HAS_ML and torch.cuda.is_available() else "cpu"
        
        if HAS_ML:
            logger.info(f"Loading local model from {model_path} on {self.device}...")
            if not os.path.exists(model_path):
                logger.error(f"Offline model path does not exist: {model_path}. Please run download script first.")
            else:
                try:
                    self.model = SentenceTransformer(model_path, device=self.device)
                    logger.info("Successfully loaded offline SecureBERT.")
                except Exception as e:
                    logger.error(f"Failed to load local model: {e}")
        else:
            logger.warning("ML libraries (sentence-transformers, torch) not found. SecureBERT disabled.")

    @classmethod
    def get_instance(cls) -> 'SecureBERTClient':
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_embedding(self, text: str) -> List[float]:
        """
        Generate a vector embedding for the given text.
        توليد متجه رياضي للنص للبحث الدلالي
        """
        if not self.model:
            return []
        
        try:
            # Generate embedding and convert to list of floats
            embedding = self.model.encode(text, convert_to_numpy=True)
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            return []

    def compute_similarity(self, text1: str, text2: str) -> float:
        """
        Compute cosine similarity between two texts.
        حساب نسبة التطابق الدلالي بين نصين
        """
        if not HAS_ML or not self.model:
            return 0.0
            
        from sentence_transformers import util
        
        emb1 = self.model.encode(text1, convert_to_tensor=True)
        emb2 = self.model.encode(text2, convert_to_tensor=True)
        
        cosine_score = util.cos_sim(emb1, emb2)
        return float(cosine_score[0][0])

    def classify_severity_fast(self, log_text: str) -> str:
        """
        A fast heuristic classification based on semantic similarity to known attack patterns.
        تصنيف سريع للخطورة بناءً على التطابق الدلالي مع أنماط الهجوم المعروفة
        """
        if not self.model:
            return "UNKNOWN"
            
        # Very simple zero-shot heuristic for demonstration:
        # In a real SOC, we would train a classification head on top of SecureBERT.
        critical_patterns = [
            "ransomware encryption process",
            "reverse shell connection established",
            "domain controller compromise DCSync",
            "clear text credentials dumped from memory lsass"
        ]
        
        benign_patterns = [
            "normal user login success",
            "background service started",
            "network connection closed gracefully",
            "system health check ok"
        ]
        
        try:
            log_emb = self.model.encode(log_text, convert_to_tensor=True)
            crit_embs = self.model.encode(critical_patterns, convert_to_tensor=True)
            benign_embs = self.model.encode(benign_patterns, convert_to_tensor=True)
            
            from sentence_transformers import util
            crit_scores = util.cos_sim(log_emb, crit_embs)
            benign_scores = util.cos_sim(log_emb, benign_embs)
            
            max_crit = float(torch.max(crit_scores))
            max_benign = float(torch.max(benign_scores))
            
            if max_crit > 0.7 and max_crit > max_benign:
                return "CRITICAL"
            elif max_crit > 0.5:
                return "HIGH"
            elif max_benign > 0.6:
                return "LOW"
            else:
                return "MEDIUM"
                
        except Exception as e:
            logger.error(f"Fast classification failed: {e}")
            return "MEDIUM"

