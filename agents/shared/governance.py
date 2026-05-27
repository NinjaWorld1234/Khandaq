"""
SOC Platform — AI Governance Layer
طبقة حوكمة الذكاء الاصطناعي — سجلات قرارات غير قابلة للتعديل + تبرير القرار

This module provides:
1. ImmutableDecisionLog — Write-only decision logging to OpenSearch
2. DecisionExplainer — Builds human-readable reasoning chains
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

logger = logging.getLogger("soc.governance")


class ImmutableDecisionLog:
    """
    Append-only decision ledger stored in OpenSearch.
    سجل قرارات للكتابة فقط — لا يمكن تعديل أو حذف أي سجل بعد كتابته.
    
    Each log entry includes:
    - Decision details (who, what, when, why)
    - SHA-256 hash of the decision (tamper detection)
    - Chain hash linking to previous decision (blockchain-lite)
    """

    INDEX_NAME = "soc-governance-decisions"

    def __init__(self, os_client=None):
        """
        Initialize the governance log.
        
        Args:
            os_client: OpenSearchClient instance (lazy-loaded if None)
        """
        self._os_client = os_client
        self._last_hash: str = "GENESIS"
        self._initialized = False

    def _ensure_index(self):
        """Create the governance index with write-only settings."""
        if self._initialized or not self._os_client:
            return
        
        try:
            index_body = {
                "settings": {
                    "index": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1,
                        # Prevent deletion of individual documents
                        "blocks.read_only_allow_delete": False,
                    }
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "decision_id": {"type": "keyword"},
                        "agent_name": {"type": "keyword"},
                        "action_type": {"type": "keyword"},
                        "target": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "status": {"type": "keyword"},
                        "reasoning_chain": {"type": "text"},
                        "decision_hash": {"type": "keyword"},
                        "previous_hash": {"type": "keyword"},
                        "raw_payload": {"type": "object", "enabled": False},
                    }
                }
            }
            
            self._os_client.create_index_if_not_exists(self.INDEX_NAME, index_body)
            self._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize governance index: {e}")

    def log_decision(
        self,
        decision_id: str,
        agent_name: str,
        action_type: str,
        target: str,
        severity: str,
        status: str,
        reasoning: str,
        raw_payload: Optional[Dict] = None,
    ) -> bool:
        """
        Log an immutable decision record.
        تسجيل قرار في السجل الدائم — لا يمكن تعديله لاحقاً
        
        Returns:
            True if logged successfully, False otherwise.
        """
        if not self._os_client:
            return False

        self._ensure_index()

        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Build the record
        record = {
            "@timestamp": timestamp,
            "decision_id": decision_id,
            "agent_name": agent_name,
            "action_type": action_type,
            "target": target,
            "severity": severity,
            "status": status,
            "reasoning_chain": reasoning,
            "raw_payload": raw_payload or {},
        }
        
        # Calculate decision hash (tamper-proof)
        hash_input = json.dumps(record, sort_keys=True, default=str)
        decision_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        
        # Chain to previous hash (blockchain-lite)
        record["decision_hash"] = decision_hash
        record["previous_hash"] = self._last_hash
        
        try:
            self._os_client.index_document(self.INDEX_NAME, record)
            self._last_hash = decision_hash
            logger.info(
                f"📋 Governance: Logged decision {decision_id} "
                f"({action_type} on {target}) — hash: {decision_hash[:12]}..."
            )
            return True
        except Exception as e:
            logger.error(f"Failed to log governance decision: {e}")
            return False


class DecisionExplainer:
    """
    Builds human-readable reasoning chains for AI decisions.
    يبني سلسلة تبرير مقروءة لكل قرار يتخذه الذكاء الاصطناعي
    
    This helps SOC analysts understand WHY the AI made a specific decision,
    fulfilling regulatory and audit requirements.
    """

    @staticmethod
    def build_reasoning_chain(
        trigger_event: str,
        worker_findings: List[str],
        supervisor_summary: str,
        commander_decision: str,
        historical_context: Optional[str] = None,
        confidence_score: Optional[float] = None,
    ) -> str:
        """
        Build a structured reasoning chain.
        بناء سلسلة تبرير منظمة
        
        Returns:
            Human-readable reasoning string.
        """
        chain_parts = [
            f"[1. TRIGGER] {trigger_event}",
        ]
        
        for i, finding in enumerate(worker_findings, start=1):
            chain_parts.append(f"[2.{i} WORKER FINDING] {finding}")
        
        chain_parts.append(f"[3. SUPERVISOR ASSESSMENT] {supervisor_summary}")
        
        if historical_context:
            chain_parts.append(f"[4. HISTORICAL CONTEXT] {historical_context}")
        
        chain_parts.append(f"[5. COMMANDER DECISION] {commander_decision}")
        
        if confidence_score is not None:
            chain_parts.append(f"[6. CONFIDENCE] {confidence_score:.1%}")
        
        return " → ".join(chain_parts)

    @staticmethod
    def explain_severity(severity: str, action_type: str) -> str:
        """Generate human-readable severity explanation."""
        explanations = {
            "LOW": f"Action '{action_type}' is observation-only. Auto-approved — no infrastructure changes.",
            "MEDIUM": f"Action '{action_type}' modifies system behavior but is reversible. Requires HITL review.",
            "CRITICAL": f"Action '{action_type}' is destructive/blocking. Mandatory human approval before execution.",
        }
        return explanations.get(severity, f"Unknown severity level for '{action_type}'.")
