"""
SOC Platform - OpenSearch Client Wrapper
عميل أوبن سيرش لمنصة مركز العمليات الأمنية

Provides connection with retry logic, query/index helpers,
event retrieval by time window, field statistics, and health checks.
"""

from __future__ import annotations

import logging
import time
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from opensearchpy import OpenSearch, helpers as os_helpers
from opensearchpy.exceptions import (
    ConnectionError as OSConnectionError,
    ConnectionTimeout,
    TransportError,
)

from .config import SOCConfig

logger = logging.getLogger("soc.opensearch")


class OpenSearchClient:
    """
    Thread-safe OpenSearch client wrapper with retry logic and helper methods.
    عميل أوبن سيرش مع منطق إعادة المحاولة ودوال مساعدة
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        """
        Initialize the OpenSearch client.

        Args:
            config: SOCConfig instance. Falls back to singleton if not provided.
        """
        self._cfg = (config or SOCConfig.get_instance()).opensearch
        self._client: Optional[OpenSearch] = None
        self._conn_lock = threading.Lock()
        self._connect()

    # ------------------------------------------------------------------
    # Connection management / إدارة الاتصال
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        """Create the OpenSearch client with retry logic."""
        max_attempts = self._cfg.max_retries + 1
        for attempt in range(1, max_attempts + 1):
            try:
                self._client = OpenSearch(
                    hosts=self._cfg.hosts,
                    http_auth=(self._cfg.username, self._cfg.password),
                    use_ssl=any(h.startswith("https") for h in self._cfg.hosts),
                    verify_certs=self._cfg.verify_certs,
                    ssl_show_warn=self._cfg.ssl_show_warn,
                    timeout=self._cfg.timeout,
                    max_retries=self._cfg.max_retries,
                    retry_on_timeout=self._cfg.retry_on_timeout,
                )
                # Quick connectivity test
                info = self._client.info()
                logger.info(
                    "Connected to OpenSearch cluster '%s' (v%s)",
                    info.get("cluster_name", "unknown"),
                    info.get("version", {}).get("number", "?"),
                )
                return
            except (OSConnectionError, ConnectionTimeout, TransportError) as exc:
                wait = min(2 ** attempt, 30)
                logger.warning(
                    "OpenSearch connection attempt %d/%d failed: %s — retrying in %ds",
                    attempt, max_attempts, exc, wait,
                )
                time.sleep(wait)
        logger.error("Failed to connect to OpenSearch after %d attempts", max_attempts)

    @property
    def client(self) -> OpenSearch:
        """Return the underlying OpenSearch client."""
        if self._client is None:
            with self._conn_lock:
                if self._client is None:
                    self._connect()
        assert self._client is not None, "OpenSearch client is not connected"
        return self._client

    # ------------------------------------------------------------------
    # Query helpers / دوال الاستعلام المساعدة
    # ------------------------------------------------------------------

    def search(
        self,
        index: str,
        body: dict[str, Any],
        size: int = 100,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Execute a search query and return the full response.

        Args:
            index: Index pattern (e.g. "wazuh-alerts-*").
            body:  OpenSearch query DSL body.
            size:  Max documents to return.

        Returns:
            Full OpenSearch response dict.
        """
        try:
            return self.client.search(index=index, body=body, size=size, **kwargs)
        except (OSConnectionError, TransportError) as exc:
            logger.error("Search failed on index '%s': %s", index, exc)
            raise

    def aggregate(
        self,
        index: str,
        aggs: dict[str, Any],
        query: Optional[dict[str, Any]] = None,
        size: int = 0,
    ) -> dict[str, Any]:
        """
        Run an aggregation query. Returns the 'aggregations' section.

        Args:
            index: Index pattern.
            aggs:  Aggregation DSL.
            query: Optional filter query.
            size:  Set to 0 to skip hits (aggregation only).

        Returns:
            The 'aggregations' dict from the response.
        """
        body: dict[str, Any] = {"aggs": aggs, "size": size}
        if query:
            body["query"] = query
        resp = self.search(index, body, size=size)
        return resp.get("aggregations", {})

    def count(self, index: str, query: Optional[dict[str, Any]] = None) -> int:
        """
        Count documents matching a query.

        Args:
            index: Index pattern.
            query: Optional query DSL.

        Returns:
            Document count.
        """
        body = {"query": query} if query else {}
        try:
            resp = self.client.count(index=index, body=body)
            return resp.get("count", 0)
        except (OSConnectionError, TransportError) as exc:
            logger.error("Count failed on index '%s': %s", index, exc)
            raise

    # ------------------------------------------------------------------
    # Index helpers / دوال الفهرسة المساعدة
    # ------------------------------------------------------------------

    def index_document(
        self,
        index: str,
        document: dict[str, Any],
        doc_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Index a single document.

        Args:
            index:    Target index name.
            document: Document body.
            doc_id:   Optional document ID.

        Returns:
            OpenSearch index response.
        """
        try:
            return self.client.index(index=index, body=document, id=doc_id)
        except (OSConnectionError, TransportError) as exc:
            logger.error("Index document failed on '%s': %s", index, exc)
            raise

    def bulk_index(
        self,
        index: str,
        documents: list[dict[str, Any]],
    ) -> tuple[int, list[Any]]:
        """
        Bulk-index a list of documents.

        Args:
            index:     Target index name.
            documents: List of document bodies.

        Returns:
            Tuple of (success_count, error_list).
        """
        actions = [
            {"_index": index, "_source": doc}
            for doc in documents
        ]
        try:
            success, errors = os_helpers.bulk(self.client, actions, raise_on_error=False)
            if errors:
                logger.warning("Bulk index had %d errors on '%s'", len(errors), index)
            return success, errors
        except (OSConnectionError, TransportError) as exc:
            logger.error("Bulk index failed on '%s': %s", index, exc)
            raise

    # ------------------------------------------------------------------
    # Convenience queries / استعلامات مريحة
    # ------------------------------------------------------------------

    def get_events_since(
        self,
        index: str,
        minutes: int,
        query: Optional[dict[str, Any]] = None,
        size: int = 1000,
        timestamp_field: str = "@timestamp",
    ) -> list[dict[str, Any]]:
        """
        Retrieve events from the last N minutes.

        Args:
            index:           Index pattern.
            minutes:         Look-back window in minutes.
            query:           Additional query filter (combined via bool/must).
            size:            Max documents to return.
            timestamp_field: Name of the timestamp field.

        Returns:
            List of _source dicts.
        """
        time_filter: dict[str, Any] = {
            "range": {
                timestamp_field: {
                    "gte": f"now-{minutes}m",
                    "lte": "now",
                }
            }
        }
        must_clauses = [time_filter]
        if query:
            must_clauses.append(query)

        body: dict[str, Any] = {
            "query": {"bool": {"must": must_clauses}},
            "sort": [{timestamp_field: {"order": "desc"}}],
        }
        resp = self.search(index, body, size=size)
        return [hit.get("_source", {}) for hit in resp.get("hits", {}).get("hits", [])]

    def get_field_stats(
        self,
        index: str,
        field: str,
        minutes: int,
        timestamp_field: str = "@timestamp",
    ) -> dict[str, Any]:
        """
        Get min/max/avg/sum/count statistics for a numeric field over last N minutes.

        Args:
            index:           Index pattern.
            field:           Numeric field to aggregate.
            minutes:         Look-back window in minutes.
            timestamp_field: Name of the timestamp field.

        Returns:
            Dict with min, max, avg, sum, count.
        """
        query: dict[str, Any] = {
            "range": {
                timestamp_field: {
                    "gte": f"now-{minutes}m",
                    "lte": "now",
                }
            }
        }
        aggs: dict[str, Any] = {
            "stats": {"extended_stats": {"field": field}}
        }
        result = self.aggregate(index, aggs, query=query)
        stats = result.get("stats", {})
        return {
            "count": stats.get("count", 0),
            "min": stats.get("min"),
            "max": stats.get("max"),
            "avg": stats.get("avg"),
            "sum": stats.get("sum"),
            "std_deviation": stats.get("std_deviation"),
        }

    # ------------------------------------------------------------------
    # Health check / فحص الصحة
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """
        Check cluster health status.
        فحص حالة صحة مجموعة أوبن سيرش

        Returns:
            Dict with cluster_name, status, number_of_nodes, etc.
        """
        try:
            health = self.client.cluster.health()
            return {
                "healthy": health.get("status") in ("green", "yellow"),
                "status": health.get("status", "unknown"),
                "cluster_name": health.get("cluster_name", "unknown"),
                "number_of_nodes": health.get("number_of_nodes", 0),
                "active_shards": health.get("active_shards", 0),
                "unassigned_shards": health.get("unassigned_shards", 0),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            logger.error("OpenSearch health check failed: %s", exc)
            return {
                "healthy": False,
                "status": "unreachable",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
