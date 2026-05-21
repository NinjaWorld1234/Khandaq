"""
SOC Platform - Wazuh API Client
عميل واجهة برمجة تطبيقات وازوه

Provides JWT-authenticated access to the Wazuh REST API for:
- Agent management (list, info, restart)
- Alert retrieval with filters
- Active response triggers (block IP, isolate agent)
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from .config import SOCConfig

logger = logging.getLogger("soc.wazuh")

# Wazuh API v4 base paths
_AUTH_PATH = "/security/user/authenticate"
_AGENTS_PATH = "/agents"
_ALERTS_PATH = "/alerts"  # via Wazuh API (limited) or OpenSearch
_ACTIVE_RESPONSE_PATH = "/active-response"


class WazuhClient:
    """
    Wazuh REST API client with JWT authentication and retry logic.
    عميل وازوه مع مصادقة JWT ومنطق إعادة المحاولة
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        """
        Initialize the Wazuh client.

        Args:
            config: SOCConfig instance. Falls back to singleton if not provided.
        """
        self._cfg = (config or SOCConfig.get_instance()).wazuh
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0
        self._http = httpx.Client(
            base_url=self._cfg.url,
            verify=self._cfg.verify_ssl,
            timeout=self._cfg.timeout,
        )

    # ------------------------------------------------------------------
    # Authentication / المصادقة
    # ------------------------------------------------------------------

    def _authenticate(self) -> None:
        """
        Authenticate with Wazuh and obtain a JWT token.
        المصادقة مع وازوه والحصول على رمز JWT
        """
        try:
            resp = self._http.post(
                _AUTH_PATH,
                auth=(self._cfg.username, self._cfg.password),
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("data", {}).get("token", "")
            # Wazuh tokens typically expire in 900s; refresh at 800s
            self._token_expiry = time.time() + 800
            logger.info("Wazuh authentication successful")
        except httpx.HTTPStatusError as exc:
            logger.error("Wazuh authentication failed: HTTP %d", exc.response.status_code)
            raise
        except httpx.RequestError as exc:
            logger.error("Wazuh authentication request error: %s", exc)
            raise

    def _ensure_token(self) -> str:
        """Return a valid JWT token, refreshing if expired."""
        if self._token is None or time.time() >= self._token_expiry:
            self._authenticate()
        assert self._token, "Wazuh JWT token not available"
        return self._token

    def _headers(self) -> dict[str, str]:
        """Return request headers with Authorization."""
        return {
            "Authorization": f"Bearer {self._ensure_token()}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Internal request helpers / دوال الطلبات الداخلية
    # ------------------------------------------------------------------

    def _get(
        self,
        path: str,
        params: Optional[dict[str, Any]] = None,
        max_retries: int = 2,
    ) -> dict[str, Any]:
        """Authenticated GET request with retry on 401."""
        for attempt in range(max_retries + 1):
            try:
                resp = self._http.get(path, headers=self._headers(), params=params)
                if resp.status_code == 401 and attempt < max_retries:
                    logger.warning("Wazuh token expired, re-authenticating…")
                    self._token = None
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.RequestError as exc:
                logger.error("Wazuh GET %s failed: %s", path, exc)
                raise
        return {}

    def _post(
        self,
        path: str,
        json_data: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
        max_retries: int = 2,
    ) -> dict[str, Any]:
        """Authenticated POST request with retry on 401."""
        for attempt in range(max_retries + 1):
            try:
                resp = self._http.post(
                    path,
                    headers=self._headers(),
                    json=json_data,
                    params=params,
                )
                if resp.status_code == 401 and attempt < max_retries:
                    logger.warning("Wazuh token expired, re-authenticating…")
                    self._token = None
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.RequestError as exc:
                logger.error("Wazuh POST %s failed: %s", path, exc)
                raise
        return {}

    def _put(
        self,
        path: str,
        json_data: Optional[dict[str, Any]] = None,
        params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Authenticated PUT request."""
        try:
            resp = self._http.put(
                path,
                headers=self._headers(),
                json=json_data,
                params=params,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.RequestError as exc:
            logger.error("Wazuh PUT %s failed: %s", path, exc)
            raise

    # ------------------------------------------------------------------
    # Agent management / إدارة الوكلاء
    # ------------------------------------------------------------------

    def list_agents(
        self,
        status: Optional[str] = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """
        List registered Wazuh agents.

        Args:
            status: Filter by status (active, disconnected, never_connected).
            limit:  Max results per page.
            offset: Pagination offset.

        Returns:
            List of agent dicts.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        resp = self._get(_AGENTS_PATH, params=params)
        return resp.get("data", {}).get("affected_items", [])

    def get_agent_info(self, agent_id: str) -> dict[str, Any]:
        """
        Get detailed info for a specific Wazuh agent.

        Args:
            agent_id: The agent ID (e.g., '001').

        Returns:
            Agent detail dict.
        """
        resp = self._get(f"{_AGENTS_PATH}", params={"agents_list": agent_id})
        items = resp.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    def restart_agent(self, agent_id: str) -> dict[str, Any]:
        """
        Restart a Wazuh agent.

        Args:
            agent_id: The agent ID to restart.

        Returns:
            API response dict.
        """
        logger.info("Restarting Wazuh agent %s", agent_id)
        return self._put(
            f"{_AGENTS_PATH}/restart",
            params={"agents_list": agent_id},
        )

    # ------------------------------------------------------------------
    # Alert retrieval / استرجاع التنبيهات
    # ------------------------------------------------------------------

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        rule_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        level_min: Optional[int] = None,
        search: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        Get Wazuh alerts with optional filters.

        Note: For large-scale alert queries, prefer querying OpenSearch directly
        on the wazuh-alerts-* index pattern with OpenSearchClient.

        Args:
            limit:     Max results.
            offset:    Pagination offset.
            rule_id:   Filter by rule ID.
            agent_id:  Filter by agent ID.
            level_min: Minimum rule level.
            search:    Full-text search term.

        Returns:
            List of alert dicts.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if rule_id:
            params["rule_id"] = rule_id
        if agent_id:
            params["agent_id"] = agent_id
        if level_min is not None:
            params["min_level"] = level_min
        if search:
            params["search"] = search

        resp = self._get(_ALERTS_PATH, params=params)
        return resp.get("data", {}).get("affected_items", [])

    # ------------------------------------------------------------------
    # Active Response / الاستجابة النشطة
    # ------------------------------------------------------------------

    def trigger_active_response(
        self,
        agent_id: str,
        command: str,
        arguments: Optional[list[str]] = None,
        alert: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Trigger an active response on a Wazuh agent.

        Args:
            agent_id:  Target agent ID.
            command:   Active response command name (e.g. 'firewall-drop').
            arguments: Optional command arguments.
            alert:     Optional alert data to pass along.

        Returns:
            API response dict.
        """
        payload: dict[str, Any] = {"command": command}
        if arguments:
            payload["arguments"] = arguments
        if alert:
            payload["alert"] = alert

        logger.warning(
            "Triggering active response '%s' on agent %s with args=%s",
            command, agent_id, arguments,
        )
        return self._put(
            f"{_ACTIVE_RESPONSE_PATH}",
            json_data=payload,
            params={"agents_list": agent_id},
        )

    def block_ip(self, agent_id: str, ip_address: str) -> dict[str, Any]:
        """
        Block an IP address on a Wazuh agent via active response.
        حظر عنوان IP عبر الاستجابة النشطة

        Args:
            agent_id:   Target agent ID (or 'all' for all agents).
            ip_address: IP address to block.

        Returns:
            API response dict.
        """
        logger.warning("Blocking IP %s on agent %s", ip_address, agent_id)
        return self.trigger_active_response(
            agent_id=agent_id,
            command="firewall-drop",
            arguments=[ip_address, "-", "srcip"],
        )

    def isolate_agent(self, agent_id: str) -> dict[str, Any]:
        """
        Isolate a Wazuh agent (network isolation via active response).
        عزل وكيل وازوه عن الشبكة

        Args:
            agent_id: Agent ID to isolate.

        Returns:
            API response dict.
        """
        logger.warning("Isolating agent %s", agent_id)
        return self.trigger_active_response(
            agent_id=agent_id,
            command="netsh",
            arguments=["advfirewall", "set", "allprofiles", "firewallpolicy",
                        "blockinbound,blockoutbound"],
        )

    # ------------------------------------------------------------------
    # Manager status / حالة المدير
    # ------------------------------------------------------------------

    def get_manager_status(self) -> dict[str, Any]:
        """
        Get the Wazuh manager daemon status.

        Returns:
            Dict of daemon name → status.
        """
        try:
            resp = self._get("/manager/status")
            return resp.get("data", {}).get("affected_items", [{}])[0]
        except Exception as exc:
            logger.error("Failed to get Wazuh manager status: %s", exc)
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # Health check / فحص الصحة
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """
        Quick health check for the Wazuh API.

        Returns:
            Dict with 'healthy' bool and status info.
        """
        try:
            status = self.get_manager_status()
            is_healthy = status.get("wazuh-modulesd", "") == "running"
            return {
                "healthy": is_healthy,
                "daemons": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {
                "healthy": False,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    # ------------------------------------------------------------------
    # Cleanup / التنظيف
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the HTTP client."""
        self._http.close()

    def __enter__(self) -> WazuhClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
