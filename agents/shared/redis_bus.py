"""
SOC Platform - Redis Message Bus
ناقل الرسائل عبر ريدس

Provides a Redis pub/sub message bus for inter-agent communication:
- Agent → Supervisor reporting
- Supervisor → Commander escalation
- Commander → Broadcast directives
- JSON message serialization with metadata
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import redis

from .config import SOCConfig

logger = logging.getLogger("soc.redis_bus")

# ---------------------------------------------------------------------------
# Standard channel names / أسماء القنوات القياسية
# ---------------------------------------------------------------------------

CHANNEL_AGENT_TO_SUPERVISOR = "soc:agent-to-supervisor"
CHANNEL_SUPERVISOR_TO_COMMANDER = "soc:supervisor-to-commander"
CHANNEL_COMMANDER_BROADCAST = "soc:commander-broadcast"


# ---------------------------------------------------------------------------
# Message Bus / ناقل الرسائل
# ---------------------------------------------------------------------------

class RedisBus:
    """
    Redis-based message bus for SOC agent communication.
    ناقل رسائل مبني على ريدس للتواصل بين الوكلاء

    Supports publishing messages and subscribing to channels with callbacks.
    All messages are JSON-serialized with standard metadata fields.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        """
        Initialize the Redis bus.

        Args:
            config: SOCConfig instance. Falls back to singleton if not provided.
        """
        self._cfg = (config or SOCConfig.get_instance()).redis
        self._client: Optional[redis.Redis] = None
        self._pubsub: Optional[redis.client.PubSub] = None
        self._subscriber_threads: list[threading.Thread] = []
        self._running = True
        self._connect()

    # ------------------------------------------------------------------
    # Connection management / إدارة الاتصال
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        """Establish Redis connection with retry logic."""
        max_retries = 5
        for attempt in range(1, max_retries + 1):
            try:
                kwargs: dict[str, Any] = {
                    "host": self._cfg.host,
                    "port": self._cfg.port,
                    "db": self._cfg.db,
                    "socket_timeout": self._cfg.socket_timeout,
                    "decode_responses": True,
                }
                if self._cfg.password:
                    kwargs["password"] = self._cfg.password

                self._client = redis.Redis(**kwargs)
                self._client.ping()
                logger.info(
                    "Connected to Redis at %s:%d (db=%d)",
                    self._cfg.host, self._cfg.port, self._cfg.db,
                )
                return
            except redis.ConnectionError as exc:
                wait = min(2 ** attempt, 30)
                logger.warning(
                    "Redis connection attempt %d/%d failed: %s — retrying in %ds",
                    attempt, max_retries, exc, wait,
                )
                time.sleep(wait)

        logger.error("Failed to connect to Redis after %d attempts", max_retries)

    @property
    def client(self) -> redis.Redis:
        """Return the underlying Redis client."""
        if self._client is None:
            self._connect()
        assert self._client is not None, "Redis client is not connected"
        return self._client

    # ------------------------------------------------------------------
    # Message formatting / تنسيق الرسائل
    # ------------------------------------------------------------------

    @staticmethod
    def _wrap_message(
        sender: str,
        message_type: str,
        payload: dict[str, Any],
    ) -> str:
        """
        Wrap a payload with standard metadata and serialize to JSON.

        Args:
            sender:       Name of the sending agent.
            message_type: Type of message (e.g. 'alert', 'report', 'heartbeat').
            payload:      The actual message content.

        Returns:
            JSON string.
        """
        envelope = {
            "sender": sender,
            "type": message_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        return json.dumps(envelope, default=str)

    @staticmethod
    def _unwrap_message(raw: str) -> dict[str, Any]:
        """
        Deserialize a JSON message.

        Args:
            raw: JSON string from Redis.

        Returns:
            Parsed message dict.
        """
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("Failed to parse message: %s", exc)
            return {"raw": raw, "parse_error": True}

    # ------------------------------------------------------------------
    # Publish / النشر
    # ------------------------------------------------------------------

    def publish(
        self,
        channel: str,
        payload: dict[str, Any],
        sender: str = "unknown",
        message_type: str = "message",
    ) -> int:
        """
        Publish a message to a Redis channel.

        Args:
            channel:      Target channel name.
            payload:      Message payload dict.
            sender:       Name of the sending agent.
            message_type: Message type tag.

        Returns:
            Number of subscribers that received the message.
        """
        message = self._wrap_message(sender, message_type, payload)
        try:
            count = self.client.publish(channel, message)
            logger.debug(
                "Published to '%s' (type=%s, receivers=%d)", channel, message_type, count
            )
            return count
        except redis.RedisError as exc:
            logger.error("Failed to publish to '%s': %s", channel, exc)
            return 0

    # Convenience publishers for standard channels
    def report_to_supervisor(
        self,
        sender: str,
        payload: dict[str, Any],
        message_type: str = "report",
    ) -> int:
        """Publish to the agent-to-supervisor channel."""
        return self.publish(
            CHANNEL_AGENT_TO_SUPERVISOR, payload, sender, message_type
        )

    def escalate_to_commander(
        self,
        sender: str,
        payload: dict[str, Any],
        message_type: str = "escalation",
    ) -> int:
        """Publish to the supervisor-to-commander channel."""
        return self.publish(
            CHANNEL_SUPERVISOR_TO_COMMANDER, payload, sender, message_type
        )

    def broadcast(
        self,
        sender: str,
        payload: dict[str, Any],
        message_type: str = "directive",
    ) -> int:
        """Publish to the commander broadcast channel."""
        return self.publish(
            CHANNEL_COMMANDER_BROADCAST, payload, sender, message_type
        )

    # ------------------------------------------------------------------
    # Subscribe / الاشتراك
    # ------------------------------------------------------------------

    def subscribe(
        self,
        channel: str,
        callback: Callable[[dict[str, Any]], None],
        daemon: bool = True,
    ) -> threading.Thread:
        """
        Subscribe to a channel and invoke callback for each message.

        The subscriber runs in a background daemon thread.

        Args:
            channel:  Channel name to subscribe to.
            callback: Function called with the parsed message dict.
            daemon:   Whether the thread should be a daemon thread.

        Returns:
            The subscriber thread.
        """
        def _listener() -> None:
            pubsub = None
            while self._running:
                try:
                    if pubsub is None:
                        pubsub = self.client.pubsub()
                        pubsub.subscribe(channel)
                        logger.info("Subscribed to channel '%s'", channel)

                    raw_msg = pubsub.get_message(timeout=1.0)
                    if raw_msg is None:
                        continue
                    if raw_msg["type"] != "message":
                        continue
                    try:
                        parsed = self._unwrap_message(raw_msg["data"])
                        callback(parsed)
                    except Exception as exc:
                        logger.error(
                            "Error in subscriber callback for '%s': %s", channel, exc
                        )
                except redis.ConnectionError as exc:
                    logger.warning("Redis PubSub connection lost on channel '%s': %s. Reconnecting in 5s...", channel, exc)
                    pubsub = None
                    time.sleep(5)
                except Exception as exc:
                    logger.error("Unexpected error in subscriber for '%s': %s", channel, exc)
                    time.sleep(1)

            if pubsub:
                try:
                    pubsub.unsubscribe(channel)
                    pubsub.close()
                except Exception:
                    pass
            logger.info("Unsubscribed from channel '%s'", channel)

        thread = threading.Thread(
            target=_listener,
            name=f"redis-sub-{channel}",
            daemon=daemon,
        )
        thread.start()
        self._subscriber_threads.append(thread)
        return thread

    # ------------------------------------------------------------------
    # Key-Value helpers (for agent state) / مساعدات القيمة-المفتاح
    # ------------------------------------------------------------------

    def set_state(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store a JSON-serializable value with optional TTL."""
        try:
            self.client.set(key, json.dumps(value, default=str), ex=ttl)
        except redis.RedisError as exc:
            logger.error("Failed to set state key '%s': %s", key, exc)

    def get_state(self, key: str) -> Optional[Any]:
        """Retrieve a stored value by key."""
        try:
            raw = self.client.get(key)
            return json.loads(raw) if raw else None
        except (redis.RedisError, json.JSONDecodeError) as exc:
            logger.error("Failed to get state key '%s': %s", key, exc)
            return None

    # ------------------------------------------------------------------
    # Health check / فحص الصحة
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """Check Redis connectivity."""
        try:
            self.client.ping()
            info = self.client.info(section="server")
            return {
                "healthy": True,
                "redis_version": info.get("redis_version", "unknown"),
                "connected_clients": self.client.info(section="clients").get(
                    "connected_clients", 0
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            return {
                "healthy": False,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    # ------------------------------------------------------------------
    # Shutdown / إيقاف التشغيل
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """Gracefully shut down all subscribers and the Redis connection."""
        logger.info("Shutting down Redis bus…")
        self._running = False
        for thread in self._subscriber_threads:
            thread.join(timeout=5)
        if self._client:
            self._client.close()
        logger.info("Redis bus shut down.")

    def __enter__(self) -> RedisBus:
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()
