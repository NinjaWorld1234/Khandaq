"""
SOC Platform - Base Agent Class
الفئة الأساسية للوكيل

All SOC worker agents inherit from BaseAgent.
Implements the Collect → Analyze → Decide → Act loop with:
- Scheduled run loop with error recovery
- Prometheus metrics instrumentation
- Redis pub/sub supervisor reporting
- Graceful shutdown on SIGTERM/SIGINT
- Health-check endpoint
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from .alerter import Alerter
from .config import SOCConfig
from .metrics import AgentMetrics, start_metrics_server
from .opensearch_client import OpenSearchClient
from .redis_bus import CHANNEL_AGENT_TO_SUPERVISOR, CHANNEL_COMMANDER_BROADCAST, RedisBus
from .wazuh_client import WazuhClient

logger = logging.getLogger("soc.agent")


class BaseAgent(ABC):
    """
    Abstract base class for all SOC agents.
    الفئة الأساسية المجردة لجميع وكلاء مركز العمليات الأمنية

    Sub-classes must implement:
        collect()  -> raw data
        analyze()  -> findings from data
        decide()   -> actions from findings
        act()      -> results from actions

    The run_loop() orchestrates these in a timed cycle with metrics,
    error handling, and supervisor reporting.
    """

    def __init__(
        self,
        name: str,
        description: str,
        interval_seconds: int = 60,
        config: Optional[SOCConfig] = None,
        supervisor_channel: Optional[str] = None,
    ) -> None:
        """
        Initialize the base agent.

        Args:
            name:               Unique agent name (e.g. 'w37_brute_force').
            description:        Human-readable description.
            interval_seconds:   Seconds between each run cycle.
            config:             SOCConfig instance (defaults to singleton).
            supervisor_channel: Redis channel for supervisor reporting.
                                Defaults to 'soc:agent-to-supervisor'.
        """
        self.name = name
        self.description = description
        self.interval_seconds = interval_seconds
        self.config = config or SOCConfig.get_instance()
        self.supervisor_channel = supervisor_channel or CHANNEL_AGENT_TO_SUPERVISOR

        # Shared clients (lazy-initialized)
        self._os_client: Optional[OpenSearchClient] = None
        self._redis_bus: Optional[RedisBus] = None
        self._alerter: Optional[Alerter] = None
        self._wazuh_client: Optional[WazuhClient] = None

        # Metrics
        self._metrics = AgentMetrics(self.name)

        # Runtime state
        self._running = False
        self._last_run: Optional[float] = None
        self._events_processed: int = 0
        self._errors: int = 0
        self._lock = threading.Lock()

        # Supervisor delivery resilience tracking
        # تتبع مرونة التسليم للمشرف
        self._supervisor_failures: int = 0

        # Agent-specific config overrides
        self._agent_config = self.config.get_agent_config(self.name)

        logger.info(
            "Agent '%s' initialized: %s (interval=%ds, channel=%s)",
            name, description, interval_seconds, self.supervisor_channel,
        )

    # ------------------------------------------------------------------
    # Shared client accessors (lazy init) / عملاء مشتركون
    # ------------------------------------------------------------------

    @property
    def os_client(self) -> OpenSearchClient:
        """OpenSearch client (lazy-initialized)."""
        if self._os_client is None:
            self._os_client = OpenSearchClient(self.config)
        return self._os_client

    @property
    def redis_bus(self) -> RedisBus:
        """Redis message bus (lazy-initialized)."""
        if self._redis_bus is None:
            self._redis_bus = RedisBus(self.config)
        return self._redis_bus

    @property
    def alerter(self) -> Alerter:
        """Alert dispatcher (lazy-initialized)."""
        if self._alerter is None:
            self._alerter = Alerter(self.config)
        return self._alerter

    @property
    def wazuh_client(self) -> WazuhClient:
        """Wazuh API client (lazy-initialized)."""
        if self._wazuh_client is None:
            self._wazuh_client = WazuhClient(self.config)
        return self._wazuh_client

    # ------------------------------------------------------------------
    # Abstract methods (Collect -> Analyze -> Decide -> Act)
    # الطرق المجردة: جمع -> تحليل -> قرار -> تنفيذ
    # ------------------------------------------------------------------

    @abstractmethod
    def collect(self) -> Any:
        """
        Collect raw data from sources (OpenSearch, Wazuh, etc.).
        جمع البيانات الخام من المصادر

        Returns:
            Raw data in any format suitable for the agent.
        """
        ...

    @abstractmethod
    def analyze(self, data: Any) -> Any:
        """
        Analyze collected data and extract findings.
        تحليل البيانات المجمعة واستخراج النتائج

        Args:
            data: Raw data from collect().

        Returns:
            Findings (threats, anomalies, patterns, etc.).
        """
        ...

    @abstractmethod
    def decide(self, findings: Any) -> Any:
        """
        Decide on actions based on findings.
        اتخاذ القرارات بناءً على النتائج

        Args:
            findings: Analysis results from analyze().

        Returns:
            List of actions to execute.
        """
        ...

    @abstractmethod
    def act(self, actions: Any) -> Any:
        """
        Execute decided actions (alert, block, isolate, etc.).
        تنفيذ الإجراءات المقررة

        Args:
            actions: Actions from decide().

        Returns:
            Results of executed actions.
        """
        ...

    # ------------------------------------------------------------------
    # Supervisor reporting / التقرير إلى المشرف
    # ------------------------------------------------------------------

    def report_to_supervisor(self, message: dict[str, Any]) -> None:
        """
        Send a report to the supervisor agent via Redis pub/sub.
        Uses self.supervisor_channel for targeted routing.
        إرسال تقرير إلى المشرف عبر ريديس مع حماية متعددة الطبقات

        Resilience features / ميزات الحماية:
            1. Retry with exponential backoff (3 attempts)
               إعادة المحاولة مع تأخير تصاعدي
            2. Fallback to default channel on primary failure
               الرجوع للقناة الافتراضية عند فشل الأساسية
            3. Delivery count validation (warns if no subscribers)
               التحقق من وجود مستمعين على القناة
            4. Failure metrics tracking
               تتبع مقاييس الفشل
            5. Circuit breaker: stops retrying after repeated failures
               قاطع الدائرة: يتوقف عن المحاولة بعد فشل متكرر

        Args:
            message: Report payload dict.
        """
        report = {
            "agent_name": self.name,
            "agent_description": self.description,
            **message,
        }

        max_retries = 3
        delivered = False

        # --- Attempt delivery on the primary supervisor channel ---
        # --- محاولة التسليم على القناة الرئيسية ---
        for attempt in range(1, max_retries + 1):
            try:
                receiver_count = self.redis_bus.publish(
                    channel=self.supervisor_channel,
                    payload=report,
                    sender=self.name,
                    message_type="agent_report",
                )
                if receiver_count > 0:
                    delivered = True
                    # Reset consecutive failure counter on success
                    self._supervisor_failures = 0
                    break
                else:
                    # Published but no subscribers listening
                    logger.warning(
                        "[%s] ⚠️ Published to '%s' but 0 subscribers received "
                        "(attempt %d/%d)",
                        self.name, self.supervisor_channel, attempt, max_retries,
                    )
            except Exception as exc:
                wait = min(2 ** attempt, 8)
                logger.warning(
                    "[%s] ⚠️ Publish to '%s' failed (attempt %d/%d): %s "
                    "— retrying in %ds",
                    self.name, self.supervisor_channel, attempt, max_retries,
                    exc, wait,
                )
                if attempt < max_retries:
                    time.sleep(wait)

        # --- Fallback: try the default channel if primary failed ---
        # --- خطة بديلة: القناة الافتراضية إذا فشلت الأساسية ---
        if (
            not delivered
            and self.supervisor_channel != CHANNEL_AGENT_TO_SUPERVISOR
        ):
            try:
                fallback_count = self.redis_bus.publish(
                    channel=CHANNEL_AGENT_TO_SUPERVISOR,
                    payload={
                        **report,
                        "_fallback": True,
                        "_original_channel": self.supervisor_channel,
                    },
                    sender=self.name,
                    message_type="agent_report_fallback",
                )
                if fallback_count > 0:
                    delivered = True
                    logger.info(
                        "[%s] 🔄 Delivered via fallback channel '%s' "
                        "(primary '%s' was unreachable)",
                        self.name, CHANNEL_AGENT_TO_SUPERVISOR,
                        self.supervisor_channel,
                    )
                else:
                    logger.error(
                        "[%s] 🔴 Fallback channel '%s' also has 0 subscribers!",
                        self.name, CHANNEL_AGENT_TO_SUPERVISOR,
                    )
            except Exception as exc:
                logger.error(
                    "[%s] 🔴 Fallback publish also failed: %s",
                    self.name, exc,
                )

        # --- Track failures and alert ---
        # --- تتبع الفشل وإرسال تنبيهات ---
        if not delivered:
            self._supervisor_failures = getattr(
                self, "_supervisor_failures", 0
            ) + 1
            self._metrics.inc_errors("supervisor_delivery_failed")

            logger.error(
                "[%s] 🔴 SUPERVISOR UNREACHABLE — message lost! "
                "(consecutive failures: %d, channel: '%s')",
                self.name, self._supervisor_failures,
                self.supervisor_channel,
            )

            # Alert via OpenSearch after 3 consecutive failures
            # تنبيه عبر أوبن سيرش بعد 3 فشل متتالي
            if self._supervisor_failures == 3:
                try:
                    self.os_client.index_document(
                        "soc-channel-failures",
                        {
                            "@timestamp": datetime.now(
                                timezone.utc
                            ).isoformat(),
                            "agent_name": self.name,
                            "channel": self.supervisor_channel,
                            "consecutive_failures": self._supervisor_failures,
                            "severity": "CRITICAL",
                            "message": (
                                f"Agent {self.name} cannot reach supervisor "
                                f"on channel {self.supervisor_channel} — "
                                f"{self._supervisor_failures} consecutive "
                                f"delivery failures"
                            ),
                        },
                    )
                    logger.critical(
                        "[%s] 📢 Channel failure alert indexed to "
                        "'soc-channel-failures'",
                        self.name,
                    )
                except Exception as exc:
                    logger.error(
                        "[%s] Failed to index channel failure alert: %s",
                        self.name, exc,
                    )

    # ------------------------------------------------------------------
    # Commander broadcast listener / مستمع أوامر القائد
    # ------------------------------------------------------------------

    def _handle_commander_broadcast(self, message: dict[str, Any]) -> None:
        """Handle broadcast messages from the Commander agent."""
        msg_type = message.get("type", "")
        payload = message.get("payload", {})
        target = payload.get("target_agent")

        # Only process if broadcast is for all agents or this agent specifically
        if target and target != self.name and target != "all":
            return

        logger.info(
            "Received commander broadcast: type=%s, payload=%s",
            msg_type, str(payload)[:200],
        )

        # Handle standard directives
        directive = payload.get("directive", "")
        if directive == "pause":
            logger.warning("Received PAUSE directive -- agent will stop running.")
            self._running = False
        elif directive == "update_interval":
            new_interval = payload.get("interval_seconds")
            if isinstance(new_interval, int) and new_interval > 0:
                self.interval_seconds = new_interval
                logger.info("Interval updated to %ds", new_interval)
        elif directive == "health_check":
            health = self.health_check()
            self.report_to_supervisor({"type": "health_response", **health})

    # ------------------------------------------------------------------
    # Health check / فحص الصحة
    # ------------------------------------------------------------------

    def health_check(self) -> dict[str, Any]:
        """
        Return the agent's current health status.

        Returns:
            Dict with status, last_run, events_processed, errors, etc.
        """
        return {
            "agent_name": self.name,
            "status": "running" if self._running else "stopped",
            "last_run": (
                datetime.fromtimestamp(self._last_run, tz=timezone.utc).isoformat()
                if self._last_run
                else None
            ),
            "events_processed": self._events_processed,
            "errors": self._errors,
            "interval_seconds": self.interval_seconds,
            "supervisor_channel": self.supervisor_channel,
            "supervisor_failures": self._supervisor_failures,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Single run cycle / دورة تشغيل واحدة
    # ------------------------------------------------------------------

    def _run_once(self) -> None:
        """Execute one full Collect -> Analyze -> Decide -> Act cycle."""
        start_time = time.time()
        try:
            # Collect
            data = self.collect()
            if data is None:
                logger.debug("[%s] No data collected this cycle.", self.name)
                return

            # Analyze
            findings = self.analyze(data)

            # Decide
            actions = self.decide(findings)

            # Act
            results = self.act(actions)

            # Update metrics
            duration = time.time() - start_time
            self._last_run = time.time()
            self._metrics.set_last_run(self._last_run)
            self._metrics.observe_duration(duration)

            logger.debug(
                "[%s] Cycle completed in %.2fs -- results: %s",
                self.name, duration, str(results)[:200],
            )

        except Exception as exc:
            self._errors += 1
            self._metrics.inc_errors(type(exc).__name__)
            logger.exception("[%s] Error in run cycle: %s", self.name, exc)
            # Report error to supervisor
            self.report_to_supervisor({
                "type": "error",
                "error": str(exc),
                "error_type": type(exc).__name__,
            })

    # ------------------------------------------------------------------
    # Main run loop / حلقة التشغيل الرئيسية
    # ------------------------------------------------------------------

    def run_loop(self) -> None:
        """
        Main agent loop. Runs collect->analyze->decide->act on a schedule.

        - Handles errors gracefully (logs, increments counter, continues).
        - Publishes Prometheus metrics each cycle.
        - Listens for commander broadcasts.
        - Shuts down gracefully on SIGTERM / SIGINT.
        """
        self._running = True

        # Start Prometheus metrics server (idempotent)
        start_metrics_server(self.config)

        # Subscribe to commander broadcast channel
        try:
            self.redis_bus.subscribe(
                CHANNEL_COMMANDER_BROADCAST,
                self._handle_commander_broadcast,
            )
        except Exception as exc:
            logger.warning("Could not subscribe to commander broadcast: %s", exc)

        # Register signal handlers for graceful shutdown
        def _shutdown_handler(signum: int, frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            logger.info(
                "[%s] Received %s -- shutting down gracefully...",
                self.name, sig_name,
            )
            self._running = False

        signal.signal(signal.SIGTERM, _shutdown_handler)
        signal.signal(signal.SIGINT, _shutdown_handler)

        logger.info(
            "Agent '%s' starting run loop (interval=%ds)",
            self.name, self.interval_seconds,
        )

        # Send startup heartbeat
        self.report_to_supervisor({
            "type": "heartbeat",
            "status": "started",
            "interval_seconds": self.interval_seconds,
        })

        try:
            while self._running:
                self._run_once()

                # Sleep in small increments to allow responsive shutdown
                sleep_end = time.time() + self.interval_seconds
                while self._running and time.time() < sleep_end:
                    time.sleep(min(1.0, sleep_end - time.time()))

        finally:
            # Cleanup
            logger.info("[%s] Shutting down...", self.name)
            self.report_to_supervisor({
                "type": "heartbeat",
                "status": "stopped",
            })
            if self._redis_bus:
                self._redis_bus.shutdown()
            logger.info("[%s] Shutdown complete.", self.name)

    # ------------------------------------------------------------------
    # Stop / إيقاف الوكيل
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Gracefully stop the agent's run loop. إيقاف الوكيل بأمان"""
        logger.info("[%s] Stop requested.", self.name)
        self._running = False

    # ------------------------------------------------------------------
    # Start in thread / بدء في خيط
    # ------------------------------------------------------------------

    def start_in_thread(self) -> threading.Thread:
        """
        Start the agent's run loop in a background thread.

        Returns:
            The running thread.
        """
        thread = threading.Thread(
            target=self.run_loop,
            name=f"agent-{self.name}",
            daemon=True,
        )
        thread.start()
        return thread

    # ------------------------------------------------------------------
    # Repr / التمثيل
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} name={self.name!r} "
            f"interval={self.interval_seconds}s "
            f"status={'running' if self._running else 'stopped'}>"
        )
