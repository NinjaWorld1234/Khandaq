"""
SOC Platform - Multi-Channel Alerter
نظام التنبيهات متعدد القنوات

Sends alerts across Slack, Telegram, Email (SMTP), and OpenSearch.
Includes severity levels and rate-limiting to prevent alert storms.
"""

from __future__ import annotations

import hashlib
import json
import logging
import smtplib
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import IntEnum
from typing import Any, Optional

import httpx

from .config import SOCConfig

logger = logging.getLogger("soc.alerter")


# ---------------------------------------------------------------------------
# Severity Levels / مستويات الخطورة
# ---------------------------------------------------------------------------

class Severity(IntEnum):
    """Alert severity levels. مستويات خطورة التنبيهات"""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def emoji(self) -> str:
        """Return a severity-appropriate emoji for Slack/Telegram."""
        return {
            Severity.INFO: "ℹ️",
            Severity.LOW: "🟡",
            Severity.MEDIUM: "🟠",
            Severity.HIGH: "🔴",
            Severity.CRITICAL: "🚨",
        }[self]

    @property
    def color(self) -> str:
        """Return a hex color for Slack attachments."""
        return {
            Severity.INFO: "#36a64f",
            Severity.LOW: "#daa520",
            Severity.MEDIUM: "#ff8c00",
            Severity.HIGH: "#ff0000",
            Severity.CRITICAL: "#8b0000",
        }[self]


# ---------------------------------------------------------------------------
# Multi-Channel Alerter / نظام التنبيهات
# ---------------------------------------------------------------------------

class Alerter:
    """
    Multi-channel alert dispatcher with rate limiting.
    موزع التنبيهات متعدد القنوات مع تحديد المعدل

    Usage:
        alerter = Alerter()
        alerter.send_alert(
            severity=Severity.HIGH,
            title="Brute Force Detected",
            details={"source_ip": "10.0.0.5", "attempts": 50},
            agent_name="w37_brute_force",
        )
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        """
        Initialize the alerter.

        Args:
            config: SOCConfig instance. Falls back to singleton if not provided.
        """
        cfg = config or SOCConfig.get_instance()
        self._alerting = cfg.alerting
        self._os_client: Optional[Any] = None  # Lazy-loaded to avoid circular import
        self._os_config = cfg.opensearch

        # Rate limiter: hash(alert) → last-sent timestamp
        self._rate_cache: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Rate limiting / تحديد المعدل
    # ------------------------------------------------------------------

    def _alert_hash(self, severity: Severity, title: str, agent_name: str) -> str:
        """Generate a stable hash for rate-limit deduplication."""
        key = f"{severity.name}:{title}:{agent_name}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _is_rate_limited(self, alert_key: str) -> bool:
        """Check whether this alert was sent recently."""
        last_sent = self._rate_cache.get(alert_key, 0.0)
        if time.time() - last_sent < self._alerting.rate_limit_seconds:
            return True
        return False

    def _mark_sent(self, alert_key: str) -> None:
        """Record the send time for rate-limiting."""
        self._rate_cache[alert_key] = time.time()
        # Periodically prune old entries to prevent unbounded growth
        if len(self._rate_cache) > 10_000:
            cutoff = time.time() - self._alerting.rate_limit_seconds * 2
            self._rate_cache = {
                k: v for k, v in self._rate_cache.items() if v > cutoff
            }

    # ------------------------------------------------------------------
    # Main send method / طريقة الإرسال الرئيسية
    # ------------------------------------------------------------------

    def send_alert(
        self,
        severity: Severity,
        title: str,
        details: dict[str, Any],
        agent_name: str,
        force: bool = False,
    ) -> bool:
        """
        Send an alert across all configured channels.

        Args:
            severity:   Alert severity level.
            title:      Short alert title.
            details:    Dict of alert details / context.
            agent_name: Name of the agent raising the alert.
            force:      If True, bypass rate limiting.

        Returns:
            True if the alert was dispatched (not rate-limited).
        """
        alert_key = self._alert_hash(severity, title, agent_name)

        if not force and self._is_rate_limited(alert_key):
            logger.debug(
                "Alert rate-limited: [%s] %s from %s", severity.name, title, agent_name
            )
            return False

        timestamp = datetime.now(timezone.utc).isoformat()
        alert_doc = {
            "timestamp": timestamp,
            "severity": severity.name,
            "severity_level": int(severity),
            "title": title,
            "details": details,
            "agent_name": agent_name,
        }

        logger.info(
            "[%s] %s %s — %s (agent=%s)",
            severity.name, severity.emoji, title,
            json.dumps(details, default=str)[:200],
            agent_name,
        )

        # Dispatch to all channels (best-effort; one failure doesn't block others)
        self._send_to_opensearch(alert_doc)
        self._send_to_slack(severity, title, details, agent_name, timestamp)
        self._send_to_telegram(severity, title, details, agent_name, timestamp)
        self._send_to_email(severity, title, details, agent_name, timestamp)

        self._mark_sent(alert_key)
        return True

    # ------------------------------------------------------------------
    # Channel: OpenSearch / قناة: أوبن سيرش
    # ------------------------------------------------------------------

    def _get_os_client(self) -> Any:
        """Lazy-load OpenSearch client to avoid circular imports."""
        if self._os_client is None:
            from .opensearch_client import OpenSearchClient
            self._os_client = OpenSearchClient()
        return self._os_client

    def _send_to_opensearch(self, alert_doc: dict[str, Any]) -> None:
        """Log alert to OpenSearch index."""
        if not self._alerting.log_to_opensearch:
            return
        try:
            client = self._get_os_client()
            index = self._alerting.alert_index
            client.index_document(index, alert_doc)
            logger.debug("Alert logged to OpenSearch index '%s'", index)
        except Exception as exc:
            logger.error("Failed to log alert to OpenSearch: %s", exc)

    # ------------------------------------------------------------------
    # Channel: Slack / قناة: سلاك
    # ------------------------------------------------------------------

    def _send_to_slack(
        self,
        severity: Severity,
        title: str,
        details: dict[str, Any],
        agent_name: str,
        timestamp: str,
    ) -> None:
        """Send alert to Slack via webhook."""
        slack_cfg = self._alerting.slack
        if not slack_cfg.enabled or not slack_cfg.webhook_url:
            return

        detail_lines = "\n".join(
            f"• *{k}*: `{v}`" for k, v in details.items()
        )
        payload = {
            "channel": slack_cfg.channel,
            "username": "SOC Bot",
            "icon_emoji": ":shield:",
            "attachments": [
                {
                    "color": severity.color,
                    "title": f"{severity.emoji} [{severity.name}] {title}",
                    "text": detail_lines,
                    "footer": f"Agent: {agent_name} | {timestamp}",
                    "fallback": f"[{severity.name}] {title}",
                }
            ],
        }

        try:
            resp = httpx.post(
                slack_cfg.webhook_url,
                json=payload,
                timeout=10,
            )
            resp.raise_for_status()
            logger.debug("Alert sent to Slack")
        except Exception as exc:
            logger.error("Slack alert failed: %s", exc)

    # ------------------------------------------------------------------
    # Channel: Telegram / قناة: تليغرام
    # ------------------------------------------------------------------

    def _send_to_telegram(
        self,
        severity: Severity,
        title: str,
        details: dict[str, Any],
        agent_name: str,
        timestamp: str,
    ) -> None:
        """Send alert to Telegram via Bot API."""
        tg_cfg = self._alerting.telegram
        if not tg_cfg.enabled or not tg_cfg.bot_token or not tg_cfg.chat_id:
            return

        detail_lines = "\n".join(f"  {k}: {v}" for k, v in details.items())
        text = (
            f"{severity.emoji} <b>[{severity.name}] {title}</b>\n\n"
            f"{detail_lines}\n\n"
            f"<i>Agent: {agent_name}</i>\n"
            f"<i>{timestamp}</i>"
        )

        url = f"https://api.telegram.org/bot{tg_cfg.bot_token}/sendMessage"
        try:
            resp = httpx.post(
                url,
                json={
                    "chat_id": tg_cfg.chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                },
                timeout=10,
            )
            resp.raise_for_status()
            logger.debug("Alert sent to Telegram")
        except Exception as exc:
            logger.error("Telegram alert failed: %s", exc)

    # ------------------------------------------------------------------
    # Channel: Email (SMTP) / قناة: البريد الإلكتروني
    # ------------------------------------------------------------------

    def _send_to_email(
        self,
        severity: Severity,
        title: str,
        details: dict[str, Any],
        agent_name: str,
        timestamp: str,
    ) -> None:
        """Send alert via SMTP email."""
        smtp_cfg = self._alerting.smtp
        if not smtp_cfg.to_addrs or not smtp_cfg.host:
            return

        subject = f"[SOC {severity.name}] {title}"
        detail_rows = "".join(
            f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k, v in details.items()
        )
        html_body = f"""
        <html>
        <body>
            <h2 style="color:{severity.color}">{severity.emoji} {title}</h2>
            <p><b>Severity:</b> {severity.name} | <b>Agent:</b> {agent_name}</p>
            <table border="1" cellpadding="5" cellspacing="0">
                {detail_rows}
            </table>
            <p><small>{timestamp}</small></p>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_cfg.from_addr
        msg["To"] = ", ".join(smtp_cfg.to_addrs)
        msg.attach(MIMEText(html_body, "html"))

        try:
            if smtp_cfg.use_tls:
                server = smtplib.SMTP(smtp_cfg.host, smtp_cfg.port)
                server.starttls()
            else:
                server = smtplib.SMTP(smtp_cfg.host, smtp_cfg.port)

            if smtp_cfg.username:
                server.login(smtp_cfg.username, smtp_cfg.password)

            server.sendmail(smtp_cfg.from_addr, smtp_cfg.to_addrs, msg.as_string())
            server.quit()
            logger.debug("Alert sent via email to %s", smtp_cfg.to_addrs)
        except Exception as exc:
            logger.error("Email alert failed: %s", exc)
