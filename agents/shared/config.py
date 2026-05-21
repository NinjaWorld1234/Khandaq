"""
SOC Platform - Central Configuration Loader
محمّل الإعدادات المركزي لمنصة مركز العمليات الأمنية

Loads configuration from YAML file and environment variables.
Provides typed access to all service connections and agent thresholds.
Implements the Singleton pattern to ensure one config instance across the platform.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Optional

import yaml

logger = logging.getLogger("soc.config")


# ---------------------------------------------------------------------------
# Typed configuration dataclasses
# كائنات الإعدادات المكتوبة بنوع محدد
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OpenSearchConfig:
    """OpenSearch connection settings. إعدادات اتصال أوبن سيرش"""
    hosts: list[str] = field(default_factory=lambda: ["https://localhost:9200"])
    username: str = "admin"
    password: str = "admin"
    verify_certs: bool = False
    ssl_show_warn: bool = False
    timeout: int = 30
    max_retries: int = 3
    retry_on_timeout: bool = True


@dataclass(frozen=True)
class WazuhConfig:
    """Wazuh API connection settings. إعدادات اتصال وازوه"""
    url: str = "https://localhost:55000"
    username: str = "wazuh-wui"
    password: str = "wazuh-wui"
    verify_ssl: bool = False
    timeout: int = 30


@dataclass(frozen=True)
class MISPConfig:
    """MISP connection settings. إعدادات اتصال منصة مشاركة المعلومات"""
    url: str = "https://localhost:8443"
    api_key: str = ""
    verify_ssl: bool = False
    timeout: int = 30


@dataclass(frozen=True)
class IRISConfig:
    """DFIR-IRIS connection settings. إعدادات اتصال آيريس"""
    url: str = "https://localhost:8443"
    api_key: str = ""
    verify_ssl: bool = False
    timeout: int = 30


@dataclass(frozen=True)
class OllamaConfig:
    """Ollama LLM connection settings. إعدادات اتصال نموذج اللغة"""
    url: str = "http://localhost:11434"
    model: str = "llama3"
    timeout: int = 120
    max_tokens: int = 2048
    temperature: float = 0.1


@dataclass(frozen=True)
class RedisConfig:
    """Redis connection settings. إعدادات اتصال ريدس"""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: str = ""
    socket_timeout: int = 10


@dataclass(frozen=True)
class SMTPConfig:
    """SMTP email settings. إعدادات البريد الإلكتروني"""
    host: str = "localhost"
    port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = "soc@example.com"
    to_addrs: list[str] = field(default_factory=list)
    use_tls: bool = True


@dataclass(frozen=True)
class SlackConfig:
    """Slack webhook settings. إعدادات سلاك"""
    webhook_url: str = ""
    channel: str = "#soc-alerts"
    enabled: bool = False


@dataclass(frozen=True)
class TelegramConfig:
    """Telegram bot settings. إعدادات تليغرام"""
    bot_token: str = ""
    chat_id: str = ""
    enabled: bool = False


@dataclass(frozen=True)
class AlertingConfig:
    """Alerting configuration combining all channels. إعدادات التنبيهات"""
    smtp: SMTPConfig = field(default_factory=SMTPConfig)
    slack: SlackConfig = field(default_factory=SlackConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    rate_limit_seconds: int = 300  # Don't repeat same alert within 5 min
    log_to_opensearch: bool = True
    alert_index: str = "soc-alerts"


@dataclass(frozen=True)
class AgentThresholds:
    """Global agent threshold defaults. عتبات الوكلاء الافتراضية"""
    brute_force_fast_threshold: int = 10
    brute_force_fast_window_min: int = 5
    brute_force_slow_threshold: int = 20
    brute_force_slow_window_hours: int = 24
    brute_force_distributed_ips: int = 5
    brute_force_distributed_window_min: int = 60
    brute_force_spray_accounts: int = 10
    brute_force_spray_window_min: int = 60
    log_drop_critical_pct: float = 100.0  # 100% drop = critical
    log_drop_high_pct: float = 70.0       # 70% drop = high
    log_baseline_days: int = 7
    health_check_timeout: int = 10


@dataclass
class MetricsConfig:
    """Prometheus metrics exporter settings. إعدادات مقاييس بروميثيوس"""
    enabled: bool = True
    port: int = 9100


# ---------------------------------------------------------------------------
# Singleton Configuration Loader
# محمّل الإعدادات بنمط المفرد
# ---------------------------------------------------------------------------

class SOCConfig:
    """
    Central configuration singleton.
    Loads settings from a YAML file, with environment variable overrides.

    Usage:
        config = SOCConfig.get_instance()
        config = SOCConfig.get_instance("/path/to/config.yaml")
    """

    _instance: Optional[SOCConfig] = None
    _lock: Lock = Lock()

    def __init__(self, config_path: Optional[str] = None) -> None:
        """Initialize configuration. Should be called via get_instance()."""
        self._raw: dict[str, Any] = {}
        self._config_path = config_path or self._resolve_config_path()
        self._load()

    # -- Singleton accessor --------------------------------------------------

    @classmethod
    def get_instance(cls, config_path: Optional[str] = None) -> SOCConfig:
        """
        Return the singleton config instance.
        Thread-safe via double-checked locking.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(config_path)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (useful for testing). إعادة تعيين المفرد"""
        with cls._lock:
            cls._instance = None

    # -- Config resolution ---------------------------------------------------

    @staticmethod
    def _resolve_config_path() -> str:
        """Resolve the config file path from env or default location."""
        env_path = os.environ.get("SOC_CONFIG_PATH")
        if env_path and Path(env_path).is_file():
            return env_path
        # Default: look relative to agents/ directory
        default = Path(__file__).resolve().parent.parent / "config" / "agent_config.yaml"
        return str(default)

    # -- Loading logic -------------------------------------------------------

    def _load(self) -> None:
        """Load YAML config and apply environment variable overrides."""
        path = Path(self._config_path)
        if path.is_file():
            with open(path, "r", encoding="utf-8") as fh:
                self._raw = yaml.safe_load(fh) or {}
            logger.info("Configuration loaded from %s", path)
        else:
            logger.warning(
                "Config file not found at %s — using defaults + env vars",
                path,
            )
            self._raw = {}

        # Build typed sub-configs
        self.opensearch = self._build_opensearch()
        self.wazuh = self._build_wazuh()
        self.misp = self._build_misp()
        self.iris = self._build_iris()
        self.ollama = self._build_ollama()
        self.redis = self._build_redis()
        self.alerting = self._build_alerting()
        self.thresholds = self._build_thresholds()
        self.metrics = self._build_metrics()

        # Agent-specific overrides stored as raw dicts
        self.agents: dict[str, dict[str, Any]] = self._raw.get("agents", {})

        logger.info("Configuration initialised successfully.")

    # -- Environment variable helper -----------------------------------------

    @staticmethod
    def _env(key: str, default: Any = None, cast: type = str) -> Any:
        """
        Read an environment variable with optional type casting.
        قراءة متغير البيئة مع تحويل النوع الاختياري
        """
        val = os.environ.get(key)
        if val is None:
            return default
        try:
            if cast is bool:
                return val.lower() in ("1", "true", "yes")
            return cast(val)
        except (ValueError, TypeError):
            return default

    # -- Builder methods (YAML → dataclass, env override) --------------------

    def _section(self, *keys: str) -> dict[str, Any]:
        """Safely traverse nested YAML keys."""
        node = self._raw
        for k in keys:
            if isinstance(node, dict):
                node = node.get(k, {})
            else:
                return {}
        return node if isinstance(node, dict) else {}

    def _build_opensearch(self) -> OpenSearchConfig:
        s = self._section("opensearch")
        hosts_raw = self._env("OPENSEARCH_HOSTS", s.get("hosts", ["https://localhost:9200"]))
        if isinstance(hosts_raw, str):
            hosts = [h.strip() for h in hosts_raw.split(",")]
        else:
            hosts = list(hosts_raw)
        return OpenSearchConfig(
            hosts=hosts,
            username=self._env("OPENSEARCH_USER", s.get("username", "admin")),
            password=self._env("OPENSEARCH_PASSWORD", s.get("password", "admin")),
            verify_certs=self._env("OPENSEARCH_VERIFY_CERTS", s.get("verify_certs", False), bool),
            ssl_show_warn=self._env("OPENSEARCH_SSL_WARN", s.get("ssl_show_warn", False), bool),
            timeout=self._env("OPENSEARCH_TIMEOUT", s.get("timeout", 30), int),
            max_retries=self._env("OPENSEARCH_MAX_RETRIES", s.get("max_retries", 3), int),
            retry_on_timeout=self._env("OPENSEARCH_RETRY_TIMEOUT", s.get("retry_on_timeout", True), bool),
        )

    def _build_wazuh(self) -> WazuhConfig:
        s = self._section("wazuh")
        return WazuhConfig(
            url=self._env("WAZUH_API_URL", s.get("url", "https://localhost:55000")),
            username=self._env("WAZUH_API_USER", s.get("username", "wazuh-wui")),
            password=self._env("WAZUH_API_PASSWORD", s.get("password", "wazuh-wui")),
            verify_ssl=self._env("WAZUH_VERIFY_SSL", s.get("verify_ssl", False), bool),
            timeout=self._env("WAZUH_TIMEOUT", s.get("timeout", 30), int),
        )

    def _build_misp(self) -> MISPConfig:
        s = self._section("misp")
        return MISPConfig(
            url=self._env("MISP_URL", s.get("url", "https://localhost:8443")),
            api_key=self._env("MISP_API_KEY", s.get("api_key", "")),
            verify_ssl=self._env("MISP_VERIFY_SSL", s.get("verify_ssl", False), bool),
            timeout=self._env("MISP_TIMEOUT", s.get("timeout", 30), int),
        )

    def _build_iris(self) -> IRISConfig:
        s = self._section("iris")
        return IRISConfig(
            url=self._env("IRIS_URL", s.get("url", "https://localhost:8443")),
            api_key=self._env("IRIS_API_KEY", s.get("api_key", "")),
            verify_ssl=self._env("IRIS_VERIFY_SSL", s.get("verify_ssl", False), bool),
            timeout=self._env("IRIS_TIMEOUT", s.get("timeout", 30), int),
        )

    def _build_ollama(self) -> OllamaConfig:
        s = self._section("ollama")
        return OllamaConfig(
            url=self._env("OLLAMA_URL", s.get("url", "http://localhost:11434")),
            model=self._env("OLLAMA_MODEL", s.get("model", "llama3")),
            timeout=self._env("OLLAMA_TIMEOUT", s.get("timeout", 120), int),
            max_tokens=self._env("OLLAMA_MAX_TOKENS", s.get("max_tokens", 2048), int),
            temperature=self._env("OLLAMA_TEMPERATURE", s.get("temperature", 0.1), float),
        )

    def _build_redis(self) -> RedisConfig:
        s = self._section("redis")
        return RedisConfig(
            host=self._env("REDIS_HOST", s.get("host", "localhost")),
            port=self._env("REDIS_PORT", s.get("port", 6379), int),
            db=self._env("REDIS_DB", s.get("db", 0), int),
            password=self._env("REDIS_PASSWORD", s.get("password", "")),
            socket_timeout=self._env("REDIS_SOCKET_TIMEOUT", s.get("socket_timeout", 10), int),
        )

    def _build_alerting(self) -> AlertingConfig:
        s = self._section("alerting")
        smtp_s = s.get("smtp", {})
        slack_s = s.get("slack", {})
        tg_s = s.get("telegram", {})

        smtp = SMTPConfig(
            host=self._env("SMTP_HOST", smtp_s.get("host", "localhost")),
            port=self._env("SMTP_PORT", smtp_s.get("port", 587), int),
            username=self._env("SMTP_USER", smtp_s.get("username", "")),
            password=self._env("SMTP_PASSWORD", smtp_s.get("password", "")),
            from_addr=self._env("SMTP_FROM", smtp_s.get("from_addr", "soc@example.com")),
            to_addrs=smtp_s.get("to_addrs", []),
            use_tls=self._env("SMTP_TLS", smtp_s.get("use_tls", True), bool),
        )
        slack = SlackConfig(
            webhook_url=self._env("SLACK_WEBHOOK_URL", slack_s.get("webhook_url", "")),
            channel=self._env("SLACK_CHANNEL", slack_s.get("channel", "#soc-alerts")),
            enabled=self._env("SLACK_ENABLED", slack_s.get("enabled", False), bool),
        )
        telegram = TelegramConfig(
            bot_token=self._env("TELEGRAM_BOT_TOKEN", tg_s.get("bot_token", "")),
            chat_id=self._env("TELEGRAM_CHAT_ID", tg_s.get("chat_id", "")),
            enabled=self._env("TELEGRAM_ENABLED", tg_s.get("enabled", False), bool),
        )
        return AlertingConfig(
            smtp=smtp,
            slack=slack,
            telegram=telegram,
            rate_limit_seconds=s.get("rate_limit_seconds", 300),
            log_to_opensearch=s.get("log_to_opensearch", True),
            alert_index=s.get("alert_index", "soc-alerts"),
        )

    def _build_thresholds(self) -> AgentThresholds:
        s = self._section("thresholds")
        return AgentThresholds(
            brute_force_fast_threshold=s.get("brute_force_fast_threshold", 10),
            brute_force_fast_window_min=s.get("brute_force_fast_window_min", 5),
            brute_force_slow_threshold=s.get("brute_force_slow_threshold", 20),
            brute_force_slow_window_hours=s.get("brute_force_slow_window_hours", 24),
            brute_force_distributed_ips=s.get("brute_force_distributed_ips", 5),
            brute_force_distributed_window_min=s.get("brute_force_distributed_window_min", 60),
            brute_force_spray_accounts=s.get("brute_force_spray_accounts", 10),
            brute_force_spray_window_min=s.get("brute_force_spray_window_min", 60),
            log_drop_critical_pct=s.get("log_drop_critical_pct", 100.0),
            log_drop_high_pct=s.get("log_drop_high_pct", 70.0),
            log_baseline_days=s.get("log_baseline_days", 7),
            health_check_timeout=s.get("health_check_timeout", 10),
        )

    def _build_metrics(self) -> MetricsConfig:
        s = self._section("metrics")
        return MetricsConfig(
            enabled=self._env("METRICS_ENABLED", s.get("enabled", True), bool),
            port=self._env("METRICS_PORT", s.get("port", 9100), int),
        )

    # -- Agent-specific config accessor --------------------------------------

    def get_agent_config(self, agent_name: str) -> dict[str, Any]:
        """
        Return agent-specific configuration overrides.
        إرجاع إعدادات خاصة بوكيل معيّن
        """
        return self.agents.get(agent_name, {})

    # -- Convenience ----------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<SOCConfig path={self._config_path!r} "
            f"opensearch={self.opensearch.hosts} "
            f"wazuh={self.wazuh.url}>"
        )
