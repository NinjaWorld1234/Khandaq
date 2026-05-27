"""
SOC Platform - Worker Agent W30: Phishing Email Analyzer
وكيل تحليل رسائل التصيد الاحتيالي

Detects phishing indicators in email-related Wazuh alerts:
- Sender domain reputation (known phishing TLD patterns, newly-seen domains)
- Reply-to mismatch (From ≠ Reply-To)
- Urgent language patterns in subjects
- Suspicious attachment types (.html, .exe, .scr, .js, .vbs, etc.)
- Malicious URLs: IP-based links, URL shorteners, lookalike domains

Interval: 60 seconds | Supervisor: soc:detection-supervisor
"""

from __future__ import annotations

import logging
import re
import time
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w30_phishing")

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_URGENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\burgent\b", r"\bimmediate action\b", r"\bverify your account\b",
        r"\baccount.{0,10}suspend", r"\bunauthori[sz]ed.{0,10}access",
        r"\bconfirm.{0,10}identity\b", r"\bsecurity.{0,10}alert\b",
        r"\bpassword.{0,10}expir", r"\blocked.{0,5}out\b",
        r"\bfinal.{0,5}warning\b", r"\baction.{0,5}required\b",
    ]
]

_SUSPICIOUS_EXTENSIONS: set[str] = {
    ".html", ".htm", ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd",
    ".ps1", ".msi", ".jar", ".hta", ".wsf", ".iso", ".img",
}

_SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

_LEGITIMATE_DOMAINS: list[str] = [
    "paypal.com", "microsoft.com", "apple.com", "amazon.com", "google.com",
    "facebook.com", "instagram.com", "linkedin.com", "netflix.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "dropbox.com",
]

_SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".top", ".club", ".work", ".click", ".loan", ".stream",
    ".gq", ".cf", ".tk", ".ml", ".ga", ".buzz", ".icu",
}

_IP_URL_RE = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_URL_RE = re.compile(r"https?://([a-zA-Z0-9._-]+)")


class PhishingAnalyzerAgent(BaseAgent):
    """Phishing Email Analyzer Agent (W30)."""

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w30_phishing_analyzer",
            description="Analyzes emails for phishing links, attachments, and spoofing",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self._alert_index = self._agent_config.get(
            "alert_index", "wazuh-alerts-*")
        # domain -> first_seen timestamp
        self._seen_domains: dict[str, float] = {}
        self._alerted_cache: dict[str, float] = {}
        self._alert_cooldown = 300
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[list[dict[str, Any]]]:
        """Fetch email-related alerts from Wazuh for the last 2 minutes."""
        try:
            query = {
                "bool": {
                    "should": [
                        {"match_phrase": {"rule.groups": "mail"}},
                        {"match_phrase": {"rule.groups": "postfix"}},
                        {"match_phrase": {"rule.groups": "sendmail"}},
                        {"match_phrase": {"data.type": "email"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2, query=query, size=10000,
            )
            logger.debug("Collected %d email events", len(events))
            return events
        except Exception as exc:
            logger.error("Failed to collect email events: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Scan each email event for phishing indicators."""
        findings: list[dict[str, Any]] = []
        for event in data:
            try:
                indicators = self._score_event(event)
                if indicators:
                    score = sum(i["weight"] for i in indicators)
                    severity = (
                        Severity.HIGH if score >= 5
                        else Severity.MEDIUM if score >= 3
                        else Severity.LOW
                    )
                    findings.append({
                        "event": event,
                        "indicators": indicators,
                        "score": score,
                        "severity": severity,
                        "source": (event.get("data") or {}).get("srcip", "unknown"),
                        "from": (event.get("data") or {}).get("from", "unknown"),
                    })
                self._events_processed += 1
                self._metrics.inc_events(1)
            except Exception as e:
                logger.warning("Error analyzing phishing event: %s", e)
        return findings

    def _score_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Return weighted indicator list for a single event."""
        indicators: list[dict[str, Any]] = []
        data = event.get("data") or {}
        subject = data.get("subject", "")
        from_addr = data.get("from", "")
        reply_to = data.get("reply_to", "")
        attachments = data.get("attachments", [])
        body = data.get("body", "")
        urls = data.get("urls", []) or _URL_RE.findall(body)

        # 1. Reply-to mismatch
        if from_addr and reply_to and self._domain_of(
                from_addr) != self._domain_of(reply_to):
            indicators.append({"check": "reply_to_mismatch",
                               "weight": 3,
                               "detail": f"From={from_addr} Reply-To={reply_to}"})

        # 2. Urgent language
        for pat in _URGENT_PATTERNS:
            if pat.search(subject):
                indicators.append({"check": "urgent_language",
                                   "weight": 2,
                                   "detail": f"Subject matched: {pat.pattern}"})
                break  # one hit is enough

        # 3. Suspicious attachments
        if isinstance(attachments, list):
            for att in attachments:
                name = att if isinstance(att, str) else att.get("filename", "")
                ext = ("." + name.rsplit(".", 1)
                       [-1]).lower() if "." in name else ""
                if ext in _SUSPICIOUS_EXTENSIONS:
                    indicators.append({"check": "suspicious_attachment", "weight": 3,
                                       "detail": f"Attachment: {name}"})

        # 4. IP-based URLs
        all_urls = urls if isinstance(urls, list) else [urls]
        for url in all_urls:
            url_str = url if isinstance(url, str) else ""
            if _IP_URL_RE.search(url_str):
                indicators.append(
                    {"check": "ip_url", "weight": 3, "detail": url_str})
            # Shortened URLs
            for short in _SHORTENER_DOMAINS:
                if short in url_str.lower():
                    indicators.append(
                        {"check": "shortened_url", "weight": 2, "detail": url_str})
                    break

        # 5. Lookalike domains
        sender_domain = self._domain_of(from_addr)
        if sender_domain:
            for legit in _LEGITIMATE_DOMAINS:
                if sender_domain != legit and self._is_lookalike(
                        sender_domain, legit):
                    indicators.append({"check": "lookalike_domain",
                                       "weight": 4,
                                       "detail": f"{sender_domain} resembles {legit}"})
                    break

        # 6. Suspicious TLD
        if sender_domain:
            tld = "." + sender_domain.rsplit(".",
                                             1)[-1] if "." in sender_domain else ""
            if tld in _SUSPICIOUS_TLDS:
                indicators.append({"check": "suspicious_tld", "weight": 2,
                                   "detail": f"TLD: {tld}"})

        return indicators

    @staticmethod
    def _domain_of(addr: str) -> str:
        """Extract domain from an email address."""
        if "@" in addr:
            return addr.split("@")[-1].strip().lower().rstrip(">")
        return addr.strip().lower()

    @staticmethod
    def _is_lookalike(candidate: str, legitimate: str) -> bool:
        """Detect typo-squatting via character substitution heuristics."""
        c, line_str = candidate.lower(), legitimate.lower()
        if c == line_str:
            return False
        subs = {"1": "line_str", "0": "o", "rn": "m", "vv": "w", "5": "s"}
        normalized = c
        for fake, real in subs.items():
            normalized = normalized.replace(fake, real)
        if normalized == line_str:
            return True
        # Levenshtein distance ≤ 2
        if abs(len(c) - len(line_str)) > 2:
            return False
        diffs = sum(1 for a, b in zip(c, line_str) if a != b) + abs(len(c) - len(line_str))
        return 0 < diffs <= 2

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build alert and log actions for each finding."""
        actions: list[dict[str, Any]] = []
        now = time.time()
        for f in findings:
            try:
                key = f"phish:{f['from']}:{f['score']}"
                if now - self._alerted_cache.get(key, 0) < self._alert_cooldown:
                    continue
                checks = ", ".join(i["check"] for i in f["indicators"])
                actions.append({
                    "type": "alert",
                    "severity": f["severity"],
                    "title": "Phishing Email Detected",
                    "details": {
                        "from": f["from"], "source_ip": f["source"],
                        "score": f["score"], "indicators": checks,
                    },
                    "alert_key": key,
                })
                actions.append({"type": "log_incident", "finding": f})
            except Exception as e:
                logger.warning("Error deciding for phishing finding: %s", e)
        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """Execute alert and logging actions."""
        alerts_sent, logged = 0, 0
        for action in actions:
            try:
                if action["type"] == "alert":
                    sent = self.alerter.send_alert(
                        severity=action["severity"], title=action["title"],
                        details=action["details"], agent_name=self.name,
                    )
                    if sent:
                        alerts_sent += 1
                        self._metrics.inc_alerts(action["severity"].name)
                        with self._cache_lock:

                            self._alerted_cache[action["alert_key"]] = time.time()
                elif action["type"] == "log_incident":
                    try:
                        f = action["finding"]
                        self.os_client.index_document("soc-phishing-incidents", {
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name, "score": f["score"],
                            "severity": f["severity"].name, "from": f["from"],
                            "indicators": [i["check"] for i in f["indicators"]],
                        })
                        logged += 1
                    except Exception as exc:
                        logger.error("Failed to log phishing incident: %s", exc)
            except Exception as e:
                logger.warning("Error executing phishing action: %s", e)
        if alerts_sent:
            self.report_to_supervisor({
                "type": "phishing_report", "alerts_sent": alerts_sent,
                "incidents_logged": logged,
            })
        return {"alerts_sent": alerts_sent, "incidents_logged": logged}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = PhishingAnalyzerAgent()
    agent.run_loop()
