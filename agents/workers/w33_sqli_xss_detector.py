"""
W33 - SQL Injection / XSS / Command Injection Detection Agent
Monitors web server logs and Wazuh alerts from OpenSearch for injection attacks.

Detections:
  1. SQL Injection — UNION SELECT, OR 1=1, DROP TABLE, EXEC xp_, WAITFOR DELAY,
     benchmark(), information_schema, CHAR(), CONCAT(), hex encoding
  2. Cross-Site Scripting — <script>, javascript:, onerror=, onload=,
     document.cookie, <svg onload, <img onerror, eval(), String.fromCharCode
  3. Command Injection — pipe |, semicolon ;, &&, backticks, $(cmd),
     /etc/passwd, /bin/sh, cmd.exe, powershell
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote

from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("soc.agent.w33_sqli_xss_detector")

# ---------------------------------------------------------------------------
# SQL Injection patterns
# ---------------------------------------------------------------------------
SQLI_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
    (re.compile(r"union\s+(all\s+)?select", re.I), "UNION SELECT", 8),
    (re.compile(r"(?:^|\s|=)or\s+1\s*=\s*1", re.I), "OR 1=1 tautology", 7),
    (re.compile(r"(?:^|\s|=)or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.I), "OR tautology", 6),
    (re.compile(r"drop\s+(table|database)", re.I), "DROP TABLE/DATABASE", 9),
    (re.compile(r"exec\s+xp_", re.I), "EXEC xp_ stored procedure", 9),
    (re.compile(r"waitfor\s+delay", re.I), "WAITFOR DELAY (time-based blind)", 8),
    (re.compile(r"benchmark\s*\(", re.I), "benchmark() (time-based blind)", 8),
    (re.compile(r"information_schema", re.I), "information_schema enumeration", 7),
    (re.compile(r"(?:char|concat|hex)\s*\(", re.I), "Encoded payload (CHAR/CONCAT/HEX)", 6),
    (re.compile(r"(?:--|#|/\*)\s*$", re.I), "SQL comment terminator", 5),
    (re.compile(r"(?:'\s*;\s*(?:drop|alter|insert|update|delete))", re.I), "Stacked query", 9),
    (re.compile(r"(?:load_file|into\s+outfile|into\s+dumpfile)", re.I), "File access via SQL", 9),
    (re.compile(r"sleep\s*\(\s*\d+\s*\)", re.I), "SLEEP() blind injection", 8),
]

# ---------------------------------------------------------------------------
# XSS patterns
# ---------------------------------------------------------------------------
XSS_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
    (re.compile(r"<\s*script", re.I), "<script> tag", 8),
    (re.compile(r"javascript\s*:", re.I), "javascript: URI", 8),
    (re.compile(r"on(error|load|click|mouseover|focus|blur)\s*=", re.I), "Event handler attribute", 7),
    (re.compile(r"document\.(cookie|domain|write|location)", re.I), "DOM access (cookie/write)", 8),
    (re.compile(r"<\s*svg\s+onload", re.I), "<svg onload>", 8),
    (re.compile(r"<\s*img\s+[^>]*onerror", re.I), "<img onerror>", 7),
    (re.compile(r"<\s*iframe", re.I), "<iframe> injection", 7),
    (re.compile(r"eval\s*\(", re.I), "eval() call", 7),
    (re.compile(r"string\.fromcharcode", re.I), "String.fromCharCode obfuscation", 7),
    (re.compile(r"<\s*body\s+onload", re.I), "<body onload>", 7),
    (re.compile(r"alert\s*\(", re.I), "alert() probe", 5),
    (re.compile(r"prompt\s*\(", re.I), "prompt() probe", 5),
    (re.compile(r"<\s*embed|<\s*object|<\s*applet", re.I), "Embedded object tag", 6),
]

# ---------------------------------------------------------------------------
# Command Injection patterns
# ---------------------------------------------------------------------------
CMDI_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
    (re.compile(r"\|\s*\w+"), "Pipe command chaining", 7),
    (re.compile(r";\s*(?:ls|cat|whoami|id|uname|wget|curl|nc|bash|sh)\b", re.I), "Semicolon + command", 8),
    (re.compile(r"&&\s*(?:ls|cat|whoami|id|wget|curl|nc|bash|sh)\b", re.I), "&& command chaining", 8),
    (re.compile(r"`[^`]+`"), "Backtick command substitution", 8),
    (re.compile(r"\$\([^)]+\)"), "$(cmd) command substitution", 8),
    (re.compile(r"/etc/passwd", re.I), "/etc/passwd access", 7),
    (re.compile(r"/bin/(?:sh|bash|zsh|csh|dash)", re.I), "Shell binary reference", 8),
    (re.compile(r"cmd\.exe|powershell|pwsh", re.I), "Windows shell reference", 8),
    (re.compile(r"(?:wget|curl)\s+https?://", re.I), "Remote download attempt", 7),
    (re.compile(r"(?:nc|ncat|netcat)\s+-", re.I), "Netcat reverse shell", 9),
]

# Minimum score to generate a finding for each category
SQLI_MIN_SCORE = 5
XSS_MIN_SCORE = 5
CMDI_MIN_SCORE = 6

# Per-source tracking: IP → attack count (for repeat-offender escalation)
REPEAT_OFFENDER_THRESHOLD = 5


class SQLiXSSDetectorAgent(BaseAgent):
    """Detects SQL injection, XSS, and command injection in web traffic."""

    def __init__(self) -> None:
        super().__init__(
            name="W33_SQLiXSSDetector",
            description="Detects SQL injection, XSS, and command injection attacks in web logs",
            interval_seconds=30,
            supervisor_channel="soc:network-supervisor",
        )
        # Track repeat offenders: src_ip → list of (timestamp, type)
        self._offender_log: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._offender_window = 300  # 5-minute window
        self._alerted: Dict[str, float] = {}
        self._alert_cooldown = 120

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_payload(raw: str) -> str:
        """Double URL-decode the payload for pattern matching."""
        try:
            decoded = unquote(unquote(raw))
        except Exception:
            decoded = raw
        return decoded

    @staticmethod
    def _extract_payloads(event: Dict[str, Any]) -> List[str]:
        """Pull all fields that may contain injection payloads."""
        fields = [
            "data.url", "url", "request", "http.url",
            "data.srcuser", "data.dstuser", "data.data",
            "full_log", "message", "rule.description",
            "http.http_refer", "http.http_user_agent",
            "query", "request_body", "args",
        ]
        payloads: List[str] = []
        for field in fields:
            val = event.get(field)
            if val is None and "." in field:
                parts = field.split(".")
                val = (event.get(parts[0]) or {}).get(parts[1])
            if val and isinstance(val, str):
                payloads.append(val)
        return payloads

    def _scan_patterns(
        self, text: str, patterns: List[Tuple[re.Pattern, str, int]]
    ) -> List[Tuple[str, int]]:
        """Return list of (pattern_name, score) for all matching patterns."""
        matches = []
        for regex, name, score in patterns:
            if regex.search(text):
                matches.append((name, score))
        return matches

    def _should_alert(self, key: str) -> bool:
        now = time.time()
        last = self._alerted.get(key, 0)
        if now - last < self._alert_cooldown:
            return False
        self._alerted[key] = now
        return True

    def _prune_offenders(self) -> None:
        cutoff = time.time() - self._offender_window
        for ip in list(self._offender_log.keys()):
            self._offender_log[ip] = [
                (ts, t) for ts, t in self._offender_log[ip] if ts > cutoff
            ]
            if not self._offender_log[ip]:
                del self._offender_log[ip]

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Wazuh web-related alerts and web server logs from the last 30 seconds."""
        wazuh_query = {
            "bool": {
                "should": [
                    {"range": {"rule.level": {"gte": 3}}},
                    {"terms": {"rule.groups": ["web", "attack", "sqli", "xss"]}},
                    {"wildcard": {"data.url": "*"}},
                    {"wildcard": {"request": "*"}},
                ],
                "minimum_should_match": 1,
            }
        }
        web_query = {
            "bool": {
                "must": [
                    {"exists": {"field": "http.url"}},
                ],
            }
        }
        try:
            wazuh_events = self.os_client.get_events_since(
                "wazuh-alerts-*", minutes=1, query=wazuh_query, size=10000
            )
            web_events = self.os_client.get_events_since(
                "filebeat-*", minutes=1, query=web_query, size=10000
            )
            all_events = wazuh_events + web_events
            logger.debug("Collected %d web/Wazuh events", len(all_events))
            return all_events
        except Exception as exc:
            logger.error("Failed to collect web log data: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan every event for SQLi, XSS, and command injection patterns."""
        findings: List[Dict[str, Any]] = []
        if not data:
            return findings

        for event in data:
            try:
                data_block = event.get("data") or {}
                src_ip = (
                    event.get("data.srcip")
                    or data_block.get("srcip")
                    or event.get("src_ip")
                    or event.get("client.ip")
                    or "unknown"
                )
                dest_ip = event.get("data.dstip") or data_block.get("dstip") or event.get("dest_ip") or ""
                url = event.get("data.url") or data_block.get("url") or event.get("url") or event.get("http.url") or ""

                payloads = self._extract_payloads(event)
                if not payloads:
                    self._events_processed += 1
                    self._metrics.inc_events(1)
                    continue

                for raw_payload in payloads:
                    decoded = self._decode_payload(raw_payload)

                    # --- SQLi check ---
                    sqli_matches = self._scan_patterns(decoded, SQLI_PATTERNS)
                    if sqli_matches:
                        max_score = max(s for _, s in sqli_matches)
                        if max_score >= SQLI_MIN_SCORE:
                            pattern_names = [n for n, _ in sqli_matches]
                            key = f"sqli:{src_ip}:{hash(decoded) % 10**8}"
                            if self._should_alert(key):
                                severity = Severity.CRITICAL if max_score >= 9 else Severity.HIGH
                                findings.append({
                                    "type": "sql_injection",
                                    "severity": severity,
                                    "src_ip": src_ip,
                                    "dest_ip": dest_ip,
                                    "url": url[:300],
                                    "matched_patterns": pattern_names,
                                    "score": max_score,
                                    "payload_snippet": decoded[:200],
                                    "details": (
                                        f"SQLi from {src_ip}: {', '.join(pattern_names[:3])} "
                                        f"(score {max_score})"
                                    ),
                                })
                                self._offender_log[src_ip].append((time.time(), "sqli"))

                    # --- XSS check ---
                    xss_matches = self._scan_patterns(decoded, XSS_PATTERNS)
                    if xss_matches:
                        max_score = max(s for _, s in xss_matches)
                        if max_score >= XSS_MIN_SCORE:
                            pattern_names = [n for n, _ in xss_matches]
                            key = f"xss:{src_ip}:{hash(decoded) % 10**8}"
                            if self._should_alert(key):
                                severity = Severity.HIGH if max_score >= 7 else Severity.MEDIUM
                                findings.append({
                                    "type": "xss",
                                    "severity": severity,
                                    "src_ip": src_ip,
                                    "dest_ip": dest_ip,
                                    "url": url[:300],
                                    "matched_patterns": pattern_names,
                                    "score": max_score,
                                    "payload_snippet": decoded[:200],
                                    "details": (
                                        f"XSS from {src_ip}: {', '.join(pattern_names[:3])} "
                                        f"(score {max_score})"
                                    ),
                                })
                                self._offender_log[src_ip].append((time.time(), "xss"))

                    # --- Command Injection check ---
                    cmdi_matches = self._scan_patterns(decoded, CMDI_PATTERNS)
                    if cmdi_matches:
                        max_score = max(s for _, s in cmdi_matches)
                        if max_score >= CMDI_MIN_SCORE:
                            pattern_names = [n for n, _ in cmdi_matches]
                            key = f"cmdi:{src_ip}:{hash(decoded) % 10**8}"
                            if self._should_alert(key):
                                severity = Severity.CRITICAL if max_score >= 9 else Severity.HIGH
                                findings.append({
                                    "type": "command_injection",
                                    "severity": severity,
                                    "src_ip": src_ip,
                                    "dest_ip": dest_ip,
                                    "url": url[:300],
                                    "matched_patterns": pattern_names,
                                    "score": max_score,
                                    "payload_snippet": decoded[:200],
                                    "details": (
                                        f"Command injection from {src_ip}: "
                                        f"{', '.join(pattern_names[:3])} (score {max_score})"
                                    ),
                                })
                                self._offender_log[src_ip].append((time.time(), "cmdi"))
                self._events_processed += 1
                self._metrics.inc_events(1)
            except Exception as e:
                logger.warning("Error analyzing SQLi/XSS event: %s", e)

        # --- Repeat-offender detection ---
        self._prune_offenders()
        for src_ip, entries in self._offender_log.items():
            try:
                if len(entries) >= REPEAT_OFFENDER_THRESHOLD:
                    key = f"repeat:{src_ip}"
                    if self._should_alert(key):
                        attack_types = list({t for _, t in entries})
                        findings.append({
                            "type": "repeat_offender",
                            "severity": Severity.CRITICAL,
                            "src_ip": src_ip,
                            "attack_count": len(entries),
                            "attack_types": attack_types,
                            "details": (
                                f"Repeat offender {src_ip}: {len(entries)} injection attempts "
                                f"({', '.join(attack_types)}) in 5 min"
                            ),
                        })
            except Exception as e:
                logger.warning("Error processing repeat offender: %s", e)

        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build action list: alert, escalate, block repeat offenders."""
        actions: List[Dict[str, Any]] = []

        for f in findings:
            try:
                actions.append({"action": "alert", "data": f})

                if f["severity"] >= Severity.HIGH:
                    actions.append({"action": "escalate", "data": f})

                # Block repeat offenders via active response
                if f["type"] == "repeat_offender":
                    actions.append({
                        "action": "block_source",
                        "src_ip": f["src_ip"],
                        "reason": f["details"],
                    })

                actions.append({"action": "index_finding", "data": f})
            except Exception as e:
                logger.warning("Error deciding for SQLi/XSS finding: %s", e)

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alerts, escalations, blocks, and indexing."""
        results = {"alerts_sent": 0, "escalations": 0, "blocks": 0, "indexed": 0}

        for action in actions:
            try:
                if action["action"] == "alert":
                    d = action["data"]
                    sent = self.alerter.send_alert(
                        severity=d["severity"],
                        title=f"Web Attack: {d['type'].replace('_', ' ').title()}",
                        details={
                            "src_ip": d.get("src_ip"),
                            "dest_ip": d.get("dest_ip", "N/A"),
                            "url": d.get("url", "N/A"),
                            "patterns": ", ".join(d.get("matched_patterns", [])[:4]),
                            "info": d["details"],
                        },
                        agent_name=self.name,
                    )
                    if sent:
                        results["alerts_sent"] += 1
                        self._metrics.inc_alerts(d["severity"].name)

                elif action["action"] == "escalate":
                    self.report_to_supervisor(action["data"])
                    results["escalations"] += 1

                elif action["action"] == "block_source":
                    doc = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent": self.name,
                        "action": "waf-block",
                        "src_ip": action["src_ip"],
                        "reason": action["reason"],
                        "status": "requested",
                    }
                    self.os_client.index_document("soc-active-response", doc)
                    logger.warning(
                        "WAF block requested for %s: %s",
                        action["src_ip"], action["reason"][:100],
                    )
                    results["blocks"] += 1

                elif action["action"] == "index_finding":
                    d = action["data"]
                    doc = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent": self.name,
                        "finding_type": d["type"],
                        "severity": d["severity"].name,
                        "src_ip": d.get("src_ip"),
                        "dest_ip": d.get("dest_ip", ""),
                        "url": d.get("url", ""),
                        "matched_patterns": d.get("matched_patterns", []),
                        "payload_snippet": d.get("payload_snippet", ""),
                        "details": d["details"],
                    }
                    self.os_client.index_document("soc-injection-findings", doc)
                    results["indexed"] += 1

            except Exception as exc:
                logger.error("Action '%s' failed: %s", action.get("action"), exc)

        if results["alerts_sent"]:
            logger.info(
                "Injection cycle: %d alerts, %d escalations, %d blocks, %d indexed",
                results["alerts_sent"], results["escalations"],
                results["blocks"], results["indexed"],
            )

        return results


if __name__ == "__main__":
    agent = SQLiXSSDetectorAgent()
    agent.run_loop()
