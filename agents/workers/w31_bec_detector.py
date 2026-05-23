"""
SOC Platform - Worker Agent W31: Business Email Compromise Detector
وكيل كشف اختراق البريد الإلكتروني التجاري

Detects BEC / CEO fraud attempts from email logs:
- Executive impersonation (display name vs actual email mismatch)
- Wire transfer / payment keywords in subjects and body
- Domain spoofing (similar domain names to company)
- Unusual email forwarding rules being created
- Auto-forward rules to external addresses

Severity: CRITICAL for payment-related BEC, HIGH for impersonation
Interval: 120 seconds | Supervisor: soc:detection-supervisor
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w31_bec")

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_PAYMENT_KEYWORDS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bwire\s*transfer\b", r"\bbank\s*transfer\b", r"\bpayment\b",
        r"\binvoice\b", r"\bpurchase\s*order\b", r"\bACH\b",
        r"\bremittance\b", r"\btransaction\b", r"\bfund\s*transfer\b",
        r"\bfinancial\b", r"\baccount\s*number\b", r"\brouting\s*number\b",
        r"\bswift\s*code\b", r"\bwiring\s*instructions\b",
    ]
]

_URGENCY_KEYWORDS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\burgent\b", r"\basap\b", r"\bimmediately\b", r"\bconfidential\b",
        r"\bdo not share\b", r"\bkeep.{0,5}quiet\b", r"\bbefore\s*end\s*of\s*day\b",
        r"\btime.{0,5}sensitive\b", r"\bdon'?t\s*tell\b",
    ]
]


class BECDetectorAgent(BaseAgent):
    """Business Email Compromise Detector Agent (W31)."""

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w31_bec_detector",
            description="Detects Business Email Compromise (BEC) patterns",
            interval_seconds=120,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")

        # Executive roster loaded from agent config (fallback to defaults)
        self._executives: list[dict[str, str]] = self._agent_config.get("executives", [
            {"name": "John Smith", "email": "jsmith@company.com", "title": "CEO"},
            {"name": "Jane Doe", "email": "jdoe@company.com", "title": "CFO"},
            {"name": "Robert Brown", "email": "rbrown@company.com", "title": "COO"},
        ])
        self._exec_names: dict[str, str] = {
            e["name"].lower(): e["email"].lower() for e in self._executives
        }
        self._exec_emails: set[str] = {e["email"].lower() for e in self._executives}
        self._company_domains: set[str] = set(
            self._agent_config.get("company_domains", ["company.com"])
        )

        self._alerted_cache: dict[str, float] = {}
        self._alert_cooldown = 600

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[list[dict[str, Any]]]:
        """Fetch email-related and forwarding-rule events."""
        try:
            email_query = {
                "bool": {
                    "should": [
                        {"match_phrase": {"rule.groups": "mail"}},
                        {"match_phrase": {"data.type": "email"}},
                        {"match_phrase": {"rule.groups": "exchange"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            email_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3, query=email_query, size=500,
            )
            # Also fetch forwarding rule changes
            fwd_query = {
                "bool": {
                    "should": [
                        {"match_phrase": {"data.action": "Set-Mailbox"}},
                        {"match_phrase": {"data.action": "New-InboxRule"}},
                        {"match_phrase": {"rule.description": "forwarding"}},
                        {"match": {"data.win.eventdata.commandLine": "forward"}},
                    ],
                    "minimum_should_match": 1,
                }
            }
            fwd_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=3, query=fwd_query, size=100,
            )
            return email_events + fwd_events
        except Exception as exc:
            logger.error("Failed to collect BEC data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Detect BEC indicators in collected events."""
        findings: list[dict[str, Any]] = []
        for event in data:
            data_block = event.get("data", {})
            action = data_block.get("action", "")

            # Check forwarding rules
            if action in ("Set-Mailbox", "New-InboxRule") or "forward" in str(event).lower():
                finding = self._check_forwarding_rule(event, data_block)
                if finding:
                    findings.append(finding)
                continue

            # Check email events for impersonation / payment BEC
            from_addr = data_block.get("from", "")
            display_name = data_block.get("display_name", "")
            subject = data_block.get("subject", "")
            body = data_block.get("body", "")
            text_blob = f"{subject} {body}"

            # Executive impersonation: display name matches exec but email doesn't
            impersonation = self._check_impersonation(display_name, from_addr)
            if impersonation:
                has_payment = any(p.search(text_blob) for p in _PAYMENT_KEYWORDS)
                severity = Severity.CRITICAL if has_payment else Severity.HIGH
                findings.append({
                    "type": "executive_impersonation",
                    "severity": severity,
                    "from": from_addr,
                    "display_name": display_name,
                    "claimed_exec": impersonation["claimed"],
                    "real_email": impersonation["real_email"],
                    "has_payment_keywords": has_payment,
                    "subject": subject[:120],
                })
                continue

            # Domain spoofing: email from domain similar to company domain
            spoofing = self._check_domain_spoofing(from_addr)
            if spoofing:
                has_payment = any(p.search(text_blob) for p in _PAYMENT_KEYWORDS)
                has_urgency = any(p.search(text_blob) for p in _URGENCY_KEYWORDS)
                if has_payment or has_urgency:
                    findings.append({
                        "type": "domain_spoofing",
                        "severity": Severity.CRITICAL if has_payment else Severity.HIGH,
                        "from": from_addr,
                        "spoofed_domain": spoofing["spoofed"],
                        "real_domain": spoofing["legitimate"],
                        "has_payment_keywords": has_payment,
                        "subject": subject[:120],
                    })

            # Payment BEC from external sender
            if from_addr and not self._is_internal(from_addr):
                payment_hits = [p.pattern for p in _PAYMENT_KEYWORDS if p.search(text_blob)]
                urgency_hits = [p.pattern for p in _URGENCY_KEYWORDS if p.search(text_blob)]
                if len(payment_hits) >= 2 and urgency_hits:
                    findings.append({
                        "type": "payment_bec",
                        "severity": Severity.HIGH,
                        "from": from_addr,
                        "payment_keywords": payment_hits[:5],
                        "urgency_keywords": urgency_hits[:3],
                        "subject": subject[:120],
                    })

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    def _check_impersonation(
        self, display_name: str, from_addr: str,
    ) -> Optional[dict[str, str]]:
        """Check if display name impersonates an executive."""
        if not display_name:
            return None
        dn_lower = display_name.strip().lower()
        from_lower = from_addr.strip().lower()
        for exec_name, exec_email in self._exec_names.items():
            if exec_name in dn_lower and from_lower and exec_email not in from_lower:
                return {"claimed": exec_name, "real_email": exec_email}
        return None

    def _check_domain_spoofing(self, from_addr: str) -> Optional[dict[str, str]]:
        """Check if sender domain is a lookalike of company domains."""
        if "@" not in from_addr:
            return None
        sender_domain = from_addr.split("@")[-1].strip().lower().rstrip(">")
        for legit in self._company_domains:
            if sender_domain == legit:
                return None
            if self._is_similar_domain(sender_domain, legit):
                return {"spoofed": sender_domain, "legitimate": legit}
        return None

    @staticmethod
    def _is_similar_domain(candidate: str, legitimate: str) -> bool:
        """Detect domain similarity via substitution and edit distance."""
        c, l = candidate.lower(), legitimate.lower()
        subs = {"1": "l", "0": "o", "rn": "m", "vv": "w", "5": "s", "ii": "u"}
        norm = c
        for fake, real in subs.items():
            norm = norm.replace(fake, real)
        if norm == l:
            return True
        if abs(len(c) - len(l)) > 2:
            return False
        diffs = sum(1 for a, b in zip(c, l) if a != b) + abs(len(c) - len(l))
        return 0 < diffs <= 2

    def _is_internal(self, addr: str) -> bool:
        if "@" not in addr:
            return False
        domain = addr.split("@")[-1].strip().lower().rstrip(">")
        return domain in self._company_domains

    def _check_forwarding_rule(
        self, event: dict[str, Any], data_block: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Check if a forwarding rule directs mail to an external address."""
        fwd_to = data_block.get("forward_to", "") or data_block.get("parameters", "")
        user = data_block.get("user", data_block.get("srcuser", "unknown"))
        if not fwd_to:
            return None
        if "@" in fwd_to:
            fwd_domain = fwd_to.split("@")[-1].strip().lower().rstrip(">")
            if fwd_domain not in self._company_domains:
                return {
                    "type": "external_forwarding",
                    "severity": Severity.HIGH,
                    "user": user,
                    "forward_to": fwd_to,
                    "external_domain": fwd_domain,
                }
        return None

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        now = time.time()
        for f in findings:
            key = f"bec:{f['type']}:{f.get('from', f.get('user', ''))}"
            if now - self._alerted_cache.get(key, 0) < self._alert_cooldown:
                continue
            title_map = {
                "executive_impersonation": "BEC: Executive Impersonation Detected",
                "domain_spoofing": "BEC: Domain Spoofing Detected",
                "payment_bec": "BEC: Suspicious Payment Request",
                "external_forwarding": "BEC: External Mail Forwarding Rule Created",
            }
            actions.append({
                "type": "alert", "severity": f["severity"],
                "title": title_map.get(f["type"], "BEC: Suspicious Activity"),
                "details": {k: v for k, v in f.items() if k not in ("severity",)},
                "alert_key": key,
            })
            actions.append({"type": "log_incident", "finding": f})
        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        alerts_sent, logged = 0, 0
        for action in actions:
            if action["type"] == "alert":
                sent = self.alerter.send_alert(
                    severity=action["severity"], title=action["title"],
                    details=action["details"], agent_name=self.name,
                )
                if sent:
                    alerts_sent += 1
                    self._alerted_cache[action["alert_key"]] = time.time()
            elif action["type"] == "log_incident":
                try:
                    f = action["finding"]
                    self.os_client.index_document("soc-bec-incidents", {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent_name": self.name, "type": f["type"],
                        "severity": f["severity"].name,
                        "from": f.get("from", ""), "subject": f.get("subject", ""),
                    })
                    logged += 1
                except Exception as exc:
                    logger.error("Failed to log BEC incident: %s", exc)
        if alerts_sent:
            self.report_to_supervisor({
                "type": "bec_report", "alerts_sent": alerts_sent,
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
    agent = BECDetectorAgent()
    agent.run_loop()
