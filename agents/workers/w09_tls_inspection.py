"""
W09 - TLS/SSL Anomaly Detection Agent
Monitors TLS/SSL handshake metadata from Zeek ssl.log for security anomalies.

Detections:
  1. Self-signed certificates to external IPs
  2. Expired certificates (not_valid_after in the past)
  3. Suspicious CN patterns (random strings, IP addresses as CN)
  4. JA3/JA3S fingerprints matching known malware families
  5. TLS on non-standard ports (not 443, 8443, 993, 995, 465, 636)
  6. Weak cipher suites (RC4, DES, NULL, EXPORT)
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.base_agent import BaseAgent
from shared.config import SOCConfig
from shared.alerter import Severity

logger = logging.getLogger("soc.agent.w09_tls_inspection")

# --- Standard TLS ports (traffic here is expected) ---
STANDARD_TLS_PORTS: Set[int] = {443, 8443, 993, 995, 465, 636, 853, 5061}

# --- RFC-1918 internal ranges ---
_INTERNAL_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|fe80:|::1)"
)

# --- Suspicious CN patterns ---
_CN_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")  # IP address used as CN
_CN_RANDOM_RE = re.compile(r"^[a-z0-9]{16,}$", re.IGNORECASE)  # Long hex/random string
_CN_DGA_RE = re.compile(
    r"^[a-z]{4,20}\.(top|xyz|club|work|buzz|gq|ml|tk|cf|ga|icu)$", re.IGNORECASE
)

# --- Known malware JA3 fingerprints (sample set) ---
MALWARE_JA3: Dict[str, str] = {
    "51c64c77e60f3980eea90869b68c58a8": "Emotet",
    "a0e9f5d64349fb13191bc781f81f42e1": "TrickBot",
    "e7d705a3286e19ea42f587b344ee6865": "Dridex",
    "6734f37431670b3ab4292b8f60f29984": "Tofsee",
    "b386946a5a44d1ddcc843bc75336dfce": "AsyncRAT",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
    "a112a7eed34d3f49e3fe3aa3a3217537": "Metasploit Meterpreter",
    "3b5074b1b5d032e5620f69f9f700ff0e": "IcedID",
}

MALWARE_JA3S: Dict[str, str] = {
    "ae4edc6faf64d08308082ad26be60767": "Cobalt Strike",
    "ec74a5c51106f0419184d0dd08fb05bc": "Cobalt Strike",
    "649d6810e8392f63dc311eecb6b7098b": "Trickbot",
}

# --- Weak cipher keywords ---
WEAK_CIPHER_TOKENS = ("RC4", "DES", "NULL", "EXPORT", "anon", "MD5")

# --- Known-good certificate fingerprints (allowlist) ---
CERT_FINGERPRINT_ALLOWLIST: Set[str] = set()


class TLSInspectionAgent(BaseAgent):
    """Detects TLS/SSL anomalies from Zeek ssl.log data."""

    def __init__(self) -> None:
        super().__init__(
            name="W09_TLSInspection",
            description="Monitors TLS/SSL metadata for anomalies in certificates, ciphers, and fingerprints",
            interval_seconds=120,
            supervisor_channel="soc:network-supervisor",
        )
        # Track recently alerted fingerprints to avoid duplicates within a window
        self._alerted_certs: Dict[str, float] = {}
        self._alert_cooldown = 600  # seconds

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_external(ip: str) -> bool:
        """Return True if the IP is NOT in a private/internal range."""
        return not bool(_INTERNAL_RE.match(ip))

    @staticmethod
    def _is_self_signed(event: Dict[str, Any]) -> bool:
        """Heuristic: certificate is self-signed if subject == issuer or validation_status says so."""
        subject = (event.get("subject") or "").strip()
        issuer = (event.get("issuer") or "").strip()
        validation = (event.get("validation_status") or "").lower()
        if "self signed" in validation or "self-signed" in validation:
            return True
        return bool(subject and issuer and subject == issuer)

    @staticmethod
    def _is_expired(event: Dict[str, Any]) -> bool:
        """Check if certificate not_valid_after is in the past."""
        not_after = event.get("not_valid_after") or event.get("certificate.not_valid_after")
        if not not_after:
            return False
        try:
            if isinstance(not_after, (int, float)):
                expiry = datetime.fromtimestamp(not_after, tz=timezone.utc)
            else:
                expiry = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
            return expiry < datetime.now(timezone.utc)
        except (ValueError, OSError):
            return False

    @staticmethod
    def _extract_cn(subject: str) -> str:
        """Extract CN= value from an X.509 subject string."""
        match = re.search(r"CN=([^,/]+)", subject or "", re.IGNORECASE)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _is_suspicious_cn(cn: str) -> bool:
        """Return True if the CN looks like an IP, DGA domain, or random string."""
        if not cn:
            return False
        if _CN_IP_RE.match(cn):
            return True
        if _CN_RANDOM_RE.match(cn):
            return True
        if _CN_DGA_RE.match(cn):
            return True
        return False

    def _should_alert(self, key: str) -> bool:
        """Return True if this key hasn't been alerted within the cooldown."""
        now = time.time()
        last = self._alerted_certs.get(key, 0)
        if now - last < self._alert_cooldown:
            return False
        self._alerted_certs[key] = now
        return True

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Zeek ssl.log events from the last 2 minutes."""
        query = {
            "bool": {
                "must": [
                    {"exists": {"field": "id.resp_h"}},
                ],
                "should": [
                    {"exists": {"field": "subject"}},
                    {"exists": {"field": "ja3"}},
                    {"exists": {"field": "cipher"}},
                ],
                "minimum_should_match": 1,
            }
        }
        try:
            events = self.os_client.get_events_since(
                "zeek-*", minutes=2, query=query, size=5000
            )
            logger.debug("Collected %d TLS events", len(events))
            return events
        except Exception as exc:
            logger.error("Failed to collect TLS data: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run six detection rules across TLS events."""
        findings: List[Dict[str, Any]] = []
        if not data:
            return findings

        for event in data:
            src_ip = event.get("id.orig_h", "unknown")
            dest_ip = event.get("id.resp_h", "")
            dest_port = int(event.get("id.resp_p", 0) or 0)
            subject = event.get("subject") or ""
            ja3_hash = event.get("ja3") or ""
            ja3s_hash = event.get("ja3s") or ""
            cipher = event.get("cipher") or ""
            cert_fingerprint = event.get("cert_chain_fps") or event.get("sha1") or ""

            cn = self._extract_cn(subject)

            # Skip allowlisted certificate fingerprints
            if cert_fingerprint and cert_fingerprint in CERT_FINGERPRINT_ALLOWLIST:
                continue

            # Rule 1 — Self-signed certificate to external IP
            if self._is_self_signed(event) and self._is_external(dest_ip):
                key = f"self_signed:{dest_ip}:{cn}"
                if self._should_alert(key):
                    findings.append({
                        "type": "self_signed_cert",
                        "severity": Severity.HIGH,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "cn": cn,
                        "details": f"Self-signed certificate to external host {dest_ip} (CN={cn})",
                    })

            # Rule 2 — Expired certificate
            if self._is_expired(event):
                key = f"expired:{dest_ip}:{cn}"
                if self._should_alert(key):
                    findings.append({
                        "type": "expired_cert",
                        "severity": Severity.MEDIUM,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "cn": cn,
                        "details": f"Expired certificate on {dest_ip} (CN={cn})",
                    })

            # Rule 3 — Suspicious CN
            if self._is_suspicious_cn(cn):
                key = f"sus_cn:{dest_ip}:{cn}"
                if self._should_alert(key):
                    findings.append({
                        "type": "suspicious_cn",
                        "severity": Severity.HIGH,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "cn": cn,
                        "details": f"Suspicious certificate CN='{cn}' on {dest_ip}",
                    })

            # Rule 4 — JA3 / JA3S matching known malware
            malware_name = MALWARE_JA3.get(ja3_hash) or MALWARE_JA3S.get(ja3s_hash)
            if malware_name:
                matched_hash = ja3_hash if ja3_hash in MALWARE_JA3 else ja3s_hash
                key = f"ja3:{src_ip}:{matched_hash}"
                if self._should_alert(key):
                    findings.append({
                        "type": "malware_ja3",
                        "severity": Severity.CRITICAL,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "ja3": matched_hash,
                        "malware_family": malware_name,
                        "details": f"JA3 fingerprint matches {malware_name}: {matched_hash} ({src_ip} → {dest_ip})",
                    })

            # Rule 5 — TLS on non-standard port
            if dest_port and dest_port not in STANDARD_TLS_PORTS:
                key = f"nonstandard_port:{src_ip}:{dest_ip}:{dest_port}"
                if self._should_alert(key):
                    findings.append({
                        "type": "tls_nonstandard_port",
                        "severity": Severity.MEDIUM,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "details": f"TLS traffic on non-standard port {dest_port} ({src_ip} → {dest_ip})",
                    })

            # Rule 6 — Weak cipher suite
            if cipher and any(tok in cipher.upper() for tok in WEAK_CIPHER_TOKENS):
                key = f"weak_cipher:{dest_ip}:{cipher}"
                if self._should_alert(key):
                    findings.append({
                        "type": "weak_cipher",
                        "severity": Severity.HIGH,
                        "src_ip": src_ip,
                        "dest_ip": dest_ip,
                        "dest_port": dest_port,
                        "cipher": cipher,
                        "details": f"Weak cipher suite '{cipher}' negotiated with {dest_ip}",
                    })

        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build action list from findings: alert, escalate, log."""
        actions: List[Dict[str, Any]] = []

        for f in findings:
            actions.append({"action": "alert", "data": f})

            # Escalate CRITICAL and HIGH findings
            if f["severity"] >= Severity.HIGH:
                actions.append({"action": "escalate", "data": f})

            # Store finding for forensic timeline
            actions.append({"action": "index_finding", "data": f})

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alert, escalation, and indexing actions."""
        results = {"alerts_sent": 0, "escalations": 0, "findings_indexed": 0}

        for action in actions:
            try:
                if action["action"] == "alert":
                    d = action["data"]
                    self.alerter.send_alert(
                        severity=d["severity"],
                        title=f"TLS Anomaly: {d['type'].replace('_', ' ').title()}",
                        details={
                            "src_ip": d.get("src_ip"),
                            "dest_ip": d.get("dest_ip"),
                            "dest_port": d.get("dest_port"),
                            "info": d["details"],
                        },
                        agent_name=self.name,
                    )
                    results["alerts_sent"] += 1

                elif action["action"] == "escalate":
                    self.report_to_supervisor(action["data"])
                    results["escalations"] += 1

                elif action["action"] == "index_finding":
                    d = action["data"]
                    doc = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent": self.name,
                        "finding_type": d["type"],
                        "severity": d["severity"].name,
                        "src_ip": d.get("src_ip"),
                        "dest_ip": d.get("dest_ip"),
                        "dest_port": d.get("dest_port"),
                        "details": d["details"],
                    }
                    self.os_client.index_document("soc-tls-findings", doc)
                    results["findings_indexed"] += 1

            except Exception as exc:
                logger.error("Action '%s' failed: %s", action.get("action"), exc)

        if results["alerts_sent"]:
            logger.info(
                "TLS cycle: %d alerts, %d escalations, %d indexed",
                results["alerts_sent"], results["escalations"], results["findings_indexed"],
            )

        return results


if __name__ == "__main__":
    agent = TLSInspectionAgent()
    agent.run_loop()
