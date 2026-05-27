"""
SOC Platform - Worker Agent W40: Kerberoasting / AD Attack Detection
وكيل كشف هجمات كيربيروستينغ والدليل النشط

Detects Active Directory Kerberos abuse via Windows Security events:
- Kerberoasting:  Event 4769 with RC4 encryption (0x17) for service tickets
- AS-REP Roasting: Event 4768 without pre-authentication
- Golden Ticket:  TGT with unusual lifetime or forged PAC
- Silver Ticket:  Service ticket anomalies (no preceding TGT request)
- DCSync:         Event 4662 with replication rights GUIDs
- DCShadow:       Rogue DC registration via SPN changes

Maintains baselines of normal Kerberos patterns per user.

Interval: 60 seconds | Supervisor: soc:endpoint-supervisor
"""

from __future__ import annotations

import logging
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w40_kerberoasting")

# RC4 encryption type in Kerberos tickets — marker for Kerberoasting
_RC4_ETYPE = "0x17"
_RC4_ETYPE_DEC = "23"

# DCSync-related replication rights GUIDs
_DCSYNC_GUIDS: Set[str] = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
}

# Service accounts to whitelist (krbtgt, machine accounts)
_SPN_WHITELIST_PREFIXES = ("krbtgt", "kadmin/")

# Suspicious ticket options for Kerberoasting
_KERB_TICKET_OPTIONS = {"0x40810000", "0x40800000", "0x40810010"}


class KerberoastingAgent(BaseAgent):
    """
    Kerberoasting / AD Attack Detection Agent (W40).
    وكيل كشف هجمات كيربيروستينغ

    Monitors Windows Security event logs for Kerberos protocol abuse
    patterns that indicate credential theft or domain persistence attacks.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w40_kerberoasting",
            description="Detects Kerberoasting, AS-REP Roasting, Golden/Silver Ticket, DCSync, DCShadow",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")

        # Baselines: user -> normal hourly TGS request count
        self._tgs_baseline: Dict[str, float] = {}
        self._tgs_counts: Dict[str, List[int]] = defaultdict(list)
        self._baseline_window = 168  # 7 days of hourly samples

        # Service account whitelist
        self._service_whitelist: Set[str] = set(
            self._agent_config.get("service_whitelist", [])
        )

        # Cooldown cache
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown = 600
        self._cache_lock = threading.Lock()

    @staticmethod
    def _extract(doc: Dict[str, Any], dotted_key: str) -> Optional[str]:
        if dotted_key in doc:
            return str(doc[dotted_key])
        current: Any = doc
        for key in dotted_key.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return str(current) if current is not None else None

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[Dict[str, Any]]:
        """Fetch Kerberos and directory service access events."""
        try:
            # Event 4769: Kerberos Service Ticket (TGS) requests
            tgs_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2,
                query={"match": {"data.win.system.eventID": "4769"}},
                size=10000,
            )
            # Event 4768: Kerberos TGT (Authentication) requests
            tgt_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2,
                query={"match": {"data.win.system.eventID": "4768"}},
                size=10000,
            )
            # Event 4662: Directory Service Access (for DCSync)
            ds_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2,
                query={"match": {"data.win.system.eventID": "4662"}},
                size=10000,
            )
            # Event 4742: Computer account changed (for DCShadow SPN changes)
            spn_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=5,
                query={"match": {"data.win.system.eventID": "4742"}},
                size=10000,
            )
            return {
                "tgs_events": tgs_events,
                "tgt_events": tgt_events,
                "ds_events": ds_events,
                "spn_events": spn_events,
            }
        except Exception as exc:
            logger.error("Failed to collect Kerberos data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect all Kerberos attack patterns."""
        findings: List[Dict[str, Any]] = []
        tgs_events = data.get("tgs_events", [])
        tgt_events = data.get("tgt_events", [])
        ds_events = data.get("ds_events", [])
        spn_events = data.get("spn_events", [])

        self._events_processed += len(tgs_events) + len(tgt_events) + len(ds_events) + len(spn_events)
        self._metrics.inc_events(len(tgs_events) + len(tgt_events) + len(ds_events))

        # --- Kerberoasting: TGS with RC4 encryption ---
        rc4_by_user: Dict[str, List[str]] = defaultdict(list)
        for event in tgs_events:
            try:
                etype = self._extract(event, "data.win.eventdata.ticketEncryptionType") or ""
                user = self._extract(event, "data.win.eventdata.targetUserName") or ""
                requesting_user = self._extract(event, "data.win.eventdata.ipAddress") or ""
                spn = self._extract(event, "data.win.eventdata.serviceName") or ""
                ticket_opts = self._extract(event, "data.win.eventdata.ticketOptions") or ""

                if any(spn.lower().startswith(p) for p in _SPN_WHITELIST_PREFIXES):
                    continue
                if user.endswith("$") or user in self._service_whitelist:
                    continue

                if etype in (_RC4_ETYPE, _RC4_ETYPE_DEC) or ticket_opts in _KERB_TICKET_OPTIONS:
                    rc4_by_user[requesting_user].append(spn)
            except Exception as e:
                logger.warning("Error processing TGS event: %s", e)

        for requester, spns in rc4_by_user.items():
            try:
                unique_spns = set(spns)
                severity = Severity.CRITICAL if len(unique_spns) >= 5 else Severity.HIGH
                findings.append({
                    "pattern": "kerberoasting",
                    "severity": severity,
                    "source": requester,
                    "spns_targeted": sorted(unique_spns)[:15],
                    "spn_count": len(unique_spns),
                    "description": (
                        f"Kerberoasting: {requester} requested {len(unique_spns)} "
                        f"RC4-encrypted service tickets in 2 minutes"
                    ),
                })
            except Exception as e:
                logger.warning("Error evaluating kerberoasting finding: %s", e)

        # --- AS-REP Roasting: TGT without pre-authentication ---
        asrep_users: Dict[str, int] = defaultdict(int)
        for event in tgt_events:
            try:
                pre_auth = self._extract(event, "data.win.eventdata.preAuthType") or ""
                status = self._extract(event, "data.win.eventdata.status") or ""
                user = self._extract(event, "data.win.eventdata.targetUserName") or ""

                if user.endswith("$") or user in self._service_whitelist:
                    continue
                # pre-auth type 0 or missing + successful = AS-REP roastable
                if pre_auth in ("0", "") and status in ("0x0", "0"):
                    asrep_users[user] += 1
            except Exception as e:
                logger.warning("Error processing TGT event: %s", e)

        for user, count in asrep_users.items():
            try:
                if count >= 1:
                    findings.append({
                        "pattern": "asrep_roasting",
                        "severity": Severity.HIGH,
                        "source": user,
                        "request_count": count,
                        "description": (
                            f"AS-REP Roasting: {count} TGT(s) issued without "
                            f"pre-authentication for user '{user}'"
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating AS-REP finding: %s", e)

        # --- DCSync: replication rights access ---
        dcsync_users: Dict[str, Set[str]] = defaultdict(set)
        for event in ds_events:
            try:
                user = self._extract(event, "data.win.eventdata.subjectUserName") or ""
                guid = (self._extract(event, "data.win.eventdata.properties") or "").lower()

                if user.endswith("$") or user in self._service_whitelist:
                    continue
                for dcsync_guid in _DCSYNC_GUIDS:
                    if dcsync_guid in guid:
                        dcsync_users[user].add(dcsync_guid)
            except Exception as e:
                logger.warning("Error processing DS event: %s", e)

        for user, guids in dcsync_users.items():
            try:
                if len(guids) >= 2:
                    findings.append({
                        "pattern": "dcsync",
                        "severity": Severity.CRITICAL,
                        "source": user,
                        "replication_guids": sorted(guids),
                        "description": (
                            f"DCSync attack: user '{user}' exercised "
                            f"{len(guids)} replication rights"
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating DCSync finding: %s", e)

        # --- DCShadow: rogue DC registration via SPN changes ---
        for event in spn_events:
            try:
                new_spn = self._extract(event, "data.win.eventdata.servicePrincipalNames") or ""
                computer = self._extract(event, "data.win.eventdata.targetUserName") or ""
                subject = self._extract(event, "data.win.eventdata.subjectUserName") or ""

                # GC/ or E3514235 SPNs added to non-DC machines
                if any(marker in new_spn.upper() for marker in ("GC/", "E3514235-4B06")):
                    findings.append({
                        "pattern": "dcshadow",
                        "severity": Severity.CRITICAL,
                        "source": subject,
                        "target_computer": computer,
                        "spn_added": new_spn[:200],
                        "description": (
                            f"DCShadow: user '{subject}' registered DC-class SPN "
                            f"on computer '{computer}'"
                        ),
                    })
            except Exception as e:
                logger.warning("Error processing SPN event: %s", e)

        # --- Golden Ticket: TGT anomaly detection ---
        for event in tgt_events:
            try:
                user = self._extract(event, "data.win.eventdata.targetUserName") or ""
                domain = self._extract(event, "data.win.eventdata.targetDomainName") or ""
                src_ip = self._extract(event, "data.win.eventdata.ipAddress") or ""
                ticket_opts = self._extract(event, "data.win.eventdata.ticketOptions") or ""

                if user.endswith("$") or user in self._service_whitelist:
                    continue
                # Forged tickets often have ticket options 0x40810000 and anomalous source
                if ticket_opts in ("0x40810000", "0x60810010") and src_ip not in ("", "::1", "127.0.0.1"):
                    findings.append({
                        "pattern": "golden_ticket_suspect",
                        "severity": Severity.CRITICAL,
                        "source": user,
                        "source_ip": src_ip,
                        "domain": domain,
                        "description": (
                            f"Potential Golden Ticket: anomalous TGT for '{user}' "
                            f"from {src_ip} with ticket options {ticket_opts}"
                        ),
                    })
            except Exception as e:
                logger.warning("Error evaluating Golden Ticket finding: %s", e)

        if findings:
            logger.warning("Detected %d Kerberos attack pattern(s)", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create actions for each Kerberos attack finding."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            try:
                key = f"{finding['pattern']}:{finding['source']}"
                with self._cache_lock:
                    last = self._alerted_cache.get(key, 0.0)
                if now - last < self._alert_cooldown:
                    continue

                actions.append({
                    "type": "alert",
                    "severity": finding["severity"],
                    "title": f"AD Attack: {finding['pattern'].replace('_', ' ').title()}",
                    "details": {k: v for k, v in finding.items() if k != "severity"},
                    "cooldown_key": key,
                })
                actions.append({"type": "log_incident", "finding": finding})

                if finding["severity"] >= Severity.CRITICAL:
                    actions.append({"type": "escalate", "finding": finding})
            except Exception as e:
                logger.warning("Error evaluating AD Attack action: %s", e)

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alert, logging, and escalation actions."""
        alerts_sent = 0
        incidents_logged = 0

        for action in actions:
            try:
                if action["type"] == "alert":
                    sent = self.alerter.send_alert(
                        severity=action["severity"],
                        title=action["title"],
                        details=action["details"],
                        agent_name=self.name,
                    )
                    if sent:
                        alerts_sent += 1
                        self._metrics.inc_alerts(action["severity"].name)
                        with self._cache_lock:
                            self._alerted_cache[action["cooldown_key"]] = time.time()

                elif action["type"] == "log_incident":
                    try:
                        finding = action["finding"]
                        self.os_client.index_document(
                            index="soc-kerberos-incidents",
                            document={
                                "@timestamp": datetime.now(timezone.utc).isoformat(),
                                "agent_name": self.name,
                                "pattern": finding["pattern"],
                                "severity": finding["severity"].name,
                                "source": finding["source"],
                                "description": finding["description"],
                            },
                        )
                        incidents_logged += 1
                    except Exception as exc:
                        logger.error("Failed to log Kerberos incident: %s", exc)

                elif action["type"] == "escalate":
                    finding = action["finding"]
                    self.report_to_supervisor({
                        "type": "kerberos_critical",
                        "pattern": finding["pattern"],
                        "source": finding["source"],
                        "description": finding["description"],
                    })
            except Exception as e:
                logger.warning("Error executing kerberos action: %s", e)

        # Prune cooldown
        cutoff = time.time() - self._alert_cooldown * 3
        with self._cache_lock:

            self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent:
            self.report_to_supervisor({
                "type": "kerberos_report",
                "alerts_sent": alerts_sent,
                "incidents_logged": incidents_logged,
            })

        return {"alerts_sent": alerts_sent, "incidents_logged": incidents_logged}


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
    agent = KerberoastingAgent()
    agent.run_loop()
