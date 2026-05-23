"""
SOC Platform - Worker Agent W39: Lateral Movement Detection
وكيل كشف الحركة الجانبية

Detects attackers moving between internal hosts:
- One user authenticating to many hosts quickly (>5 in 10 min)
- PsExec-like activity (SMB + service creation on remote host)
- WMI remote execution (Event 4688 + wmic.exe remote)
- RDP to new/unusual hosts (Event 4624 type 10)
- Pass-the-hash (Event 4624 logon type 9 / NTLM + admin)
- SSH pivoting (internal→internal SSH connections via Zeek)

Tracks an authentication graph: user → set of hosts accessed.

Interval: 60 seconds | Supervisor: soc:endpoint-supervisor
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w39_lateral_movement")

# Thresholds
_MULTI_HOST_THRESHOLD = 5          # hosts in window → alert
_MULTI_HOST_WINDOW_S = 600         # 10 minutes
_ADMIN_SHARES = {"IPC$", "C$", "ADMIN$", "D$"}
_PSEXEC_SERVICE_NAMES = {"psexesvc", "paexec", "remcomsvc", "csexec"}
_SSH_PORT = 22
_RDP_PORT = 3389
_WMI_PORTS = {135, 5985, 5986}

# RFC-1918 check
def _is_internal(ip: str) -> bool:
    """Return True if the IP belongs to a private RFC-1918 range."""
    if not ip or ip in ("-", "::1", "127.0.0.1"):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168))


class LateralMovementAgent(BaseAgent):
    """
    Lateral Movement Detection Agent (W39).
    وكيل كشف الحركة الجانبية

    Monitors authentication logs and network connections to detect
    attackers pivoting between internal hosts.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w39_lateral_movement",
            description="Detects lateral movement: PtH, PsExec, WMI, RDP, SSH pivoting",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )
        self._alert_index = self._agent_config.get("alert_index", "wazuh-alerts-*")
        self._zeek_index = self._agent_config.get("zeek_index", "filebeat-zeek-*")

        # Auth graph: user -> {(host, timestamp), ...}  — sliding window
        self._auth_graph: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        # Known RDP destinations per user (baseline)
        self._known_rdp: Dict[str, Set[str]] = defaultdict(set)

        # Cooldown
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown = 300

    @staticmethod
    def _extract(doc: Dict[str, Any], dotted_key: str) -> Optional[str]:
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
        """Fetch authentication, service creation, and network events."""
        try:
            # Event 4624: Logon Success (types 3, 9, 10)
            logon_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2,
                query={"match": {"data.win.system.eventID": "4624"}},
                size=5000,
            )
            # Event 4697: Service installed (PsExec marker)
            service_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2,
                query={"match": {"data.win.system.eventID": "4697"}},
                size=1000,
            )
            # Event 4688: New process (WMI remote)
            process_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2,
                query={"match": {"data.win.system.eventID": "4688"}},
                size=2000,
            )
            # Event 5140: Network share access
            share_events = self.os_client.get_events_since(
                index=self._alert_index, minutes=2,
                query={"match": {"data.win.system.eventID": "5140"}},
                size=2000,
            )
            # Zeek conn.log: internal-to-internal SSH/RDP
            zeek_conn = self.os_client.get_events_since(
                index=self._zeek_index, minutes=2,
                query={"bool": {"must": [
                    {"terms": {"id.resp_p": [_SSH_PORT, _RDP_PORT]}},
                ]}},
                size=3000,
            )
            return {
                "logon_events": logon_events,
                "service_events": service_events,
                "process_events": process_events,
                "share_events": share_events,
                "zeek_conn": zeek_conn,
            }
        except Exception as exc:
            logger.error("Failed to collect lateral movement data: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect lateral movement patterns in collected data."""
        findings: List[Dict[str, Any]] = []
        logon_events = data.get("logon_events", [])
        service_events = data.get("service_events", [])
        process_events = data.get("process_events", [])
        share_events = data.get("share_events", [])
        zeek_conn = data.get("zeek_conn", [])

        total = (len(logon_events) + len(service_events) +
                 len(process_events) + len(share_events) + len(zeek_conn))
        self._events_processed += total
        self._metrics.inc_events(total)

        now = time.time()

        # --- Pass-the-Hash & RDP & Multi-host from 4624 ---
        for event in logon_events:
            user = self._extract(event, "data.win.eventdata.targetUserName") or ""
            src_ip = self._extract(event, "data.win.eventdata.ipAddress") or ""
            dst_host = self._extract(event, "data.win.eventdata.workstationName") or ""
            logon_type = self._extract(event, "data.win.eventdata.logonType") or ""
            auth_pkg = (self._extract(event, "data.win.eventdata.authenticationPackageName") or "").upper()
            logon_proc = (self._extract(event, "data.win.eventdata.logonProcessName") or "").upper()

            if not user or user.endswith("$"):
                continue

            target = dst_host or src_ip

            # Pass-the-Hash: logon type 9 (NewCredentials) or NTLM network logon
            if logon_type == "9":
                findings.append({
                    "pattern": "pass_the_hash",
                    "severity": Severity.HIGH,
                    "user": user,
                    "source_ip": src_ip,
                    "target_host": target,
                    "logon_type": logon_type,
                    "description": (
                        f"Pass-the-Hash: user '{user}' logon type 9 "
                        f"from {src_ip} to {target}"
                    ),
                })

            # NTLM network logon with seclogo (common PtH indicator)
            if (logon_type == "3" and auth_pkg == "NTLM"
                    and logon_proc == "SECLOGO" and _is_internal(src_ip)):
                findings.append({
                    "pattern": "ntlm_relay_suspect",
                    "severity": Severity.MEDIUM,
                    "user": user,
                    "source_ip": src_ip,
                    "target_host": target,
                    "description": (
                        f"NTLM relay suspect: '{user}' network logon via "
                        f"SECLOGO from internal {src_ip}"
                    ),
                })

            # RDP to new host
            if logon_type == "10" and _is_internal(src_ip):
                if target and target not in self._known_rdp[user]:
                    findings.append({
                        "pattern": "rdp_new_host",
                        "severity": Severity.MEDIUM,
                        "user": user,
                        "source_ip": src_ip,
                        "target_host": target,
                        "description": (
                            f"RDP to new host: '{user}' from {src_ip} to "
                            f"previously unseen host '{target}'"
                        ),
                    })
                self._known_rdp[user].add(target)

            # Multi-host auth tracking
            if logon_type in ("3", "10") and _is_internal(src_ip) and target:
                self._auth_graph[user].append((target, now))

        # Prune auth graph and check multi-host threshold
        for user in list(self._auth_graph.keys()):
            self._auth_graph[user] = [
                (h, t) for h, t in self._auth_graph[user]
                if now - t < _MULTI_HOST_WINDOW_S
            ]
            unique_hosts = {h for h, _ in self._auth_graph[user]}
            if len(unique_hosts) >= _MULTI_HOST_THRESHOLD:
                findings.append({
                    "pattern": "multi_host_auth",
                    "severity": Severity.HIGH,
                    "user": user,
                    "host_count": len(unique_hosts),
                    "hosts": sorted(unique_hosts)[:15],
                    "description": (
                        f"Rapid multi-host auth: '{user}' authenticated to "
                        f"{len(unique_hosts)} hosts in {_MULTI_HOST_WINDOW_S // 60} min"
                    ),
                })
                self._auth_graph[user] = []  # reset after alert

        # --- PsExec-like: admin share + service creation ---
        share_users: Dict[str, Set[str]] = defaultdict(set)
        for event in share_events:
            user = self._extract(event, "data.win.eventdata.subjectUserName") or ""
            share_name = (self._extract(event, "data.win.eventdata.shareName") or "").upper()
            src_ip = self._extract(event, "data.win.eventdata.ipAddress") or ""
            if user and not user.endswith("$"):
                for admin_share in _ADMIN_SHARES:
                    if admin_share.upper() in share_name:
                        share_users[user].add(src_ip or "unknown")

        service_users: Set[str] = set()
        for event in service_events:
            user = self._extract(event, "data.win.eventdata.subjectUserName") or ""
            svc_name = (self._extract(event, "data.win.eventdata.serviceName") or "").lower()
            if user and not user.endswith("$"):
                if any(ps in svc_name for ps in _PSEXEC_SERVICE_NAMES) or svc_name:
                    service_users.add(user)

        for user in share_users.keys() & service_users:
            findings.append({
                "pattern": "psexec_like",
                "severity": Severity.HIGH,
                "user": user,
                "admin_share_sources": sorted(share_users[user])[:10],
                "description": (
                    f"PsExec-like: '{user}' accessed admin shares and "
                    f"installed service within 2-min window"
                ),
            })

        # --- WMI remote execution ---
        for event in process_events:
            user = self._extract(event, "data.win.eventdata.subjectUserName") or ""
            proc_name = (self._extract(event, "data.win.eventdata.newProcessName") or "").lower()
            cmd_line = (self._extract(event, "data.win.eventdata.commandLine") or "").lower()

            if not user or user.endswith("$"):
                continue
            if "wmiprvse.exe" in proc_name or ("wmic" in cmd_line and "/node:" in cmd_line):
                findings.append({
                    "pattern": "wmi_remote",
                    "severity": Severity.MEDIUM,
                    "user": user,
                    "process": proc_name,
                    "command_line": cmd_line[:300],
                    "description": (
                        f"WMI remote execution: '{user}' spawned WMI process"
                    ),
                })

        # --- SSH pivoting from Zeek ---
        ssh_pivots: Dict[str, Set[str]] = defaultdict(set)
        for event in zeek_conn:
            src_ip = self._extract(event, "id.orig_h") or self._extract(event, "source.ip") or ""
            dst_ip = self._extract(event, "id.resp_h") or self._extract(event, "destination.ip") or ""
            dst_port = self._extract(event, "id.resp_p") or self._extract(event, "destination.port") or ""

            if str(dst_port) == str(_SSH_PORT) and _is_internal(src_ip) and _is_internal(dst_ip):
                ssh_pivots[src_ip].add(dst_ip)

        for src, dests in ssh_pivots.items():
            if len(dests) >= 3:
                findings.append({
                    "pattern": "ssh_pivoting",
                    "severity": Severity.HIGH,
                    "source_ip": src,
                    "destinations": sorted(dests)[:15],
                    "dest_count": len(dests),
                    "description": (
                        f"SSH pivoting: {src} connected to {len(dests)} "
                        f"internal hosts via SSH"
                    ),
                })

        if findings:
            logger.warning("Detected %d lateral movement pattern(s)", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create actions for lateral movement findings."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            actor = finding.get("user", finding.get("source_ip", "unknown"))
            key = f"{finding['pattern']}:{actor}"
            last = self._alerted_cache.get(key, 0.0)
            if now - last < self._alert_cooldown:
                continue

            actions.append({
                "type": "alert",
                "severity": finding["severity"],
                "title": f"Lateral Movement: {finding['pattern'].replace('_', ' ').title()}",
                "details": {k: v for k, v in finding.items() if k != "severity"},
                "cooldown_key": key,
            })
            actions.append({"type": "log_incident", "finding": finding})

            if finding["severity"] >= Severity.CRITICAL:
                actions.append({"type": "escalate", "finding": finding})

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alert, logging, and escalation actions."""
        alerts_sent = 0
        incidents_logged = 0

        for action in actions:
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
                    self._alerted_cache[action["cooldown_key"]] = time.time()

            elif action["type"] == "log_incident":
                try:
                    finding = action["finding"]
                    self.os_client.index_document(
                        index="soc-lateral-movement-incidents",
                        document={
                            "@timestamp": datetime.now(timezone.utc).isoformat(),
                            "agent_name": self.name,
                            "pattern": finding["pattern"],
                            "severity": finding["severity"].name,
                            "user": finding.get("user", ""),
                            "source_ip": finding.get("source_ip", ""),
                            "description": finding["description"],
                        },
                    )
                    incidents_logged += 1
                except Exception as exc:
                    logger.error("Failed to log lateral movement incident: %s", exc)

            elif action["type"] == "escalate":
                finding = action["finding"]
                self.report_to_supervisor({
                    "type": "lateral_movement_critical",
                    "pattern": finding["pattern"],
                    "user": finding.get("user", ""),
                    "description": finding["description"],
                })

        # Prune cooldown
        cutoff = time.time() - self._alert_cooldown * 3
        self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent:
            self.report_to_supervisor({
                "type": "lateral_movement_report",
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
    agent = LateralMovementAgent()
    agent.run_loop()
