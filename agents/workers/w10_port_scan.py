"""
W10 - Port Scan Detection Agent
Detects network scanning activity by analyzing Zeek conn.log from OpenSearch.

Detections:
  1. Vertical scan — 1 source → many ports on 1 destination (>20 ports in 1 min)
  2. Horizontal sweep — 1 source → many destinations on same port (>10 hosts in 1 min)
  3. SYN scan — high volume of S0 (unanswered SYN) connection states
  4. Slow/stealth scan — spread connections below threshold but over longer window
  5. Service enumeration — sequential well-known port probes with short connections
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from shared.base_agent import BaseAgent
from shared.alerter import Severity

logger = logging.getLogger("soc.agent.w10_port_scan")

# --- Detection thresholds ---
VERTICAL_SCAN_PORTS = 20        # Unique ports to 1 dest in 1 cycle
HORIZONTAL_SWEEP_HOSTS = 10     # Unique dests on same port in 1 cycle
SYN_SCAN_S0_COUNT = 30          # S0 connections from single source
SLOW_SCAN_PORTS_CUMULATIVE = 50  # Cumulative unique ports over multiple cycles
SERVICE_ENUM_SEQUENTIAL = 8     # Sequential well-known port hits

# Well-known service ports typically probed during enumeration
WELL_KNOWN_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
}


class PortScanAgent(BaseAgent):
    """Detects port scanning and sweep behavior from Zeek connection logs."""

    def __init__(self) -> None:
        super().__init__(
            name="W10_PortScan",
            description="Detects horizontal/vertical scans, SYN scans, stealth scans, and service enumeration",
            interval_seconds=60,
            supervisor_channel="soc:network-supervisor",
        )
        # Slow-scan tracking: src_ip -> {dest_ip -> set(ports)} across cycles
        self._slow_scan_state: Dict[str, Dict[str, Set[int]]] = defaultdict(
            lambda: defaultdict(set)
        )
        # Slow-sweep tracking: src_ip -> {port -> set(dest_ips)}
        self._slow_sweep_state: Dict[str, Dict[int, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self._slow_scan_window = 300  # 5-minute window
        self._slow_scan_timestamps: Dict[str, float] = {}

        # De-duplication: recently alerted scan keys -> timestamp
        self._alerted: Dict[str, float] = {}
        self._alert_cooldown = 300

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _should_alert(self, key: str) -> bool:
        """Cooldown-based de-duplication for scan alerts."""
        now = time.time()
        last = self._alerted.get(key, 0)
        if now - last < self._alert_cooldown:
            return False
        self._alerted[key] = now
        return True

    def _prune_slow_scan_state(self) -> None:
        """Remove slow-scan entries older than the tracking window."""
        now = time.time()
        expired = [
            src for src, ts in self._slow_scan_timestamps.items()
            if now - ts > self._slow_scan_window
        ]
        for src in expired:
            self._slow_scan_state.pop(src, None)
            self._slow_sweep_state.pop(src, None)
            self._slow_scan_timestamps.pop(src, None)

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Zeek conn.log events from the last 1 minute."""
        query = {
            "bool": {
                "must": [
                    {"exists": {"field": "id.orig_h"}},
                    {"exists": {"field": "id.resp_h"}},
                    {"exists": {"field": "id.resp_p"}},
                ],
            }
        }
        try:
            events = self.os_client.get_events_since(
                "zeek-*", minutes=1, query=query, size=10000
            )
            logger.debug("Collected %d connection events", len(events))
            return events
        except Exception as exc:
            logger.error("Failed to collect connection data: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run five scan-detection rules."""
        findings: List[Dict[str, Any]] = []
        if not data:
            return findings

        # --- Per-source aggregations ---
        # src_ip → dest_ip → set(ports)
        src_dest_ports: Dict[str, Dict[str, Set[int]]] = defaultdict(
            lambda: defaultdict(set)
        )
        # src_ip → port → set(dest_ips)
        src_port_dests: Dict[str, Dict[int, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        # src_ip → count of S0 states
        src_syn_count: Dict[str, int] = defaultdict(int)
        # src_ip → conn_states counter
        src_conn_states: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        # src_ip → dest_ip → list(ports) in order for sequential detection
        src_dest_port_list: Dict[str, Dict[str, List[int]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for event in data:
            try:
                src_ip = str(event.get("id.orig_h") or "")
                dest_ip = str(event.get("id.resp_h") or "")

                resp_p_val = event.get("id.resp_p")
                try:
                    dest_port = int(resp_p_val) if resp_p_val is not None else 0
                except (ValueError, TypeError):
                    dest_port = 0

                conn_state = str(event.get("conn_state") or "")
                proto = str(event.get("proto") or "").lower()

                if not src_ip or not dest_ip:
                    continue

                src_dest_ports[src_ip][dest_ip].add(dest_port)
                src_port_dests[src_ip][dest_port].add(dest_ip)
                src_conn_states[src_ip][conn_state] += 1

                # S0 = SYN sent with no reply (classic SYN scan indicator)
                if conn_state == "S0" and proto == "tcp":
                    src_syn_count[src_ip] += 1

                # Track port order for service enumeration
                if dest_port in WELL_KNOWN_PORTS:
                    src_dest_port_list[src_ip][dest_ip].append(dest_port)

                # Feed slow-scan trackers
                self._slow_scan_state[src_ip][dest_ip].add(dest_port)
                self._slow_sweep_state[src_ip][dest_port].add(dest_ip)
                self._slow_scan_timestamps[src_ip] = time.time()

            except Exception as e:
                logger.warning("Error processing scan event: %s", e)

        # --- Rule 1: Vertical scan (many ports on one dest) ---
        for src_ip, dest_map in src_dest_ports.items():
            try:
                for dest_ip, ports in dest_map.items():
                    if len(ports) >= VERTICAL_SCAN_PORTS:
                        key = f"vertical:{src_ip}:{dest_ip}"
                        if self._should_alert(key):
                            findings.append({
                                "type": "vertical_scan",
                                "severity": Severity.HIGH,
                                "src_ip": src_ip,
                                "dest_ip": dest_ip,
                                "unique_ports": len(ports),
                                "sample_ports": sorted(ports)[:20],
                                "details": (
                                    f"Vertical scan: {src_ip} probed {len(ports)} ports "
                                    f"on {dest_ip}"
                                ),
                            })
            except Exception as e:
                logger.warning("Error in Rule 1: %s", e)

        # --- Rule 2: Horizontal sweep (same port, many dests) ---
        for src_ip, port_map in src_port_dests.items():
            try:
                for port, dests in port_map.items():
                    if len(dests) >= HORIZONTAL_SWEEP_HOSTS:
                        key = f"horizontal:{src_ip}:{port}"
                        if self._should_alert(key):
                            findings.append({
                                "type": "horizontal_sweep",
                                "severity": Severity.HIGH,
                                "src_ip": src_ip,
                                "port": port,
                                "unique_hosts": len(dests),
                                "sample_hosts": sorted(dests)[:10],
                                "details": (
                                    f"Horizontal sweep: {src_ip} hit port {port} on "
                                    f"{len(dests)} hosts"
                                ),
                            })
            except Exception as e:
                logger.warning("Error in Rule 2: %s", e)

        # --- Rule 3: SYN scan (high S0 count) ---
        for src_ip, s0_count in src_syn_count.items():
            try:
                if s0_count >= SYN_SCAN_S0_COUNT:
                    key = f"syn_scan:{src_ip}"
                    if self._should_alert(key):
                        rej_count = src_conn_states[src_ip].get("REJ", 0)
                        findings.append({
                            "type": "syn_scan",
                            "severity": Severity.HIGH,
                            "src_ip": src_ip,
                            "s0_connections": s0_count,
                            "rej_connections": rej_count,
                            "conn_states": dict(src_conn_states[src_ip]),
                            "details": (
                                f"SYN scan: {src_ip} sent {s0_count} unanswered SYNs "
                                f"({rej_count} rejected)"
                            ),
                        })
            except Exception as e:
                logger.warning("Error in Rule 3: %s", e)

        # --- Rule 4: Slow/stealth scan (cumulative across cycles) ---
        self._prune_slow_scan_state()
        for src_ip, dest_map in self._slow_scan_state.items():
            try:
                for dest_ip, ports in dest_map.items():
                    if len(ports) >= SLOW_SCAN_PORTS_CUMULATIVE:
                        key = f"slow_scan:{src_ip}:{dest_ip}"
                        if self._should_alert(key):
                            findings.append({
                                "type": "slow_stealth_scan",
                                "severity": Severity.MEDIUM,
                                "src_ip": src_ip,
                                "dest_ip": dest_ip,
                                "unique_ports": len(ports),
                                "details": (
                                    f"Slow scan: {src_ip} probed {len(ports)} ports on "
                                    f"{dest_ip} over 5-min window"
                                ),
                            })
                        # Reset after alerting to avoid repeated triggers
                        dest_map[dest_ip] = set()
            except Exception as e:
                logger.warning("Error in Rule 4: %s", e)

        # --- Rule 4.5: Slow horizontal sweep (cumulative across cycles) ---
        for src_ip, port_map in self._slow_sweep_state.items():
            try:
                for port, dests in port_map.items():
                    if len(dests) >= 30:  # 30 hosts over 5 minutes
                        key = f"slow_sweep:{src_ip}:{port}"
                        if self._should_alert(key):
                            findings.append({
                                "type": "slow_stealth_sweep",
                                "severity": Severity.MEDIUM,
                                "src_ip": src_ip,
                                "port": port,
                                "unique_hosts": len(dests),
                                "details": (
                                    f"Slow horizontal sweep: {src_ip} hit port {port} on "
                                    f"{len(dests)} hosts over 5-min window"
                                ),
                            })
                        # Reset after alerting to avoid repeated triggers
                        port_map[port] = set()
            except Exception as e:
                logger.warning("Error in Rule 4.5: %s", e)

        # --- Rule 5: Service enumeration (sequential well-known ports) ---
        for src_ip, dest_map in src_dest_port_list.items():
            try:
                for dest_ip, port_seq in dest_map.items():
                    unique_wk = set(port_seq)
                    if len(unique_wk) >= SERVICE_ENUM_SEQUENTIAL:
                        key = f"svc_enum:{src_ip}:{dest_ip}"
                        if self._should_alert(key):
                            findings.append({
                                "type": "service_enumeration",
                                "severity": Severity.MEDIUM,
                                "src_ip": src_ip,
                                "dest_ip": dest_ip,
                                "services_probed": sorted(unique_wk),
                                "details": (
                                    f"Service enumeration: {src_ip} probed "
                                    f"{len(unique_wk)} well-known ports on {dest_ip}"
                                ),
                            })
            except Exception as e:
                logger.warning("Error in Rule 5: %s", e)

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build action list from scan findings."""
        actions: List[Dict[str, Any]] = []

        for f in findings:
            actions.append({"action": "alert", "data": f})

            # Escalate HIGH and CRITICAL
            if f["severity"] >= Severity.HIGH:
                actions.append({"action": "escalate", "data": f})

            # Request firewall block for confirmed SYN scans
            if f["type"] == "syn_scan" and f.get("s0_connections", 0) > SYN_SCAN_S0_COUNT * 2:
                actions.append({
                    "action": "block_source",
                    "src_ip": f["src_ip"],
                    "scan_type": f["type"],
                })

            # Always index for forensics
            actions.append({"action": "index_finding", "data": f})

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alerts, escalations, block requests, and indexing."""
        results = {"alerts_sent": 0, "escalations": 0, "blocks": 0, "indexed": 0}

        for action in actions:
            try:
                if action["action"] == "alert":
                    d = action["data"]
                    sent = self.alerter.send_alert(
                        severity=d["severity"],
                        title=f"Port Scan: {d['type'].replace('_', ' ').title()}",
                        details={
                            "src_ip": d.get("src_ip"),
                            "dest_ip": d.get("dest_ip", "multiple"),
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
                        "action": "firewall-block",
                        "src_ip": action["src_ip"],
                        "scan_type": action["scan_type"],
                        "status": "requested",
                    }
                    self.os_client.index_document("soc-active-response", doc)
                    logger.warning(
                        "Block requested for scanner %s (%s)",
                        action["src_ip"], action["scan_type"],
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
                        "dest_ip": d.get("dest_ip", "multiple"),
                        "details": d["details"],
                    }
                    self.os_client.index_document("soc-scan-findings", doc)
                    results["indexed"] += 1

            except Exception as exc:
                logger.error("Action '%s' failed: %s", action.get("action"), exc)

        if results["alerts_sent"]:
            logger.info(
                "Scan cycle: %d alerts, %d escalations, %d blocks, %d indexed",
                results["alerts_sent"], results["escalations"],
                results["blocks"], results["indexed"],
            )

        return results


if __name__ == "__main__":
    agent = PortScanAgent()
    agent.run_loop()
