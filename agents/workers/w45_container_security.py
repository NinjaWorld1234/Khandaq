"""
SOC Platform - Worker Agent W45: Container Security Monitor
وكيل مراقبة أمن الحاويات

Detects container security threats from Wazuh and system logs:
- Privileged container launched (--privileged)
- Container with host network (--net=host)
- Container mounting sensitive paths (/etc, /var/run/docker.sock)
- Container escape attempts (accessing host PID namespace)
- Image from untrusted registry
- Container running as root
- Unusual container resource usage
- New container images pulled

Interval: 60 seconds
"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w45_container_security")

# Paths that should never be mounted into containers
_SENSITIVE_MOUNTS = {
    "/var/run/docker.sock", "/etc/shadow", "/etc/passwd",
    "/root", "/etc/kubernetes", "/var/lib/kubelet",
    "/proc/sysrq-trigger", "/sys/fs/cgroup", "/dev",
}

# Trusted container registries (everything else is suspicious)
_TRUSTED_REGISTRIES = {
    "docker.io", "gcr.io", "ghcr.io", "registry.k8s.io",
    "quay.io", "mcr.microsoft.com", "public.ecr.aws",
}

# Patterns indicating escape attempts
_ESCAPE_PATTERNS = re.compile(
    r"(nsenter|--pid\s+host|/proc/1/root|/proc/1/ns|"
    r"chroot\s+/host|mount\s+--bind\s+/proc|capsh\s+--print)",
    re.IGNORECASE,
)


class ContainerSecurityAgent(BaseAgent):
    """
    Container Security Monitor (W45).
    Monitors Docker/container events for security violations.
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w45_container_security",
            description="Monitors Docker/container environments for security threats",
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:infra-supervisor",
        )

        # Configurable thresholds
        self._cpu_threshold: float = self._agent_config.get("cpu_threshold_pct", 90.0)
        self._mem_threshold: float = self._agent_config.get("mem_threshold_pct", 85.0)

        # State: known container images (baseline)
        self._known_images: Set[str] = set(self._agent_config.get("known_images", []))
        self._seen_images: Set[str] = set()

        # Cooldown cache for deduplication
        self._alerted_cache: Dict[str, float] = {}
        self._alert_cooldown: int = 600
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self) -> Optional[List[Dict[str, Any]]]:
        """Fetch Docker/container events from Wazuh alerts and system logs."""
        query = {
            "bool": {
                "should": [
                    {"match": {"rule.groups": "docker"}},
                    {"match": {"rule.groups": "container"}},
                    {"match_phrase": {"data.title": "docker"}},
                    {"match": {"rule.id": "87924"}},  # Wazuh Docker listener
                    {"match": {"rule.id": "87903"}},  # Docker container action
                    {"match": {"predecoder.program_name": "dockerd"}},
                ],
                "minimum_should_match": 1,
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*", minutes=2, query=query, size=10000,
            )
        except Exception as exc:
            logger.error("Failed to collect container events: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze container events for security violations."""
        findings: List[Dict[str, Any]] = []

        for event in data:
            try:
                agent_name = (event.get("agent") or {}).get("name", "unknown-host")
                data_dict = event.get("data") or {}
                docker_dict = data_dict.get("docker") or {}
                
                full_log = event.get("full_log", data_dict.get("log", ""))
                docker_action = docker_dict.get("Action", "")
                
                container_attrs = (docker_dict.get("Actor") or {}).get("Attributes") or {}
                container_name = container_attrs.get("name", "unknown")
                image = container_attrs.get("image", docker_dict.get("from", ""))
                command = data_dict.get("command", full_log)

                # Rule 1: Privileged container
                if "--privileged" in str(full_log) or container_attrs.get("privileged") == "true":
                    findings.append({
                        "rule": "privileged_container",
                        "severity": Severity.CRITICAL,
                        "host": agent_name,
                        "container": container_name,
                        "image": image,
                        "description": f"Privileged container '{container_name}' launched on {agent_name}",
                    })

                # Rule 2: Host network mode
                if "--net=host" in str(full_log) or "--network=host" in str(full_log):
                    findings.append({
                        "rule": "host_network",
                        "severity": Severity.HIGH,
                        "host": agent_name,
                        "container": container_name,
                        "image": image,
                        "description": f"Container '{container_name}' launched with host network on {agent_name}",
                    })

                # Rule 3: Sensitive path mounts
                log_str = str(full_log)
                for mount_path in _SENSITIVE_MOUNTS:
                    if mount_path in log_str:
                        findings.append({
                            "rule": "sensitive_mount",
                            "severity": Severity.CRITICAL,
                            "host": agent_name,
                            "container": container_name,
                            "mount_path": mount_path,
                            "image": image,
                            "description": f"Container '{container_name}' mounts sensitive path {mount_path}",
                        })
                        break  # One finding per event is enough

                # Rule 4: Container escape attempts
                if _ESCAPE_PATTERNS.search(str(command)):
                    findings.append({
                        "rule": "container_escape_attempt",
                        "severity": Severity.CRITICAL,
                        "host": agent_name,
                        "container": container_name,
                        "command": str(command)[:200],
                        "description": f"Possible container escape attempt in '{container_name}' on {agent_name}",
                    })

                # Rule 5: Untrusted registry
                if docker_action in ("pull", "create", "start") and image:
                    registry = image.split("/")[0] if "/" in image else "docker.io"
                    if "." in registry and registry not in _TRUSTED_REGISTRIES:
                        findings.append({
                            "rule": "untrusted_registry",
                            "severity": Severity.HIGH,
                            "host": agent_name,
                            "image": image,
                            "registry": registry,
                            "description": f"Image from untrusted registry '{registry}': {image}",
                        })

                # Rule 6: Container running as root
                user = container_attrs.get("user", "")
                if docker_action in ("start", "create") and (user == "root" or user == "0" or user == ""):
                    # Empty user defaults to root in Docker
                    if docker_action == "start":
                        findings.append({
                            "rule": "root_container",
                            "severity": Severity.MEDIUM,
                            "host": agent_name,
                            "container": container_name,
                            "image": image,
                            "description": f"Container '{container_name}' running as root on {agent_name}",
                        })

                # Rule 7: New image pulled
                if docker_action == "pull" and image:
                    if image not in self._known_images and image not in self._seen_images:
                        findings.append({
                            "rule": "new_image_pulled",
                            "severity": Severity.LOW,
                            "host": agent_name,
                            "image": image,
                            "description": f"New container image pulled: {image} on {agent_name}",
                        })
                        self._seen_images.add(image)
            except Exception as e:
                logger.warning("Error processing container event: %s", e)

        # Rule 8: Query container resource usage stats
        findings.extend(self._check_resource_usage())

        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    def _check_resource_usage(self) -> List[Dict[str, Any]]:
        """Check for containers with unusually high CPU/memory usage."""
        findings: List[Dict[str, Any]] = []
        query = {
            "bool": {
                "must": [
                    {"match": {"rule.groups": "docker"}},
                    {"exists": {"field": "data.docker.cpu_pct"}},
                ],
            }
        }
        try:
            stats = self.os_client.get_events_since(
                index="wazuh-alerts-*", minutes=2, query=query, size=10000,
            )
            for stat in stats:
                try:
                    data_dict = stat.get("data") or {}
                    docker_data = data_dict.get("docker") or {}
                    cpu_pct = float(docker_data.get("cpu_pct", 0))
                    mem_pct = float(docker_data.get("mem_pct", 0))
                    container = docker_data.get("name", "unknown")
                    host = (stat.get("agent") or {}).get("name", "unknown-host")

                    if cpu_pct > self._cpu_threshold or mem_pct > self._mem_threshold:
                        findings.append({
                            "rule": "unusual_resource_usage",
                            "severity": Severity.MEDIUM,
                            "host": host,
                            "container": container,
                            "cpu_pct": cpu_pct,
                            "mem_pct": mem_pct,
                            "description": (
                                f"Container '{container}' high resource usage: "
                                f"CPU={cpu_pct:.1f}% MEM={mem_pct:.1f}%"
                            ),
                        })
                except Exception as e:
                    logger.warning("Error evaluating resource usage: %s", e)
        except Exception as exc:
            logger.debug("Resource usage check skipped: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Decide
    # ------------------------------------------------------------------

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Determine actions with cooldown deduplication."""
        actions: List[Dict[str, Any]] = []
        now = time.time()

        for finding in findings:
            try:
                alert_key = f"{finding['rule']}:{finding.get('container', finding.get('image', ''))}"
                with self._cache_lock:
                    last = self._alerted_cache.get(alert_key, 0.0)
                if now - last < self._alert_cooldown:
                    continue

                actions.append({
                    "type": "alert",
                    "severity": finding["severity"],
                    "title": f"Container Security: {finding['rule'].replace('_', ' ').title()}",
                    "details": {k: v for k, v in finding.items() if k != "severity"},
                    "alert_key": alert_key,
                })

                if finding["severity"] >= Severity.HIGH:
                    actions.append({"type": "escalate", "finding": finding})

                actions.append({"type": "log_incident", "finding": finding})
            except Exception as e:
                logger.warning("Error evaluating container finding action: %s", e)

        return actions

    # ------------------------------------------------------------------
    # Act
    # ------------------------------------------------------------------

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute alert, escalation, and logging actions."""
        alerts_sent = 0
        escalations = 0
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
                            self._alerted_cache[action["alert_key"]] = time.time()

                elif action["type"] == "escalate":
                    self.report_to_supervisor({
                        "type": "container_security_escalation",
                        **action["finding"],
                    })
                    escalations += 1

                elif action["type"] == "log_incident":
                    try:
                        finding = action["finding"]
                        self.os_client.index_document(
                            index="soc-container-security-incidents",
                            document={
                                "@timestamp": datetime.now(timezone.utc).isoformat(),
                                "agent_name": self.name,
                                "rule": finding["rule"],
                                "severity": finding["severity"].name,
                                "host": finding.get("host"),
                                "container": finding.get("container"),
                                "image": finding.get("image"),
                                "description": finding["description"],
                            },
                        )
                        incidents_logged += 1
                    except Exception as exc:
                        logger.error("Failed to log container incident: %s", exc)
            except Exception as e:
                logger.warning("Error executing container security action: %s", e)

        # Prune expired cooldown entries
        cutoff = time.time() - self._alert_cooldown * 2
        with self._cache_lock:

            self._alerted_cache = {k: v for k, v in self._alerted_cache.items() if v > cutoff}

        if alerts_sent:
            self.report_to_supervisor({
                "type": "container_security_summary",
                "alerts_sent": alerts_sent,
                "escalations": escalations,
                "incidents_logged": incidents_logged,
            })

        return {"alerts_sent": alerts_sent, "escalations": escalations, "incidents_logged": incidents_logged}


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
    agent = ContainerSecurityAgent()
    agent.run_loop()
