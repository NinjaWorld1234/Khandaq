# SOC Platform - Worker Agent W36: Canary Tokens
# وكيل رموز الطُعم - ملفات وبيانات اعتماد مزيفة للكشف عن المتسللين
"""
Canary Tokens Agent
===================

Manages decoy files and credentials planted across the network to detect
unauthorized access and lateral movement:

- **Fake credential files**: ``passwords_backup.docx``, ``admin_creds.txt``
- **Fake database dumps**: ``customer_db_backup.sql``
- **Fake SSH keys**: ``id_rsa_admin``
- **Fake AWS credentials**: ``~/.aws/credentials``

Monitors access to these files via Wazuh FIM (File Integrity Monitoring).
**Any read/open/modify of a canary token = CRITICAL alert** – someone is
actively snooping for credentials or exfiltrating data.

Each canary token contains a unique identifier (UUID) so the SOC can
pinpoint exactly which token was accessed, by whom, and from where.

Interval: 30 seconds
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
import uuid
from typing import Any, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.agent.w36_canary_tokens")

# ---------------------------------------------------------------------------
# Constants / ثوابت
# ---------------------------------------------------------------------------

WAZUH_ALERTS_INDEX = "wazuh-alerts-*"
FIM_RULE_GROUP = "syscheck"

# Default canary token definitions / تعريفات رموز الطُعم الافتراضية
DEFAULT_CANARY_TOKENS: list[dict[str, str]] = [
    {
        "filename": "passwords_backup.docx.txt",
        "deploy_dir": "/app/docker/tarpit/honeyfs/IT",
        "description": "Fake password backup file",
        "content_template": (
            "=== CONFIDENTIAL - IT Password Backup ===\n"
            "Last updated: {date}\n\n"
            "Domain Admin: administrator / {token}\n"
            "Database root: root / {token}\n"
            "VPN admin: vpnadmin / {token}\n"
            "Firewall: admin / {token}\n\n"
            "DO NOT SHARE THIS FILE\n"
            "Token: {token_id}\n"
        ),
        "mitre_technique": "T1552.001 - Credentials In Files",
    },
    {
        "filename": "admin_creds.txt",
        "deploy_dir": "/app/docker/tarpit/honeyfs/Desktop",
        "description": "Fake admin credentials file",
        "content_template": (
            "# Admin Credentials - KEEP SAFE\n"
            "# Updated: {date}\n\n"
            "ssh root@10.0.1.1  # password: {token}\n"
            "ssh admin@10.0.1.5  # password: {token}\n"
            "mysql -u root -p{token} -h db.internal\n"
            "# Token: {token_id}\n"
        ),
        "mitre_technique": "T1552.001 - Credentials In Files",
    },
    {
        "filename": "customer_db_backup.sql",
        "deploy_dir": "/app/docker/tarpit/honeyfs/backups",
        "description": "Fake database dump file",
        "content_template": (
            "-- MySQL dump: customer_production\n"
            "-- Generated: {date}\n"
            "-- Token: {token_id}\n\n"
            "CREATE DATABASE IF NOT EXISTS customer_prod;\n"
            "USE customer_prod;\n\n"
            "CREATE TABLE users (\n"
            "  id INT PRIMARY KEY AUTO_INCREMENT,\n"
            "  email VARCHAR(255),\n"
            "  password_hash VARCHAR(255),\n"
            "  api_key VARCHAR(64)\n"
            ");\n\n"
            "INSERT INTO users VALUES\n"
            "(1, 'admin@company.com', '$2b$12${token}', '{token}'),\n"
            "(2, 'ceo@company.com', '$2b$12${token}', '{token}');\n"
        ),
        "mitre_technique": "T1005 - Data from Local System",
    },
    {
        "filename": "id_rsa_admin",
        "deploy_dir": "/app/docker/tarpit/honeyfs/keys",
        "description": "Fake SSH private key",
        "content_template": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            "QyNTUxOQAAACBSOC1DQU5BUlktVE9LRU4te token_id}AAAAAAAAAAAAAAA==\n"
            "CANARY-TOKEN-{token_id}-DO-NOT-USE\n"
            "{token}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
        "mitre_technique": "T1552.004 - Private Keys",
    },
    {
        "filename": "credentials",
        "deploy_dir": "/app/docker/tarpit/honeyfs/.aws",
        "description": "Fake AWS credentials file",
        "content_template": (
            "[default]\n"
            "aws_access_key_id = AKIA{token_short}\n"
            "aws_secret_access_key = {token}\n"
            "region = us-east-1\n\n"
            "[production]\n"
            "aws_access_key_id = AKIA{token_short}\n"
            "aws_secret_access_key = {token}\n"
            "region = eu-west-1\n"
            "# Token: {token_id}\n"
        ),
        "mitre_technique": "T1552.001 - Credentials In Files",
    },
]


class CanaryTokensAgent(BaseAgent):
    """
    Canary Tokens Agent – deploys and monitors decoy files/credentials.
    وكيل رموز الطُعم – ينشر ويراقب الملفات والبيانات المزيفة
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w36_canary_tokens",
            description="Canary Tokens Agent – decoy files and credentials for intrusion detection",
            interval_seconds=30,
            config=config,
            supervisor_channel="soc:detection-supervisor",
        )

        # Token registry: maps file path → token metadata
        # سجل الرموز: يربط مسار الملف → بيانات الرمز
        self.token_registry: dict[str, dict[str, Any]] = {}

        # Token definitions from config or defaults
        self.token_definitions: list[dict[str, str]] = self._agent_config.get(
            "tokens", DEFAULT_CANARY_TOKENS,
        )

        # Set of already-alerted event IDs (de-duplication within session)
        self._alerted_event_ids: set[str] = set()

    # ------------------------------------------------------------------
    # Token deployment / نشر رموز الطُعم
    # ------------------------------------------------------------------
    def deploy_canary_tokens(self) -> dict[str, dict[str, Any]]:
        """
        Create all canary token files on the filesystem.

        Each token gets a unique UUID embedded in its content so that
        when triggered, we know exactly which file was compromised.

        Returns:
            dict mapping file path → token metadata.
        """
        registry: dict[str, dict[str, Any]] = {}

        for token_def in self.token_definitions:
            deploy_dir = token_def.get("deploy_dir", "/tmp")
            filename = token_def.get("filename", "canary.txt")
            description = token_def.get("description", "Canary token")
            content_template = token_def.get("content_template", "CANARY {token_id}")
            mitre_technique = token_def.get("mitre_technique", "T1552")

            if not os.path.isdir(deploy_dir):
                logger.debug("Deploy dir does not exist, skipping: %s", deploy_dir)
                continue

            file_path = os.path.join(deploy_dir, filename)
            token_id = str(uuid.uuid4())
            fake_password = hashlib.sha256(token_id.encode()).hexdigest()[:24]
            token_short = hashlib.sha256(token_id.encode()).hexdigest()[:16].upper()

            content = content_template.format(
                date=datetime.datetime.now(datetime.timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                ),
                token=fake_password,
                token_id=token_id,
                token_short=token_short,
            )

            try:
                os.makedirs(deploy_dir, exist_ok=True)
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(content)

                content_hash = hashlib.sha256(content.encode()).hexdigest()
                registry[file_path] = {
                    "token_id": token_id,
                    "filename": filename,
                    "description": description,
                    "content_hash": content_hash,
                    "deploy_dir": deploy_dir,
                    "deployed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "mitre_technique": mitre_technique,
                }
                logger.info("🍯 Canary token deployed: %s (token=%s)", file_path, token_id[:8])

            except PermissionError:
                logger.warning("Permission denied deploying token: %s", file_path)
            except OSError as exc:
                logger.error("Failed to deploy token %s: %s", file_path, exc)

        self.token_registry = registry
        logger.info("Token deployment complete – %d tokens active", len(registry))
        return registry

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> dict[str, Any]:
        """Collect FIM events for canary token files from OpenSearch."""
        if not self.token_registry:
            self.deploy_canary_tokens()

        data: dict[str, Any] = {"fim_events": [], "missing_tokens": []}
        token_paths = list(self.token_registry.keys())

        if token_paths:
            try:
                fim_query = {
                    "bool": {
                        "must": [
                            {"term": {"rule.groups": FIM_RULE_GROUP}},
                            {"terms": {"syscheck.path": token_paths}},
                        ]
                    }
                }
                data["fim_events"] = self.os_client.get_events_since(
                    index=WAZUH_ALERTS_INDEX, minutes=1, query=fim_query, size=10000,
                )
            except Exception as exc:
                logger.error("Token FIM query failed: %s", exc)

        # Check for deleted token files (integrity check)
        for file_path in token_paths:
            if not os.path.exists(file_path):
                data["missing_tokens"].append(file_path)

        return data

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: Any) -> list[dict[str, Any]]:
        """Analyze FIM events for canary token access indicators."""
        findings: list[dict[str, Any]] = []

        for event in data.get("fim_events", []):
            try:
                event_id = event.get("id", event.get("_id", str(uuid.uuid4())))
                if event_id in self._alerted_event_ids:
                    self._events_processed += 1
                    self._metrics.inc_events(1)
                    continue
                self._alerted_event_ids.add(event_id)

                syscheck = event.get("syscheck") or {}
                file_path = syscheck.get("path", "unknown")
                fim_event_type = syscheck.get("event", "unknown").lower()
                agent_info = event.get("agent") or {}

                audit_data = syscheck.get("audit") or {}
                user_data = audit_data.get("user") or {}
                login_user_data = audit_data.get("login_user") or {}
                accessing_user = user_data.get("name", "") or login_user_data.get("name", "unknown")
                
                process_data = audit_data.get("process") or {}
                accessing_process = process_data.get("name", "unknown")
                process_id = process_data.get("id", "N/A")

                token_meta = self.token_registry.get(file_path, {})

                findings.append({
                    "type": "token_accessed",
                    "file_path": file_path,
                    "fim_event_type": fim_event_type,
                    "hostname": agent_info.get("name", "unknown"),
                    "accessing_user": accessing_user,
                    "accessing_process": accessing_process,
                    "process_id": process_id,
                    "token_id": token_meta.get("token_id", "unknown"),
                    "token_description": token_meta.get("description", "unknown"),
                    "mitre_technique": token_meta.get("mitre_technique", "T1552"),
                })
                self._events_processed += 1
                self._metrics.inc_events(1)
            except Exception as e:
                logger.warning("Error analyzing Canary Token event: %s", e)

        # Missing tokens (deleted by attacker)
        for file_path in data.get("missing_tokens", []):
            try:
                meta = self.token_registry.get(file_path, {})
                findings.append({
                    "type": "token_deleted",
                    "file_path": file_path,
                    "token_id": meta.get("token_id", "unknown"),
                    "token_description": meta.get("description", "unknown"),
                })
            except Exception as e:
                logger.warning("Error processing missing token: %s", e)

        return findings

    # ------------------------------------------------------------------
    # Decide / قرار
    # ------------------------------------------------------------------
    def decide(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Map findings to alert actions."""
        actions: list[dict[str, Any]] = []

        for finding in findings:
            try:
                if finding["type"] == "token_accessed":
                    actions.append({
                        "alert": True,
                        "severity": Severity.CRITICAL,
                        "title": "🚨 CANARY TOKEN ACCESSED – CREDENTIAL HARVESTING DETECTED",
                        "details": {
                            "file_path": finding["file_path"],
                            "token_description": finding["token_description"],
                            "token_id": finding["token_id"],
                            "fim_event_type": finding["fim_event_type"],
                            "hostname": finding["hostname"],
                            "accessing_user": finding["accessing_user"],
                            "accessing_process": finding["accessing_process"],
                            "process_id": finding["process_id"],
                            "mitre_technique": finding["mitre_technique"],
                            "mitre_tactic": "Credential Access",
                        },
                    })

                elif finding["type"] == "token_deleted":
                    actions.append({
                        "alert": True,
                        "severity": Severity.HIGH,
                        "title": "⚠️ CANARY TOKEN FILE DELETED",
                        "details": {
                            "file_path": finding["file_path"],
                            "token_id": finding["token_id"],
                            "token_description": finding["token_description"],
                            "mitre_technique": "T1070.004 - File Deletion",
                            "mitre_tactic": "Defense Evasion",
                        },
                    })
            except Exception as e:
                logger.warning("Error deciding for Canary finding: %s", e)

        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: list[dict[str, Any]]) -> dict[str, Any]:
        """Execute alert actions."""
        alerts_sent = 0

        for action in actions:
            try:
                if action.get("alert"):
                    sent = self.alerter.send_alert(
                        severity=action["severity"],
                        title=action["title"],
                        details=action["details"],
                        agent_name=self.name,
                    )
                    if sent:
                        alerts_sent += 1
                        self._metrics.inc_alerts(action["severity"].name)
            except Exception as e:
                logger.warning("Error executing Canary action: %s", e)

        if alerts_sent:
            self.report_to_supervisor({
                "type": "canary_token_report",
                "alerts_sent": alerts_sent,
            })

        return {"alerts_sent": alerts_sent}


# ---------------------------------------------------------------------------
# Entry point / نقطة الدخول
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = CanaryTokensAgent()
    agent.run_loop()
