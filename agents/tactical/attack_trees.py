"""
SOC Platform - Attack Tree Library (MITRE ATT&CK)
مكتبة أشجار الهجوم — مسارات هجوم معروفة للمحاكاة التنبؤية

Provides pre-defined attack chains based on MITRE ATT&CK framework.
Each chain maps a sequence of techniques that attackers commonly follow.
The SimulationAgent uses this to predict the next stage of an ongoing attack.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger("soc.attack_trees")


# ---------------------------------------------------------------------------
# Attack Stage Definition / تعريف مراحل الهجوم
# ---------------------------------------------------------------------------

class AttackStage:
    """Represents a single stage in an attack chain."""

    def __init__(
        self,
        name: str,
        mitre_tactic: str,
        mitre_technique_id: str,
        description: str,
        indicators: List[str],
        recommended_defense: str,
    ) -> None:
        self.name = name
        self.mitre_tactic = mitre_tactic
        self.mitre_technique_id = mitre_technique_id
        self.description = description
        self.indicators = indicators  # What to look for in logs
        self.recommended_defense = recommended_defense

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique_id": self.mitre_technique_id,
            "description": self.description,
            "indicators": self.indicators,
            "recommended_defense": self.recommended_defense,
        }


# ---------------------------------------------------------------------------
# Attack Chain Definition / تعريف سلسلة الهجوم
# ---------------------------------------------------------------------------

class AttackChain:
    """A sequence of attack stages forming a known attack pattern."""

    def __init__(self, name: str, description: str, stages: List[AttackStage]) -> None:
        self.name = name
        self.description = description
        self.stages = stages

    def get_stage_index(self, technique_id: str) -> int:
        """Find the index of a stage by its MITRE technique ID."""
        for i, stage in enumerate(self.stages):
            if stage.mitre_technique_id == technique_id:
                return i
        return -1

    def predict_next_stages(self, current_technique_id: str) -> List[AttackStage]:
        """Given a current technique, return all subsequent stages."""
        idx = self.get_stage_index(current_technique_id)
        if idx < 0 or idx >= len(self.stages) - 1:
            return []
        return self.stages[idx + 1:]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "stages": [s.to_dict() for s in self.stages],
        }


# ===========================================================================
# Pre-defined Attack Chains / سلاسل الهجوم المعرّفة مسبقاً
# ===========================================================================

ATTACK_CHAINS: List[AttackChain] = [
    # -----------------------------------------------------------------------
    # 1. Phishing → Credential Theft → Lateral Movement → Exfiltration
    # -----------------------------------------------------------------------
    AttackChain(
        name="APT Phishing Campaign",
        description="تصيد إلكتروني → سرقة بيانات اعتماد → حركة جانبية → تسريب بيانات",
        stages=[
            AttackStage(
                name="Initial Access via Phishing",
                mitre_tactic="Initial Access",
                mitre_technique_id="T1566",
                description="Spear-phishing email with malicious attachment or link",
                indicators=["suspicious_email", "macro_execution", "office_child_process"],
                recommended_defense="block_email_sender",
            ),
            AttackStage(
                name="Credential Harvesting",
                mitre_tactic="Credential Access",
                mitre_technique_id="T1003",
                description="Dumping credentials from LSASS or SAM",
                indicators=["lsass_access", "mimikatz", "credential_dump"],
                recommended_defense="require_mfa",
            ),
            AttackStage(
                name="Lateral Movement via RDP/SMB",
                mitre_tactic="Lateral Movement",
                mitre_technique_id="T1021",
                description="Moving to other systems using stolen credentials",
                indicators=["rdp_lateral", "smb_lateral", "new_logon_type3"],
                recommended_defense="isolate_host",
            ),
            AttackStage(
                name="Data Exfiltration",
                mitre_tactic="Exfiltration",
                mitre_technique_id="T1041",
                description="Exfiltrating data over C2 channel",
                indicators=["large_upload", "dns_tunneling", "encrypted_traffic_anomaly"],
                recommended_defense="block_ip",
            ),
        ],
    ),

    # -----------------------------------------------------------------------
    # 2. Brute Force → Privilege Escalation → Persistence
    # -----------------------------------------------------------------------
    AttackChain(
        name="Brute Force Escalation",
        description="هجوم قوة غاشمة → تصعيد صلاحيات → ثبات في النظام",
        stages=[
            AttackStage(
                name="Brute Force Attack",
                mitre_tactic="Credential Access",
                mitre_technique_id="T1110",
                description="Repeated login failures followed by success",
                indicators=["ssh_brute_force", "login_failure_burst", "successful_login_after_failures"],
                recommended_defense="block_ip",
            ),
            AttackStage(
                name="Privilege Escalation",
                mitre_tactic="Privilege Escalation",
                mitre_technique_id="T1068",
                description="Exploiting vulnerability to gain higher privileges",
                indicators=["sudo_abuse", "kernel_exploit", "suid_binary"],
                recommended_defense="monitor_step_up",
            ),
            AttackStage(
                name="Persistence via Scheduled Task",
                mitre_tactic="Persistence",
                mitre_technique_id="T1053",
                description="Creating scheduled tasks or cron jobs for persistence",
                indicators=["crontab_modification", "scheduled_task_creation", "startup_script"],
                recommended_defense="isolate_host",
            ),
        ],
    ),

    # -----------------------------------------------------------------------
    # 3. Supply Chain → Backdoor → C2 → Data Destruction
    # -----------------------------------------------------------------------
    AttackChain(
        name="Supply Chain Compromise",
        description="اختراق سلسلة التوريد → باب خلفي → قيادة وسيطرة → تدمير بيانات",
        stages=[
            AttackStage(
                name="Supply Chain Attack",
                mitre_tactic="Initial Access",
                mitre_technique_id="T1195",
                description="Compromise via trusted software update or dependency",
                indicators=["suspicious_package_install", "modified_binary_hash", "unsigned_update"],
                recommended_defense="monitor_step_up",
            ),
            AttackStage(
                name="Backdoor Installation",
                mitre_tactic="Persistence",
                mitre_technique_id="T1543",
                description="Installing a persistent backdoor service",
                indicators=["new_service_creation", "suspicious_listener", "reverse_shell"],
                recommended_defense="isolate_host",
            ),
            AttackStage(
                name="Command & Control",
                mitre_tactic="Command and Control",
                mitre_technique_id="T1071",
                description="Establishing C2 communication channel",
                indicators=["beaconing_pattern", "dns_c2", "unusual_port_traffic"],
                recommended_defense="block_ip",
            ),
            AttackStage(
                name="Data Destruction",
                mitre_tactic="Impact",
                mitre_technique_id="T1485",
                description="Wiping or encrypting critical data (ransomware)",
                indicators=["mass_file_encryption", "shadow_copy_deletion", "disk_wipe"],
                recommended_defense="isolate_host",
            ),
        ],
    ),

    # -----------------------------------------------------------------------
    # 4. Insider Threat — Credential Abuse → Data Collection → Exfiltration
    # -----------------------------------------------------------------------
    AttackChain(
        name="Insider Threat",
        description="تهديد داخلي — استغلال صلاحيات → جمع بيانات → تسريب",
        stages=[
            AttackStage(
                name="Valid Account Abuse",
                mitre_tactic="Initial Access",
                mitre_technique_id="T1078",
                description="Using legitimate credentials for unauthorized access",
                indicators=["off_hours_login", "unusual_geo_login", "privilege_abuse"],
                recommended_defense="require_mfa",
            ),
            AttackStage(
                name="Internal Discovery",
                mitre_tactic="Discovery",
                mitre_technique_id="T1083",
                description="Enumerating files and network shares",
                indicators=["mass_file_access", "share_enumeration", "database_query_spike"],
                recommended_defense="monitor_step_up",
            ),
            AttackStage(
                name="Data Staging & Exfiltration",
                mitre_tactic="Exfiltration",
                mitre_technique_id="T1567",
                description="Uploading data to cloud storage or personal email",
                indicators=["cloud_upload", "usb_copy", "email_attachment_burst"],
                recommended_defense="block_ip",
            ),
        ],
    ),

    # -----------------------------------------------------------------------
    # 5. Web Exploitation → Web Shell → Lateral → Ransomware
    # -----------------------------------------------------------------------
    AttackChain(
        name="Web Application Attack",
        description="استغلال تطبيق ويب → Web Shell → حركة جانبية → فدية",
        stages=[
            AttackStage(
                name="Web Exploitation",
                mitre_tactic="Initial Access",
                mitre_technique_id="T1190",
                description="Exploiting public-facing application (SQLi, RCE)",
                indicators=["sqli_pattern", "rce_attempt", "web_scanner_signature"],
                recommended_defense="block_ip",
            ),
            AttackStage(
                name="Web Shell Deployment",
                mitre_tactic="Persistence",
                mitre_technique_id="T1505.003",
                description="Uploading a web shell for persistent access",
                indicators=["webshell_upload", "suspicious_php_file", "new_jsp_file"],
                recommended_defense="isolate_host",
            ),
            AttackStage(
                name="Lateral Movement",
                mitre_tactic="Lateral Movement",
                mitre_technique_id="T1021",
                description="Moving from web server to internal network",
                indicators=["internal_scan_from_dmz", "rdp_from_webserver", "smb_from_webserver"],
                recommended_defense="isolate_host",
            ),
            AttackStage(
                name="Ransomware Deployment",
                mitre_tactic="Impact",
                mitre_technique_id="T1486",
                description="Encrypting files for ransom",
                indicators=["mass_file_encryption", "ransom_note_creation", "shadow_copy_deletion"],
                recommended_defense="isolate_host",
            ),
        ],
    ),
]


# ---------------------------------------------------------------------------
# Prediction Functions / دوال التنبؤ
# ---------------------------------------------------------------------------

# Build a flat index: technique_id → list of (chain, stage_index) pairs
_TECHNIQUE_INDEX: Dict[str, List[tuple]] = {}
for _chain in ATTACK_CHAINS:
    for _i, _stage in enumerate(_chain.stages):
        _TECHNIQUE_INDEX.setdefault(_stage.mitre_technique_id, []).append((_chain, _i))

# Build indicator → technique_id index
_INDICATOR_INDEX: Dict[str, List[str]] = {}
for _chain in ATTACK_CHAINS:
    for _stage in _chain.stages:
        for _ind in _stage.indicators:
            _INDICATOR_INDEX.setdefault(_ind.lower(), []).append(_stage.mitre_technique_id)


def predict_next_stage(
    current_technique_id: Optional[str] = None,
    event_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Predict the next attack stages based on the current technique or event type.

    Args:
        current_technique_id: A MITRE ATT&CK technique ID (e.g., "T1566").
        event_type: An event type string from the SOC system (e.g., "ssh_brute_force").

    Returns:
        A list of dicts with predicted next stages, each including:
        - chain_name, predicted_stage (dict), steps_away, recommended_defense
    """
    predictions = []

    # Resolve technique ID from event_type if not provided
    technique_ids = set()
    if current_technique_id:
        technique_ids.add(current_technique_id)
    if event_type:
        for tid in _INDICATOR_INDEX.get(event_type.lower(), []):
            technique_ids.add(tid)

    if not technique_ids:
        return predictions

    seen = set()
    for tid in technique_ids:
        for chain, stage_idx in _TECHNIQUE_INDEX.get(tid, []):
            next_stages = chain.stages[stage_idx + 1:]
            for i, ns in enumerate(next_stages):
                key = f"{chain.name}:{ns.mitre_technique_id}"
                if key in seen:
                    continue
                seen.add(key)
                predictions.append({
                    "chain_name": chain.name,
                    "current_stage": chain.stages[stage_idx].name,
                    "predicted_stage": ns.to_dict(),
                    "steps_away": i + 1,
                    "recommended_defense": ns.recommended_defense,
                    "confidence": round(max(0.3, 1.0 - (i * 0.2)), 2),
                })

    # Sort by confidence (highest first)
    predictions.sort(key=lambda x: x["confidence"], reverse=True)
    return predictions


def get_all_chains() -> List[Dict[str, Any]]:
    """Return all defined attack chains as dicts."""
    return [c.to_dict() for c in ATTACK_CHAINS]
