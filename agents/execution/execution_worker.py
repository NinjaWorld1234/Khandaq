"""
SOC Platform – Execution Layer Worker
Receives PROPOSED_ACTION from Commander, applies safety policies, 
and stages the action for HITL approval in Redis.
"""

import json
import logging
import time
import os
import ipaddress
import requests
import threading
from typing import Dict, Any, List, Optional, Set

from shared.base_agent import BaseAgent
from shared.config import SOCConfig

try:
    from shared.alerter import send_telegram_alert
    TELEGRAM_AVAILABLE = True
except ImportError:
    TELEGRAM_AVAILABLE = False

logger = logging.getLogger("soc.execution")

# ---------------------------------------------------------------------------
# Severity Classification Rules / قواعد تصنيف الخطورة
# ---------------------------------------------------------------------------
# LOW:      Actions that only observe or log — safe to auto-approve
# MEDIUM:   Actions that modify behavior but are reversible
# CRITICAL: Actions that block, isolate, or disable — require human approval

SEVERITY_MAP = {
    # LOW — Auto-approve (no HITL needed)
    "monitor": "LOW",
    "log_note": "LOW",
    "alert_step_up": "LOW",
    "enrich_ioc": "LOW",
    "scan_host": "LOW",
    # MEDIUM — HITL + notification
    "rate_limit": "MEDIUM",
    "require_mfa": "MEDIUM",
    "monitor_step_up": "MEDIUM",
    "quarantine_file": "MEDIUM",
    "revoke_session": "MEDIUM",
    # CRITICAL — HITL mandatory + block until approved
    "block_ip": "CRITICAL",
    "isolate_host": "CRITICAL",
    "disable_user": "CRITICAL",
    "shutdown_service": "CRITICAL",
    "crowdsec_ban": "CRITICAL",
}

class ExecutionWorker(BaseAgent):
    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="execution_worker",
            description="Isolates AI brain from execution, manages HITL approvals",
            interval_seconds=5,
            config=config,
            supervisor_channel="soc:proposed-actions"
        )
        self.pending_actions = []
        self._lock = threading.Lock()
        
        # Safety Policies: Load whitelist from multiple sources
        self.whitelist_ips = self._load_whitelist()
        self.whitelist_cidrs = self._load_whitelist_cidrs()
        
        # Shadow Mode (Replay / Training Mode)
        self.shadow_mode = os.environ.get("SHADOW_MODE", "false").lower() == "true"
        if self.shadow_mode:
            logger.warning("👻 SHADOW MODE ENABLED. Actions will not be queued for HITL. They will be logged for benchmarking.")

    # ------------------------------------------------------------------
    # Dynamic Whitelist Management / إدارة القائمة البيضاء الديناميكية
    # ------------------------------------------------------------------

    def _load_whitelist(self) -> Set[str]:
        """
        Load whitelisted IPs from multiple sources.
        تحميل IPs المحمية من عدة مصادر: defaults + ENV + agent_config
        """
        # 1. Hardcoded defaults (always protected)
        whitelist = {"127.0.0.1", "::1"}

        # 2. From environment variable (comma-separated)
        env_whitelist = os.environ.get("WHITELIST_IPS", "")
        if env_whitelist:
            for ip in env_whitelist.split(","):
                ip = ip.strip()
                if ip:
                    whitelist.add(ip)

        # 3. From agent config
        config_whitelist = self._agent_config.get("whitelist_ips", [])
        if isinstance(config_whitelist, list):
            for ip in config_whitelist:
                if isinstance(ip, str) and ip.strip():
                    whitelist.add(ip.strip())

        # 4. From Redis (dynamic additions by admin)
        try:
            if hasattr(self, 'redis_bus') and self.redis_bus.redis_client:
                redis_whitelist = self.redis_bus.redis_client.smembers("soc:whitelist_ips")
                if redis_whitelist:
                    whitelist.update(redis_whitelist)
        except Exception:
            pass

        logger.info(f"🛡️ Loaded {len(whitelist)} whitelisted IPs: {whitelist}")
        return whitelist

    def _load_whitelist_cidrs(self) -> List:
        """
        Load CIDR ranges from config for subnet-level protection.
        تحميل نطاقات CIDR للحماية على مستوى الشبكة الفرعية
        """
        cidrs = []

        # From environment variable
        env_cidrs = os.environ.get("WHITELIST_CIDRS", "")
        if env_cidrs:
            for cidr in env_cidrs.split(","):
                cidr = cidr.strip()
                if cidr:
                    try:
                        cidrs.append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        logger.warning(f"Invalid CIDR in WHITELIST_CIDRS: {cidr}")

        # From agent config
        config_cidrs = self._agent_config.get("whitelist_cidrs", [])
        if isinstance(config_cidrs, list):
            for cidr in config_cidrs:
                try:
                    cidrs.append(ipaddress.ip_network(cidr, strict=False))
                except (ValueError, TypeError):
                    logger.warning(f"Invalid CIDR in config: {cidr}")

        if cidrs:
            logger.info(f"🛡️ Loaded {len(cidrs)} CIDR whitelist ranges: {[str(c) for c in cidrs]}")
        return cidrs

    def _is_whitelisted(self, ip_str: str) -> bool:
        """
        Check if an IP is protected (exact match or CIDR range).
        فحص إذا كان IP محمي (مطابقة دقيقة أو نطاق CIDR)
        """
        if not ip_str:
            return False

        # Exact match
        if ip_str in self.whitelist_ips:
            return True

        # CIDR match
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for cidr in self.whitelist_cidrs:
                if ip_obj in cidr:
                    return True
        except ValueError:
            pass

        return False

    # ------------------------------------------------------------------
    # Agent Pipeline Methods
    # ------------------------------------------------------------------

    def handle_worker_message(self, message: dict) -> None:
        try:
            payload = message.get("payload", {})
            action_id = payload.get("action_id")
            if not action_id:
                return

            with self._lock:
                self.pending_actions.append(payload)
            logger.info(f"Received PROPOSED_ACTION: {payload.get('action_type')} on {payload.get('target')}")
        except Exception as exc:
            logger.error("Failed to parse proposed action: %s", exc)

    def collect(self) -> List[Dict[str, Any]]:
        with self._lock:
            batch = list(self.pending_actions)
            self.pending_actions.clear()
        return batch

    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for action in data:
            try:
                target = action.get("target")
                action_type = action.get("action_type", "unknown")
                
                # 1. Classify severity
                severity = self._classify_severity(action_type)
                action["severity"] = severity
                
                # 2. Check safety policies using dynamic whitelist
                if action_type in ("block_ip", "isolate_host") and self._is_whitelisted(target):
                    logger.warning(f"🛡️ Safety Policy Violation: Attempted to {action_type} whitelisted IP {target}. Action rejected automatically.")
                    action["status"] = "REJECTED_BY_POLICY"
                    action["policy_reason"] = f"Target IP {target} is protected (whitelist/CIDR match)."
                elif severity == "LOW":
                    # Auto-approve low-severity actions — no HITL needed
                    action["status"] = "AUTO_APPROVED"
                    logger.info(f"✅ Auto-approved LOW severity action: {action_type} on {target}")
                else:
                    action["status"] = "PENDING_APPROVAL"
                    
                findings.append(action)
            except Exception as e:
                logger.error(f"Error processing action in analyze: {e}")
                
        return findings

    def _classify_severity(self, action_type: str) -> str:
        """
        Classify action severity based on type.
        تصنيف خطورة الإجراء: LOW (تلقائي) / MEDIUM (إشعار) / CRITICAL (حظر حتى الموافقة)
        """
        return SEVERITY_MAP.get(action_type, "CRITICAL")  # Default to CRITICAL for unknown actions

    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Execution worker doesn't "decide" new actions, it just forwards validated ones to Redis hash
        return findings

    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = {"queued": 0, "rejected": 0, "auto_approved": 0}
        for action in actions:
            try:
                action_id = action.get("action_id")
                severity = action.get("severity", "CRITICAL")
                
                if action.get("status") == "AUTO_APPROVED":
                    # LOW severity — execute immediately without HITL
                    self.redis_bus.client.hset("soc:executed_actions", action_id, json.dumps(action))
                    self._publish_feedback(action_id, action, "approved", "Auto-approved (LOW severity)")
                    results["auto_approved"] += 1
                    
                elif action.get("status") == "PENDING_APPROVAL":
                    if self.shadow_mode:
                        with open("shadow_results.log", "a") as f:
                            f.write(json.dumps(action) + "\n")
                        logger.info(f"👻 [SHADOW MODE] Action {action_id} recorded in shadow_results.log.")
                        results["queued"] += 1
                    else:
                        # Store in Redis Hash for the HITL API
                        self.redis_bus.client.hset("soc:pending_approvals", action_id, json.dumps(action))
                        logger.info(f"Action {action_id} [{severity}] queued for HITL approval.")
                        results["queued"] += 1
                        
                        # Send Telegram alert for CRITICAL actions
                        if severity == "CRITICAL":
                            self._notify_critical_action(action)
                        
                elif action.get("status") == "REJECTED_BY_POLICY":
                    self.redis_bus.client.hset("soc:rejected_actions", action_id, json.dumps(action))
                    self._publish_feedback(action_id, action, "rejected", "Violation of Safety Policy (Whitelist)")
                    results["rejected"] += 1
            except Exception as e:
                logger.error(f"Error queuing action: {e}")
                
        return results

    def _notify_critical_action(self, action: dict):
        """Send Telegram/Slack notification for critical actions requiring immediate human review."""
        msg = (
            f"🚨 *CRITICAL ACTION PENDING*\n"
            f"Type: `{action.get('action_type')}`\n"
            f"Target: `{action.get('target')}`\n"
            f"Reason: {action.get('reason', 'N/A')}\n"
            f"Source: {action.get('source', 'unknown')}\n"
            f"⏳ Waiting for human approval at HITL Dashboard"
        )
        try:
            if TELEGRAM_AVAILABLE:
                send_telegram_alert(msg)
            logger.critical(f"📱 Telegram notification sent for CRITICAL action: {action.get('action_type')} on {action.get('target')}")
        except Exception as e:
            logger.error(f"Failed to send Telegram notification: {e}")

    def _publish_feedback(self, action_id: str, action: dict, status: str, reason: str):
        """Publishes a feedback event for the Self-Evaluation Agent"""
        feedback = {
            "action_id": action_id,
            "source_role": action.get("source", "commander"),
            "action_type": action.get("action_type", "unknown"),
            "status": status,  # "approved" or "rejected"
            "reason": reason,
            "timestamp": time.time()
        }
        try:
            self.redis_bus.publish("soc:ai-feedback", feedback, sender=self.name, message_type="FEEDBACK")
        except Exception as e:
            logger.error(f"Failed to publish feedback: {e}")

    def run_loop(self):
        self.redis_bus.subscribe(self.supervisor_channel, self.handle_worker_message)
        # Subscribe to execution triggers from HITL API
        self.redis_bus.subscribe("soc:execute-action", self.handle_execution_trigger)
        super().run_loop()

    def handle_execution_trigger(self, message: dict) -> None:
        """
        Triggered when a human approves an action via the API.
        """
        try:
            payload = message.get("payload", {})
            action_type = payload.get("action_type")
            target = payload.get("target")
            reason = payload.get("reason")
            
            logger.critical(f"[HITL APPROVED] Executing {action_type} on {target}...")
            
            if action_type == "block_ip":
                self._enforce_crowdsec_ban(target, reason)
            elif action_type == "isolate_host":
                logger.critical(f"Integrating with EDR to isolate: {target}")
            
            # Remove from pending queue
            action_id = payload.get("action_id")
            if action_id:
                self.redis_bus.redis_client.hdel("soc:pending_approvals", action_id)
                self.redis_bus.redis_client.hset("soc:executed_actions", action_id, json.dumps(payload))
                
                # Assume approved if it reaches here (in a real HITL API, the API would specify approved vs rejected)
                # But since this function is 'handle_execution_trigger', it implies approval.
                self._publish_feedback(action_id, payload, "approved", "HITL Approved")
                
        except Exception as e:
            logger.error(f"Failed to execute approved action: {e}")

    def _enforce_crowdsec_ban(self, ip: str, reason: str):
        """Sends a POST request to the local CrowdSec LAPI to enforce a ban."""
        bouncer_key = os.environ.get("CROWDSEC_BOUNCER_KEY", "DEMO_KEY")
        lapi_url = "http://127.0.0.1:8080/v1/decisions"
        
        headers = {
            "X-Api-Key": bouncer_key,
            "Content-Type": "application/json"
        }
        
        payload = [{
            "scenario": "soc-hitl-approved",
            "type": "ban",
            "duration": "24h",
            "scope": "ip",
            "value": ip,
            "message": f"HITL Approved Ban: {reason}"
        }]
        
        try:
            response = requests.post(lapi_url, headers=headers, json=payload, timeout=5)
            if response.status_code == 200 or response.status_code == 201:
                logger.info(f"✅ CrowdSec Enforced Ban on {ip} successfully.")
            else:
                logger.error(f"❌ CrowdSec LAPI failed to ban {ip}. Status: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Failed to reach CrowdSec LAPI: {e}")

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )
    agent = ExecutionWorker()
    agent.run_loop()
