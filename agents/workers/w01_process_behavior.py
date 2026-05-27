# SOC Platform - Worker Agent W01: Process Behavior
# وكيل كشف السلوكيات الشاذة للبرامج
"""
Process Behavior Agent
======================

Monitors process creation logs (e.g. Sysmon Event ID 1, Auditd) via OpenSearch
to detect suspicious parent-child execution chains and LOLBins.

Detects:
1. Malicious Parent-Child relationships (e.g. winword.exe -> powershell.exe)
2. Execution from unusual/temporary paths.
3. Abuse of Living-off-the-Land Binaries (LOLBins) with suspicious arguments.

Interval: 30 seconds
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from shared.alerter import Severity
from shared.base_agent import BaseAgent
from shared.config import SOCConfig

logger = logging.getLogger("soc.worker.w01_process_behavior")


class ProcessBehaviorAgent(BaseAgent):
    """
    Process Behavior Agent - Detects malicious executions.
    وكيل كشف السلوكيات الشاذة وتحركات البرامج
    """

    def __init__(self, config: Optional[SOCConfig] = None) -> None:
        super().__init__(
            name="w01_process_behavior",
            description="Monitors process creation for suspicious parent-child chains and LOLBins.",
            # إصلاح V01-PERF-LOW-01: تعديل الفاصل الزمني ليطابق دقيقة واحدة لمنع تداخل الأحداث دون التسبب بخطأ في OpenSearch
            interval_seconds=60,
            config=config,
            supervisor_channel="soc:response-supervisor",
        )
        # إصلاح V01-CONF-MED-03: توحيد حالة الأحرف لتفادي فشل المطابقة إذا تم تمرير أحرف كبيرة من YAML
        raw_pairs = self._agent_config.get("known_bad_pairs", {
            "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
            "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
            "powerpnt.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
            "explorer.exe": ["powershell.exe", "cmd.exe"],
            "nginx": ["bash", "sh", "dash"],
            "apache2": ["bash", "sh", "dash"],
            "httpd": ["bash", "sh", "dash"]
        })
        # إصلاح V01-SEC-HIGH-01: إزالة .exe داخلياً لمنع التهرب إذا تم تشغيل البرنامج بدون الامتداد
        self.known_bad_pairs = {k.lower().replace(".exe", ""): [v.lower().replace(".exe", "") for v in vals] for k, vals in raw_pairs.items()}

        # إصلاح V01-CONF-MED-01: توليد صيغ exe تلقائياً لضمان عدم تجاوز القاعدة في حال قام المستخدم بتحديث YAML
        lolbins_list = self._agent_config.get("lolbins", [
            "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "wmic.exe",
            "curl", "wget", "nc"
        ])
        self.lolbins = set([lb.lower() for lb in lolbins_list] + [lb.lower() + ".exe" for lb in lolbins_list if not lb.lower().endswith(".exe")])

        # إصلاح V01-CONF-MED-02: تحويل جميع المسارات المستلمة من YAML إلى أحرف صغيرة
        raw_paths = self._agent_config.get("suspicious_paths", [
            # إصلاح V01-SEC-LOW-01: تخطي تحذير Bandit الكاذب
            "\\temp\\", "\\appdata\\", "\\programdata\\", "/tmp/", "/dev/shm/"  # nosec B108
        ])
        self.suspicious_paths = [p.lower() for p in raw_paths]

    # ------------------------------------------------------------------
    # Collect / جمع
    # ------------------------------------------------------------------
    def collect(self) -> List[Dict[str, Any]]:
        """Fetch Sysmon Event ID 1 or Auditd Execve logs."""
        query = {
            "bool": {
                "should": [
                    {"match": {"rule.groups": "sysmon_event1"}},
                    {"match": {"rule.groups": "auditd_execve"}},
                ],
                "minimum_should_match": 1
            }
        }
        try:
            return self.os_client.get_events_since(
                index="wazuh-alerts-*",
                # إصلاح V01-PERF-LOW-01: استرجاع الدقيقة الماضية بالكامل بدون تداخل بفضل تعديل الفاصل الزمني
                minutes=1,
                query=query,
                # إصلاح V01-SEC-HIGH-05: زيادة الحد الأقصى إلى 10,000 لتخفيف خطر الإغراق اللوجي (Log Flooding Evasion)
                size=10000
            )
        except Exception as e:
            logger.error("Failed to collect process events: %s", e)
            return []

    # ------------------------------------------------------------------
    # Analyze / تحليل
    # ------------------------------------------------------------------
    def analyze(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify malicious execution patterns."""
        findings = []
        for event in data:
            try:
                # Handle both Windows Sysmon and Linux Auditd structures (simplified)
                agent_obj = event.get("agent") or {}
                agent_name = agent_obj.get("name", "unknown")

                # Extract fields based on Sysmon standard
                data_obj = event.get("data") or {}
                eventdata = (data_obj.get("win") or {}).get("eventdata") or {}
                if not eventdata:
                    # Fallback to auditd or other generic fields if available
                    eventdata = data_obj.get("audit") or {}

                # إصلاح V01-LOGIC-CRIT-01: تجنب تقييم None كنص "none" لعدم خلق معالجات وهمية
                parent_process = str(eventdata.get("parentImage") or eventdata.get("ppid") or "").lower()
                child_process = str(eventdata.get("image") or eventdata.get("exe") or "").lower()
                cmdline = str(eventdata.get("commandLine") or eventdata.get("cmd") or "").lower()

                # إصلاح V01-SEC-CRIT-01: لا تتخطى الحدث إذا كان الأب مفقوداً، فالقاعدة 2 و 3 تعتمد على الابن فقط
                if not child_process:
                    continue

                # Get just the binary name
                # إصلاح V01-SEC-MED-02: إزالة الفراغات الزائدة (Trailing Whitespace) لمنع التهرب بها
                parent_name = parent_process.split("\\")[-1].split("/")[-1].strip() if parent_process else "unknown"
                child_name = child_process.split("\\")[-1].split("/")[-1].strip()

                parent_name_base = parent_name.replace(".exe", "")
                child_name_base = child_name.replace(".exe", "")
                
                # إصلاح V01-SEC-CRIT-02: استخراج الاسم الأصلي (OriginalFileName) لإحباط حيل تغيير اسم الملف (Binary Renaming Evasion)
                original_file_name = str(eventdata.get("originalFileName") or "").lower()
                child_orig_name = original_file_name.split("\\")[-1].split("/")[-1].strip() if original_file_name else ""
                child_orig_base = child_orig_name.replace(".exe", "") if child_orig_name else ""
                
                # مجموعة هويات البرنامج الابن (تشمل الاسم الفعلي، الاسم الأصلي، ومع/بدون الامتداد)
                child_identities = {child_name, child_name_base, child_orig_name, child_orig_base}
                child_identities.discard("")

                # Rule 1: Known Bad Parent-Child Pairs (Macro execution, Web Shells)
                if parent_name_base in self.known_bad_pairs and any(c in self.known_bad_pairs[parent_name_base] for c in child_identities):
                    findings.append({
                        "type": "suspicious_parent_child",
                        "severity": Severity.CRITICAL,
                        "parent": parent_name,
                        "child": child_name,
                        "cmdline": cmdline,
                        "host": agent_name,
                        "details": f"Suspicious process chain: {parent_name} spawned {child_name}. Args: {cmdline}"
                    })
                    continue

                # Rule 2: Execution from unusual paths
                # إصلاح V01-SEC-MED-01: معالجة تلاعب المخترقين باتجاهات الشرطة المائلة (Slashes) للتهرب
                child_norm_win = child_process.replace("/", "\\")
                child_norm_nix = child_process.replace("\\", "/")
                if any(path in child_norm_win or path in child_norm_nix for path in self.suspicious_paths):
                    # We might want to lower severity if it's just a temp path, but combined with cmdline it's HIGH
                    severity = Severity.HIGH if child_name in self.lolbins else Severity.MEDIUM
                    findings.append({
                        "type": "unusual_execution_path",
                        "severity": severity,
                        "parent": parent_name,
                        "child": child_name,
                        "path": child_process,
                        "cmdline": cmdline,
                        "host": agent_name,
                        "details": f"Process spawned from unusual path: {child_process}. Args: {cmdline}"
                    })
                    # إصلاح V01-LOGIC-HIGH-01: إزالة أمر continue لضمان عدم حجب القاعدة الثالثة وإدراج سطر الأوامر

                # Rule 3: LOLBins usage
                # إصلاح V01-SEC-HIGH-04: شمول القاعدة 3 بهويات الملف البديلة لمنع تخطي الـ LOLBins
                if any(c in self.lolbins for c in child_identities):
                    # Check cmdline arguments for specific flags (-urlcache, http, etc.)
                    # إصلاح V01-LOGIC-MED-01: استخدام التقسيم (split) لمنع الإيجابيات الخاطئة ولتفادي مشاكل الفراغات
                    # إصلاح V01-SEC-HIGH-02: إزالة علامات الاقتباس لمنع التهرب باستخدام "-e"
                    args_list = cmdline.replace('"', '').replace("'", "").split()
                    suspicious_args = ["http", "urlcache", "javascript:", "download"]
                    
                    # إصلاح V01-SEC-HIGH-06: التهرب باستخدام بادئات الأعلام البديلة (Flag Prefix Evasion) مثل /e أو --e
                    evasion_flags = {"-e", "/e", "--e", "-p", "/p", "--p"}
                    if any(arg in cmdline for arg in suspicious_args) or any(flag in evasion_flags for flag in args_list):
                        findings.append({
                            "type": "lolbin_usage",
                            "severity": Severity.HIGH,
                            "parent": parent_name,
                            "child": child_name,
                            "cmdline": cmdline,
                            "host": agent_name,
                            "details": f"Suspicious LOLBin execution: {child_name} with args {cmdline}"
                        })

            except Exception as e:
                # إصلاح V1-FUNC-MED-02: Catch all exceptions in event loop to prevent crash and log warning
                logger.warning("Error analyzing process event: %s", e)

        # إصلاح V01-FUNC-MED-01: تسجيل الإحصائيات الشاملة حتى للأحداث السليمة
        self._events_processed += len(data)
        self._metrics.inc_events(len(data))
        return findings

    # ------------------------------------------------------------------
    # Decide / قرار
    # ------------------------------------------------------------------
    def decide(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Formulate alert and escalation actions."""
        actions = []
        for finding in findings:
            alert = {
                "severity": finding["severity"],
                "title": f"⚙️ Process Behavior: {finding['type']}",
                "details": {
                    "host": finding["host"],
                    "parent": finding["parent"],
                    "child": finding["child"],
                    "details": finding["details"]
                },
            }
            actions.append({"action": "alert", "data": alert})

            # Escalate HIGH and CRITICAL findings
            if finding["severity"] in (Severity.HIGH, Severity.CRITICAL):
                actions.append({
                    "action": "escalate",
                    "data": {
                        "type": "process_behavior_report",
                        "severity": finding["severity"],
                        "title": alert["title"],
                        "details": alert["details"]
                    }
                })

        return actions

    # ------------------------------------------------------------------
    # Act / تنفيذ
    # ------------------------------------------------------------------
    def act(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Dispatch alerts and supervisor reports."""
        results = {"alerts_sent": 0, "escalated": 0}

        for action in actions:
            if action["action"] == "alert":
                alert_data = action["data"]
                sent = self.alerter.send_alert(
                    severity=alert_data["severity"],
                    title=alert_data["title"],
                    details=alert_data["details"],
                    agent_name=self.name
                )
                # إصلاح V01-LOGIC-HIGH-02: ربط التحديث بنجاح الإرسال الفعلي لتفادي إحصائيات وهمية
                if sent:
                    self._metrics.inc_alerts(alert_data["severity"].name)
                    results["alerts_sent"] += 1

            elif action["action"] == "escalate":
                self.report_to_supervisor(action["data"])
                results["escalated"] += 1

        return results


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
    agent = ProcessBehaviorAgent()
    agent.run_loop()
