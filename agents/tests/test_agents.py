# SOC Platform - Unit Tests for Agents
# اختبارات الوحدة لوكلاء مركز العمليات الأمنية
"""
Unit tests for SOC agent framework and worker agents.

Tests cover:
    - BaseAgent initialization
    - Brute force detection logic (mock data)
    - Canary file creation
    - Alert severity calculation
    - Anomaly Z-score calculation
    - IQR outlier detection

Run with: pytest tests/test_agents.py -v
"""

from __future__ import annotations

import hashlib
import os
import statistics
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Mock SOCConfig so tests don't need real services
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_soc_config(monkeypatch):
    """
    Patch SOCConfig.get_instance() to return a mock config
    so agents don't try to connect to real Redis/OpenSearch/Wazuh.
    """
    mock_config = MagicMock()
    mock_config.redis.host = "localhost"
    mock_config.redis.port = 6379
    mock_config.redis.db = 0
    mock_config.redis.password = ""
    mock_config.redis.socket_timeout = 5
    mock_config.opensearch.hosts = ["https://localhost:9200"]
    mock_config.opensearch.username = "admin"
    mock_config.opensearch.password = "admin"
    mock_config.opensearch.verify_certs = False
    mock_config.opensearch.ssl_show_warn = False
    mock_config.opensearch.timeout = 30
    mock_config.opensearch.max_retries = 2
    mock_config.opensearch.retry_on_timeout = True
    mock_config.wazuh.url = "https://localhost:55000"
    mock_config.wazuh.username = "test"
    mock_config.wazuh.password = "test"
    mock_config.wazuh.verify_ssl = False
    mock_config.wazuh.timeout = 10
    mock_config.alerting.rate_limit_seconds = 60
    mock_config.alerting.log_to_opensearch = False
    mock_config.alerting.alert_index = "soc-alerts"
    mock_config.alerting.slack.enabled = False
    mock_config.alerting.telegram.enabled = False
    mock_config.alerting.smtp.host = ""
    mock_config.alerting.smtp.to_addrs = []
    mock_config.misp.url = "https://localhost"
    mock_config.misp.api_key = "test"
    mock_config.get_agent_config.return_value = {}

    with patch("shared.config.SOCConfig.get_instance", return_value=mock_config):
        # Also patch the service clients to prevent real connections
        with patch("shared.redis_bus.redis.Redis"):
            with patch("shared.opensearch_client.OpenSearch"):
                yield mock_config


# ===========================================================================
# Test 1: BaseAgent initialization / اختبار تهيئة الوكيل الأساسي
# ===========================================================================
class TestBaseAgentInit:
    """Tests for BaseAgent initialization."""

    def test_agent_name_and_description(self, mock_soc_config):
        """Agent should store name and description correctly."""
        from workers.w03_ransomware_canary import RansomwareCanaryAgent

        agent = RansomwareCanaryAgent(config=mock_soc_config)
        assert agent.name == "w03_ransomware_canary"
        assert "Ransomware" in agent.description

    def test_agent_interval(self, mock_soc_config):
        """Agent should use the correct interval."""
        from workers.w03_ransomware_canary import RansomwareCanaryAgent

        agent = RansomwareCanaryAgent(config=mock_soc_config)
        assert agent.interval_seconds == 30

    def test_agent_has_config(self, mock_soc_config):
        """Agent should have a config instance."""
        from workers.w36_canary_tokens import CanaryTokensAgent

        agent = CanaryTokensAgent(config=mock_soc_config)
        assert agent.config is not None

    def test_anomaly_agent_interval(self, mock_soc_config):
        """Anomaly detection agent should use 300-second interval."""
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        agent = AnomalyDetectionAgent(config=mock_soc_config)
        assert agent.interval_seconds == 300

    def test_supervisor_interval(self, mock_soc_config):
        """Infrastructure supervisor should use 10-second interval."""
        from supervisors.infra_supervisor import InfraSupervisor

        agent = InfraSupervisor(config=mock_soc_config)
        assert agent.interval_seconds == 10


# ===========================================================================
# Test 2: Alert severity calculation / اختبار حساب مستوى الخطورة
# ===========================================================================
class TestAlertSeverity:
    """Tests for severity level calculations."""

    def test_grade_to_severity_critical(self, mock_soc_config):
        """Anomaly grade > 0.9 should be CRITICAL."""
        from shared.alerter import Severity
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        assert AnomalyDetectionAgent.grade_to_severity(0.95) == Severity.CRITICAL
        assert AnomalyDetectionAgent.grade_to_severity(0.91) == Severity.CRITICAL

    def test_grade_to_severity_high(self, mock_soc_config):
        """Anomaly grade > 0.7 (but ≤ 0.9) should be HIGH."""
        from shared.alerter import Severity
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        assert AnomalyDetectionAgent.grade_to_severity(0.85) == Severity.HIGH
        assert AnomalyDetectionAgent.grade_to_severity(0.90) == Severity.HIGH  # 0.9 NOT > 0.9

    def test_grade_to_severity_medium(self, mock_soc_config):
        """Anomaly grade > 0.5 (but ≤ 0.7) should be MEDIUM."""
        from shared.alerter import Severity
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        assert AnomalyDetectionAgent.grade_to_severity(0.6) == Severity.MEDIUM
        assert AnomalyDetectionAgent.grade_to_severity(0.70) == Severity.MEDIUM

    def test_grade_to_severity_info(self, mock_soc_config):
        """Anomaly grade ≤ 0.5 should be INFO."""
        from shared.alerter import Severity
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        assert AnomalyDetectionAgent.grade_to_severity(0.3) == Severity.INFO
        assert AnomalyDetectionAgent.grade_to_severity(0.49) == Severity.INFO

    def test_zscore_to_severity(self, mock_soc_config):
        """Z-score values should map to correct severity levels."""
        from shared.alerter import Severity
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        assert AnomalyDetectionAgent.zscore_to_severity(4.5) == Severity.CRITICAL
        assert AnomalyDetectionAgent.zscore_to_severity(3.5) == Severity.HIGH
        assert AnomalyDetectionAgent.zscore_to_severity(2.7) == Severity.MEDIUM
        assert AnomalyDetectionAgent.zscore_to_severity(2.1) == Severity.LOW
        assert AnomalyDetectionAgent.zscore_to_severity(1.0) == Severity.INFO

    def test_severity_enum_values(self):
        """Severity enum should have correct integer ordering."""
        from shared.alerter import Severity

        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


# ===========================================================================
# Test 3: Canary file creation / اختبار إنشاء ملفات الطُعم
# ===========================================================================
class TestCanaryFileCreation:
    """Tests for ransomware canary file creation."""

    def test_setup_canary_files_creates_files(self, mock_soc_config):
        """Canary files should be created in existing directories."""
        from workers.w03_ransomware_canary import RansomwareCanaryAgent

        with tempfile.TemporaryDirectory() as tmpdir:
            mock_soc_config.get_agent_config.return_value = {"canary_dirs": [tmpdir]}
            agent = RansomwareCanaryAgent(config=mock_soc_config, canary_dirs=[tmpdir])
            registry = agent.setup_canary_files()

            assert len(registry) == 1
            canary_path = list(registry.keys())[0]
            assert os.path.exists(canary_path)

            with open(canary_path, "r") as fh:
                content = fh.read()
            assert "SOC-CANARY-SENTINEL" in content

    def test_canary_hash_recorded(self, mock_soc_config):
        """The SHA-256 hash of canary content should be recorded correctly."""
        from workers.w03_ransomware_canary import RansomwareCanaryAgent

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = RansomwareCanaryAgent(config=mock_soc_config, canary_dirs=[tmpdir])
            registry = agent.setup_canary_files()

            canary_path = list(registry.keys())[0]
            expected_hash = registry[canary_path]

            with open(canary_path, "r") as fh:
                content = fh.read()
            actual_hash = hashlib.sha256(content.encode()).hexdigest()
            assert expected_hash == actual_hash

    def test_canary_skips_nonexistent_dirs(self, mock_soc_config):
        """Canary setup should skip directories that don't exist."""
        from workers.w03_ransomware_canary import RansomwareCanaryAgent

        agent = RansomwareCanaryAgent(
            config=mock_soc_config,
            canary_dirs=["/nonexistent/path/for/testing"],
        )
        registry = agent.setup_canary_files()
        assert len(registry) == 0

    def test_canary_registry_stored_on_agent(self, mock_soc_config):
        """After setup, the registry should be stored on the agent instance."""
        from workers.w03_ransomware_canary import RansomwareCanaryAgent

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = RansomwareCanaryAgent(config=mock_soc_config, canary_dirs=[tmpdir])
            agent.setup_canary_files()
            assert len(agent.canary_registry) == 1


# ===========================================================================
# Test 4: Canary tokens deployment / اختبار نشر رموز الطُعم
# ===========================================================================
class TestCanaryTokens:
    """Tests for canary token deployment and monitoring."""

    def test_deploy_tokens_in_existing_dir(self, mock_soc_config):
        """Tokens should be created in directories that exist."""
        from workers.w36_canary_tokens import CanaryTokensAgent

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = CanaryTokensAgent(config=mock_soc_config)
            agent.token_definitions = [
                {
                    "filename": "test_creds.txt",
                    "deploy_dir": tmpdir,
                    "description": "Test credentials file",
                    "content_template": "password: {token}\nToken: {token_id}",
                    "mitre_technique": "T1552",
                },
            ]
            registry = agent.deploy_canary_tokens()

            assert len(registry) == 1
            token_path = list(registry.keys())[0]
            assert os.path.exists(token_path)

            meta = registry[token_path]
            with open(token_path, "r") as fh:
                content = fh.read()
            assert meta["token_id"] in content

    def test_token_ids_are_unique(self, mock_soc_config):
        """Each deployed token should have a unique token ID."""
        from workers.w36_canary_tokens import CanaryTokensAgent

        with tempfile.TemporaryDirectory() as tmpdir:
            agent = CanaryTokensAgent(config=mock_soc_config)
            agent.token_definitions = [
                {
                    "filename": f"test_{i}.txt",
                    "deploy_dir": tmpdir,
                    "description": f"Test file {i}",
                    "content_template": "Token: {token_id}",
                    "mitre_technique": "T1552",
                }
                for i in range(5)
            ]
            registry = agent.deploy_canary_tokens()

            token_ids = [meta["token_id"] for meta in registry.values()]
            assert len(set(token_ids)) == 5  # All unique


# ===========================================================================
# Test 5: Anomaly Z-score calculation / اختبار حساب الدرجة المعيارية
# ===========================================================================
class TestAnomalyZScore:
    """Tests for Z-score and IQR anomaly detection."""

    def test_zscore_normal_value(self):
        """A value near the mean should have a low Z-score."""
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        data = [10.0, 12.0, 11.0, 10.5, 11.5, 10.2, 11.8, 10.8, 11.2, 10.7]
        zscore = AnomalyDetectionAgent.calculate_zscore(11.0, data)
        assert zscore is not None
        assert abs(zscore) < 1.0

    def test_zscore_outlier_value(self):
        """A value far from the mean should have a high Z-score."""
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        data = [10.0, 10.1, 10.2, 9.9, 10.0, 10.1, 9.8, 10.3, 10.0, 9.9]
        zscore = AnomalyDetectionAgent.calculate_zscore(50.0, data)
        assert zscore is not None
        assert zscore > 3.0

    def test_zscore_insufficient_data(self):
        """Z-score should return None with too few data points."""
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        data = [10.0, 11.0, 12.0]  # Less than 10 points
        zscore = AnomalyDetectionAgent.calculate_zscore(11.0, data)
        assert zscore is None

    def test_zscore_zero_stddev(self):
        """Z-score should handle zero standard deviation gracefully."""
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        data = [5.0] * 20
        assert AnomalyDetectionAgent.calculate_zscore(5.0, data) == 0.0
        assert AnomalyDetectionAgent.calculate_zscore(10.0, data) is None

    def test_iqr_bounds_calculation(self):
        """IQR bounds should be calculated correctly."""
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        data = list(range(1, 101))  # 1 to 100
        result = AnomalyDetectionAgent.calculate_iqr_bounds(data)

        assert result is not None
        lower, upper, lower_ext, upper_ext = result

        # Q1 ≈ 25, Q3 ≈ 75, IQR ≈ 50
        assert lower < 0
        assert upper > 100
        assert lower_ext < lower
        assert upper_ext > upper

    def test_iqr_insufficient_data(self):
        """IQR should return None with too few data points."""
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        data = [1.0, 2.0, 3.0]  # Less than 20 points
        result = AnomalyDetectionAgent.calculate_iqr_bounds(data)
        assert result is None


# ===========================================================================
# Test 6: Ransomware patterns / اختبار أنماط الفدية
# ===========================================================================
class TestRansomwarePatterns:
    """Tests for ransomware detection patterns."""

    def test_ransomware_extensions_populated(self):
        """The ransomware extensions set should contain known extensions."""
        from workers.w03_ransomware_canary import RANSOMWARE_EXTENSIONS

        assert ".encrypted" in RANSOMWARE_EXTENSIONS
        assert ".locked" in RANSOMWARE_EXTENSIONS
        assert ".WNCRY" in RANSOMWARE_EXTENSIONS

    def test_ransomware_process_patterns_match(self):
        """Known ransomware process patterns should match expected names."""
        from workers.w03_ransomware_canary import RANSOMWARE_PROCESS_PATTERNS

        test_cases = [
            ("wannacry.exe", True),
            ("lockbit3.exe", True),
            ("conti_loader.exe", True),
            ("notepad.exe", False),
            ("svchost.exe", False),
        ]

        for process_name, should_match in test_cases:
            matched = any(p.search(process_name) for p in RANSOMWARE_PROCESS_PATTERNS)
            assert matched == should_match, (
                f"Process '{process_name}' match={matched}, expected={should_match}"
            )


# ===========================================================================
# Test 7: Agent analyze phase / اختبار مرحلة التحليل
# ===========================================================================
class TestAnalyzePhase:
    """Tests for the analyze phase of worker agents."""

    def test_ransomware_analyze_canary_finding(self, mock_soc_config):
        """Analyze should produce canary_modified findings from FIM events."""
        from workers.w03_ransomware_canary import RansomwareCanaryAgent

        agent = RansomwareCanaryAgent(config=mock_soc_config, canary_dirs=[])
        agent.canary_registry = {"/tmp/.soc_canary_sentinel.dat": "abc123"}

        mock_data = {
            "fim_events": [{
                "syscheck": {"path": "/tmp/.soc_canary_sentinel.dat"},
                "agent": {"name": "server01", "id": "001"},
            }],
            "shadow_copy_events": [],
            "boot_config_events": [],
            "process_events": [],
            "extension_events": [],
        }

        findings = agent.analyze(mock_data)
        assert len(findings) == 1
        assert findings[0]["type"] == "canary_modified"
        assert findings[0]["hostname"] == "server01"

    def test_canary_tokens_analyze_access(self, mock_soc_config):
        """Analyze should produce token_accessed findings from FIM events."""
        from workers.w36_canary_tokens import CanaryTokensAgent

        agent = CanaryTokensAgent(config=mock_soc_config)
        agent.token_registry = {
            "/opt/share/IT/admin_creds.txt": {
                "token_id": "test-uuid-123",
                "description": "Fake admin creds",
                "mitre_technique": "T1552.001",
            },
        }

        mock_data = {
            "fim_events": [{
                "syscheck": {
                    "path": "/opt/share/IT/admin_creds.txt",
                    "event": "modified",
                    "audit": {
                        "user": {"name": "attacker"},
                        "process": {"name": "cat", "id": "1234"},
                    },
                },
                "agent": {"name": "fileserver01"},
            }],
            "missing_tokens": [],
        }

        findings = agent.analyze(mock_data)
        assert len(findings) == 1
        assert findings[0]["type"] == "token_accessed"
        assert findings[0]["accessing_user"] == "attacker"


# ===========================================================================
# Test 8: Severity boundary checks / اختبار حدود الخطورة
# ===========================================================================
class TestSeverityBoundaries:
    """Additional boundary value tests for severity calculations."""

    def test_grade_boundary_exact_values(self):
        """Test exact boundary values for grade-to-severity mapping."""
        from shared.alerter import Severity
        from workers.w13_anomaly_detection import AnomalyDetectionAgent

        # Exact boundaries – 0.9 is NOT > 0.9
        assert AnomalyDetectionAgent.grade_to_severity(0.90) == Severity.HIGH
        # 0.7 is NOT > 0.7
        assert AnomalyDetectionAgent.grade_to_severity(0.70) == Severity.MEDIUM
        # 0.5 is NOT > 0.5
        assert AnomalyDetectionAgent.grade_to_severity(0.50) == Severity.INFO
        # 0.0 baseline
        assert AnomalyDetectionAgent.grade_to_severity(0.0) == Severity.INFO


# ---------------------------------------------------------------------------
# Entry point / نقطة الدخول
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
