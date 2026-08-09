"""
Tests for the detection subsystem.
====================================
Tests the AlertClassifier, IDS Rule engine, MITRE mapping,
and Automated Response Engine.
"""

import pytest
from unittest.mock import MagicMock, patch


# ===========================================================================
# AlertClassifier Tests
# ===========================================================================

class TestAlertClassifier:
    """Tests for the AlertClassifier (Upgrade 2)."""

    def test_classify_brute_force(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "Multiple failed SSH login attempts",
            "description": "5 failed connections from 10.0.0.1",
            "severity": "medium",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
        }
        result = classifier.classify(alert)
        assert result["classification"] == "Brute Force"
        assert result["mitre_technique"] == "T1110"
        assert result["mitre_tactic"] == "Credential Access"
        assert result["severity"] == "high"

    def test_classify_sql_injection(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "SQL Injection attempt detected",
            "description": "UNION SELECT payload in HTTP request",
            "severity": "medium",
            "src_ip": "10.0.0.2",
            "dst_ip": "192.168.1.1",
        }
        result = classifier.classify(alert)
        assert result["classification"] == "SQL Injection"
        assert result["mitre_technique"] == "T1190"
        assert result["severity"] == "critical"

    def test_classify_port_scan(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "Port Scan Detected",
            "description": "Host contacted 100 distinct ports",
            "severity": "low",
            "src_ip": "10.0.0.3",
            "dst_ip": "192.168.1.1",
        }
        result = classifier.classify(alert)
        assert result["classification"] == "Network Scanning"
        assert result["mitre_technique"] == "T1046"

    def test_classify_unknown_defaults_to_suspicious(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "Something weird happened",
            "description": "Unknown anomaly",
            "severity": "low",
            "src_ip": "10.0.0.4",
            "dst_ip": "192.168.1.1",
        }
        result = classifier.classify(alert)
        assert result["classification"] == "Suspicious Activity"

    def test_classify_does_not_overwrite_existing_mitre(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "DNS tunneling detected",
            "description": "Large DNS queries",
            "severity": "medium",
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.1",
            "mitre_technique": "T9999",
            "mitre_tactic": "Custom Tactic",
        }
        result = classifier.classify(alert)
        # Should NOT overwrite the existing mitre fields
        assert result["mitre_technique"] == "T9999"
        assert result["mitre_tactic"] == "Custom Tactic"

    def test_classify_dos_attack(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "Volume-based DDoS flood detected",
            "description": "Impact: Service degradation",
            "severity": "low",
            "src_ip": "10.0.0.6",
            "dst_ip": "192.168.1.1",
        }
        result = classifier.classify(alert)
        assert result["classification"] == "Denial of Service"
        assert result["mitre_technique"] == "T1498"

    def test_classify_dns_tunneling(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "DNS tunneling detected",
            "description": "Abnormally large DNS queries with encoded payloads",
            "severity": "medium",
            "src_ip": "10.0.0.7",
            "dst_ip": "192.168.1.1",
        }
        result = classifier.classify(alert)
        assert result["classification"] == "DNS Tunneling / Amplification"
        assert result["mitre_technique"] == "T1071"

    def test_classify_cleartext_protocol(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "Cleartext FTP session detected",
            "description": "Credentials sent over cleartext FTP",
            "severity": "low",
            "src_ip": "10.0.0.8",
            "dst_ip": "192.168.1.1",
        }
        result = classifier.classify(alert)
        assert result["classification"] == "Cleartext Protocol Usage"
        assert result["mitre_technique"] == "T1040"

    def test_classify_preserves_src_dst_ip(self):
        from backend.detection.classifier import classifier
        alert = {
            "title": "Port Scan Detected",
            "description": "Scanning",
            "severity": "low",
            "src_ip": "10.10.10.10",
            "dst_ip": "192.168.1.1",
        }
        result = classifier.classify(alert)
        assert result["src_ip"] == "10.10.10.10"
        assert result["dst_ip"] == "192.168.1.1"


# ===========================================================================
# IDS Engine Tests
# ===========================================================================

class TestIDSEngine:
    """Tests for the IDS rule engine."""

    def test_ids_engine_has_rules(self):
        from backend.detection.ids import ids_engine
        assert len(ids_engine.rules) > 0

    def test_ids_evaluate_empty_flow_returns_list(self, sample_flow):
        """Evaluating a mock flow with no suspicious activity should return a list."""
        from backend.detection.ids import ids_engine
        result = ids_engine.evaluate_flow(sample_flow)
        assert isinstance(result, list)

    def test_ids_rules_have_required_attributes(self):
        """Each IDS rule should have rule_id, name, mitre_technique."""
        from backend.detection.ids import ids_engine
        for rule in ids_engine.rules:
            assert hasattr(rule, "rule_id")
            assert hasattr(rule, "name")
            assert hasattr(rule, "mitre_technique")
            assert hasattr(rule, "cvss_score")

    def test_ids_rule_has_valid_severity(self):
        """Each rule's severity should be one of the valid levels."""
        from backend.detection.ids import ids_engine
        valid_severities = {"critical", "high", "medium", "low", "info"}
        for rule in ids_engine.rules:
            assert rule.severity in valid_severities, f"Rule {rule.rule_id} has invalid severity: {rule.severity}"


# ===========================================================================
# MITRE Mapping Tests
# ===========================================================================

class TestMitreMapping:
    """Tests for the MITRE ATT&CK mapping module."""

    def test_get_mitre_info_known_technique(self):
        from backend.detection.mitre import get_mitre_info
        info = get_mitre_info("T1110")
        assert info["technique_id"] == "T1110"
        assert info["technique_name"] == "Brute Force"
        assert "Credential Access" in info["tactics"]

    def test_get_mitre_info_unknown_technique(self):
        from backend.detection.mitre import get_mitre_info
        info = get_mitre_info("T9999")
        assert info["technique_name"] == "Unknown Technique"
        assert info["tactics"] == []

    def test_all_tactics_defined(self):
        from backend.detection.mitre import TACTICS
        expected_ids = ["TA0001", "TA0002", "TA0007", "TA0011", "TA0040"]
        for tid in expected_ids:
            assert tid in TACTICS

    def test_techniques_reference_valid_tactics(self):
        from backend.detection.mitre import TACTICS, TECHNIQUES
        for tech_id, tech_info in TECHNIQUES.items():
            for tactic_id in tech_info["tactics"]:
                assert tactic_id in TACTICS, f"Technique {tech_id} references unknown tactic {tactic_id}"


# ===========================================================================
# MITRE Navigator Tests (Upgrade 7)
# ===========================================================================

class TestMitreNavigator:
    """Tests for the MITRE ATT&CK Navigator module."""

    def test_full_techniques_has_all_14_tactics(self):
        from backend.detection.mitre_navigator import FULL_TECHNIQUES, TACTICS_ORDER
        tactic_ids = {tid for tid, _ in TACTICS_ORDER}
        covered = set()
        for tech_info in FULL_TECHNIQUES.values():
            for tid in tech_info["tactics"]:
                covered.add(tid)
        # Every tactic in TACTICS_ORDER should have at least one technique
        for tid in tactic_ids:
            assert tid in covered, f"Tactic {tid} has no techniques in FULL_TECHNIQUES"

    def test_heat_level_mapping(self):
        from backend.detection.mitre_navigator import MitreNavigator
        nav = MitreNavigator()
        assert nav._heat_level(0) == "none"
        assert nav._heat_level(1) == "low"
        assert nav._heat_level(5) == "medium"
        assert nav._heat_level(15) == "high"
        assert nav._heat_level(50) == "critical"

    @patch("backend.detection.mitre_navigator.get_session")
    def test_get_matrix_returns_expected_structure(self, mock_get_session):
        from backend.detection.mitre_navigator import MitreNavigator
        # Mock the session to return no alerts
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.all.return_value = []
        mock_get_session.return_value = mock_session

        nav = MitreNavigator()
        matrix = nav.get_matrix()

        assert "tactics" in matrix
        assert "matrix" in matrix
        assert "total_techniques" in matrix
        assert "detected_techniques" in matrix
        assert "coverage_percent" in matrix
        assert matrix["detected_techniques"] == 0
        assert len(matrix["tactics"]) == 14  # 14 tactics

    @patch("backend.detection.mitre_navigator.get_session")
    def test_get_coverage_returns_expected_structure(self, mock_get_session):
        from backend.detection.mitre_navigator import MitreNavigator
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.all.return_value = []
        mock_get_session.return_value = mock_session

        nav = MitreNavigator()
        coverage = nav.get_coverage()

        assert "overall" in coverage
        assert "tactics" in coverage
        assert len(coverage["tactics"]) == 14


# ===========================================================================
# Automated Response Engine Tests (Upgrade 6)
# ===========================================================================

class TestResponseEngine:
    """Tests for the Automated Response Engine."""

    def test_response_engine_default_config(self):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        config = engine.get_config()
        assert config["enabled"] is True
        assert config["threshold_full"] == 90
        assert config["threshold_partial"] == 75
        assert config["cooldown_seconds"] == 300

    def test_update_config(self):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        engine.update_config({"enabled": False, "threshold_full": 95})
        config = engine.get_config()
        assert config["enabled"] is False
        assert config["threshold_full"] == 95

    def test_no_response_when_disabled(self):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        engine.config["enabled"] = False
        results = engine.evaluate_and_respond("10.0.0.1", risk_score=99)
        assert results == []

    def test_no_response_below_threshold(self):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        results = engine.evaluate_and_respond("10.0.0.1", risk_score=50)
        assert results == []

    @patch("backend.response.response_engine.get_session")
    @patch("backend.response.response_engine.response_engine")
    def test_notifications_tracking(self, mock_engine, mock_session):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        # Directly test notification tracking
        assert engine.get_notifications() == []
        engine.notifications.append({"test": True})
        assert len(engine.get_notifications()) == 1

    def test_cooldown_prevents_duplicate_responses(self):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        engine.config["cooldown_seconds"] = 9999  # Long cooldown
        # Simulate that this IP was just acted on
        import time
        engine._cooldown_tracker["10.0.0.1"] = time.time()
        results = engine.evaluate_and_respond("10.0.0.1", risk_score=99)
        assert results == []

    def test_config_update_ignores_invalid_keys(self):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        engine.update_config({"invalid_key": "should_be_ignored", "enabled": True})
        config = engine.get_config()
        assert "invalid_key" not in config
        assert config["enabled"] is True
