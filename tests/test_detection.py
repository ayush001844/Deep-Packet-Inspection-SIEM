"""
Tests for the detection subsystem.
====================================
Tests the AlertClassifier and IDS Rule engine.
"""

import pytest


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


class TestIDSEngine:
    """Tests for the IDS rule engine."""

    def test_ids_engine_has_rules(self):
        from backend.detection.ids import ids_engine
        assert len(ids_engine.rules) > 0

    def test_ids_evaluate_empty_flow_returns_list(self):
        """Evaluating a mock flow with no suspicious activity should return a list."""
        from backend.detection.ids import ids_engine
        from unittest.mock import MagicMock

        mock_flow = MagicMock()
        mock_flow.src_ip = "192.168.1.1"
        mock_flow.dst_ip = "10.0.0.1"
        mock_flow.protocol = "TCP"
        mock_flow.total_packets = 5
        mock_flow.total_bytes = 500
        mock_flow.dst_port = 80
        mock_flow.distinct_dst_ports = set()
        mock_flow.duration = 10.0
        mock_flow.payload_sizes = [100, 100, 100, 100, 100]
        mock_flow.packet_times = [1.0, 2.0, 3.0, 4.0, 5.0]

        result = ids_engine.evaluate_flow(mock_flow)
        assert isinstance(result, list)
