"""
Tests for the capture subsystem.
==================================
Tests sniffer status management and PCAP analyzer.
"""

import os
import pytest
from unittest.mock import MagicMock, patch


class TestPacketSniffer:
    """Tests for the PacketSniffer class."""

    def test_sniffer_initial_state(self):
        from backend.capture.sniffer import PacketSniffer
        s = PacketSniffer()
        assert not s.is_running
        assert not s.is_paused
        assert s.packet_count == 0

    def test_sniffer_status(self):
        from backend.capture.sniffer import PacketSniffer
        s = PacketSniffer()
        status = s.get_status()
        assert isinstance(status, dict)
        assert "running" in status
        assert status["running"] is False

    @patch("backend.capture.sniffer.sniff")
    def test_sniffer_start_stop(self, mock_sniff):
        """Start and stop should toggle state without crashing."""
        from backend.capture.sniffer import PacketSniffer
        s = PacketSniffer()
        # Start with a dummy callback
        mock_sniff.return_value = None
        s.start("lo0", callback=lambda pkt: None)
        assert s.is_running
        s.stop()
        assert not s.is_running


class TestPcapAnalyzer:
    """Tests for the PCAP analysis pipeline."""

    def test_analyse_pcap_file_not_found(self):
        from backend.capture.pcap_analyzer import analyse_pcap
        result = analyse_pcap("/nonexistent/file.pcap")
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_analyse_pcap_returns_required_keys(self):
        """If sample_traffic.pcap exists, verify the return schema."""
        from backend.capture.pcap_analyzer import analyse_pcap
        sample = os.path.join(
            os.path.dirname(__file__), "..", "backend", "data", "uploads", "sample_traffic.pcap"
        )
        if not os.path.exists(sample):
            pytest.skip("sample_traffic.pcap not available")

        result = analyse_pcap(sample, max_packets=20)
        assert "error" not in result
        assert "total_packets" in result
        assert "protocol_hierarchy" in result
        assert "endpoints" in result
        assert "threat_summary" in result  # Upgrade 7

    def test_pcap_threat_summary_structure(self):
        """Verify threat_summary contains the expected fields."""
        from backend.capture.pcap_analyzer import analyse_pcap
        sample = os.path.join(
            os.path.dirname(__file__), "..", "backend", "data", "uploads", "sample_traffic.pcap"
        )
        if not os.path.exists(sample):
            pytest.skip("sample_traffic.pcap not available")

        result = analyse_pcap(sample, max_packets=20)
        ts = result.get("threat_summary")
        assert ts is not None
        assert "threat_verdict" in ts
        assert "suspicious_count" in ts
        assert "top_talkers" in ts
        assert isinstance(ts["top_talkers"], list)
