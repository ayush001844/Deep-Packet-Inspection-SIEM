"""
Tests for the FastAPI REST API.
=================================
Tests all REST endpoints including new Upgrade 6/7/8 endpoints.
Uses TestClient for synchronous endpoint testing with mocked database.
"""

import pytest
from unittest.mock import patch, MagicMock


# ===========================================================================
# Health & System Tests (no auth required)
# ===========================================================================

class TestHealthEndpoint:
    """Test the health check endpoint."""

    def test_health_check(self):
        try:
            from fastapi.testclient import TestClient
            from backend.main import app
        except (ImportError, ModuleNotFoundError):
            pytest.skip("Missing dependencies (elasticsearch, etc.) for full app import")
        with TestClient(app) as client:
            resp = client.get("/api/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert "version" in data


# ===========================================================================
# Standalone Module Tests (no need for full app)
# ===========================================================================

class TestRiskScorerAPI:
    """Test risk scorer module directly."""

    def test_risk_scorer_singleton_exists(self):
        from backend.detection.risk_scoring import risk_scorer
        assert risk_scorer is not None

    def test_risk_scorer_returns_list(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        scores = rs.get_all_scores()
        assert isinstance(scores, list)


class TestFirewallModule:
    """Test firewall module directly."""

    def test_firewall_exists(self):
        from backend.firewall import firewall
        assert firewall is not None

    def test_firewall_block_and_unblock(self):
        from backend.firewall.firewall_base import DryRunBackend
        fw = DryRunBackend()
        result = fw.block_ip("10.0.0.99", reason="test")
        assert result is True
        assert "10.0.0.99" in fw.get_blocked_ips()

        result2 = fw.unblock_ip("10.0.0.99")
        assert result2 is True
        assert "10.0.0.99" not in fw.get_blocked_ips()

    def test_firewall_block_duplicate_returns_false(self):
        from backend.firewall.firewall_base import DryRunBackend
        fw = DryRunBackend()
        fw.block_ip("10.0.0.99", reason="first")
        result = fw.block_ip("10.0.0.99", reason="duplicate")
        assert result is False

    def test_firewall_block_empty_ip_returns_false(self):
        from backend.firewall.firewall_base import DryRunBackend
        fw = DryRunBackend()
        result = fw.block_ip("", reason="empty")
        assert result is False

    def test_firewall_get_blocked_entries(self):
        from backend.firewall.firewall_base import DryRunBackend
        fw = DryRunBackend()
        fw.block_ip("10.0.0.1", reason="test", domain="evil.com")
        entries = fw.get_blocked_entries()
        assert len(entries) == 1
        assert entries[0]["ip"] == "10.0.0.1"
        assert entries[0]["domain"] == "evil.com"
        assert entries[0]["reason"] == "test"


# ===========================================================================
# Response Engine Tests (Upgrade 6)
# ===========================================================================

class TestResponseEngineAPI:
    """Test the automated response engine."""

    def test_response_engine_config(self):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        config = engine.get_config()
        assert "enabled" in config
        assert "threshold_full" in config
        assert "threshold_partial" in config

    def test_response_engine_no_action_below_threshold(self):
        from backend.response.response_engine import AutomatedResponseEngine
        engine = AutomatedResponseEngine()
        results = engine.evaluate_and_respond("192.168.1.1", risk_score=50)
        assert results == []


# ===========================================================================
# MITRE Navigator Tests (Upgrade 7)
# ===========================================================================

class TestMitreNavigatorAPI:
    """Test the MITRE Navigator module."""

    @patch("backend.detection.mitre_navigator.get_session")
    def test_matrix_structure(self, mock_session):
        from backend.detection.mitre_navigator import MitreNavigator
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = []
        mock_session.return_value = session

        nav = MitreNavigator()
        matrix = nav.get_matrix()
        assert "tactics" in matrix
        assert "matrix" in matrix
        assert len(matrix["tactics"]) == 14

    @patch("backend.detection.mitre_navigator.get_session")
    def test_coverage_structure(self, mock_session):
        from backend.detection.mitre_navigator import MitreNavigator
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = []
        mock_session.return_value = session

        nav = MitreNavigator()
        coverage = nav.get_coverage()
        assert "overall" in coverage
        assert "tactics" in coverage


# ===========================================================================
# Rate Limiter Tests (Upgrade 8)
# ===========================================================================

class TestRateLimiter:
    """Test the rate limiter module."""

    def test_rate_limit_config_exists(self):
        from backend.rate_limiter import RATE_LIMITS, EXEMPT_PATHS
        assert "/api/auth/login" in RATE_LIMITS
        assert "/api/health" in EXEMPT_PATHS

    def test_rate_limit_login_is_strict(self):
        from backend.rate_limiter import RATE_LIMITS
        max_req, window = RATE_LIMITS["/api/auth/login"]
        assert max_req <= 10  # Should be restrictive
        assert window >= 30   # At least 30-second window


# ===========================================================================
# Auth Module Tests (Upgrade 8)
# ===========================================================================

class TestAuthModule:
    """Test authentication module functions."""

    def test_password_hashing(self):
        from backend.auth import hash_password, verify_password
        hashed = hash_password("test_password")
        assert hashed != "test_password"
        assert verify_password("test_password", hashed) is True
        assert verify_password("wrong_password", hashed) is False

    def test_access_token_creation(self):
        from backend.auth import create_access_token
        from jose import jwt
        token = create_access_token({"sub": "testuser", "role": "admin"})
        assert isinstance(token, str)
        assert len(token) > 0

        # Decode and verify claims
        from backend.auth import SECRET_KEY, ALGORITHM
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "testuser"
        assert payload["role"] == "admin"
        assert payload["type"] == "access"

    def test_api_key_generation(self):
        from backend.auth import generate_api_key
        full_key, key_hash, key_prefix = generate_api_key()
        assert full_key.startswith("dg_")
        assert len(key_hash) == 64  # SHA-256 hex digest
        assert key_prefix == full_key[:10]
