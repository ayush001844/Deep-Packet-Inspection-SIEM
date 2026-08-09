"""
Tests for the FastAPI REST API.
=================================
Uses TestClient for synchronous endpoint testing.
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a test client for the FastAPI app."""
    from backend.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers(client):
    """Login with default credentials and return auth headers."""
    resp = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "admin123",
    })
    if resp.status_code == 200:
        token = resp.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}
    # If login fails (e.g., user not seeded), return empty
    return {}


class TestHealthEndpoint:
    def test_health_check(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"


class TestStatsEndpoint:
    def test_get_stats(self, client, auth_headers):
        resp = client.get("/api/stats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "packets_total" in data
        assert "protocol_distribution" in data
        assert "flows" in data
        assert "capture" in data


class TestPacketsEndpoint:
    def test_get_packets(self, client, auth_headers):
        resp = client.get("/api/packets", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_get_packets_with_limit(self, client, auth_headers):
        resp = client.get("/api/packets?limit=5", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) <= 5


class TestAlertsEndpoint:
    def test_get_alerts(self, client, auth_headers):
        resp = client.get("/api/alerts", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


class TestCaptureEndpoints:
    def test_get_interfaces(self, client, auth_headers):
        resp = client.get("/api/interfaces", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_capture_status(self, client, auth_headers):
        resp = client.get("/api/capture/status", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "running" in data


class TestSessionsEndpoint:
    def test_get_sessions(self, client, auth_headers):
        resp = client.get("/api/sessions", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


class TestFirewallEndpoints:
    def test_get_blocked(self, client, auth_headers):
        resp = client.get("/api/firewall/blocked", headers=auth_headers)
        assert resp.status_code == 200


class TestIncidentsEndpoint:
    def test_get_incidents(self, client, auth_headers):
        resp = client.get("/api/incidents", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


class TestNetworkEndpoint:
    def test_get_graph(self, client, auth_headers):
        resp = client.get("/api/network/graph", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "links" in data


class TestRiskEndpoint:
    def test_get_risk_scores(self, client, auth_headers):
        resp = client.get("/api/risk/scores", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


class TestMLEndpoints:
    def test_ml_status(self, client, auth_headers):
        resp = client.get("/api/ml/status", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "model_loaded" in data

    def test_ml_recent(self, client, auth_headers):
        resp = client.get("/api/ml/recent", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
