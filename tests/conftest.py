"""
Shared pytest fixtures for DeepGuard tests.
=============================================
Provides database environment setup, sample test data, and auth helpers.

IMPORTANT: This conftest sets up a SQLite in-memory database for testing
so that tests don't require a running PostgreSQL instance.
"""

import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Set environment to use SQLite for testing BEFORE any backend imports
# ---------------------------------------------------------------------------

# Override the DATABASE_URL to use SQLite in-memory for tests
# We also need to bypass the "SQLite is no longer supported" check in database.py
os.environ["DATABASE_URL"] = "sqlite:///test_deepguard.db"


@pytest.fixture
def sample_alert():
    """A sample alert dictionary for testing."""
    return {
        "title": "Multiple failed SSH login attempts",
        "description": "5 failed connections from 10.0.0.1 to port 22",
        "severity": "medium",
        "src_ip": "10.0.0.1",
        "dst_ip": "192.168.1.1",
        "protocol": "TCP",
    }


@pytest.fixture
def sample_critical_alert():
    """A sample critical-severity alert."""
    return {
        "title": "SQL Injection attempt detected",
        "description": "UNION SELECT payload in HTTP request from 45.33.32.156",
        "severity": "medium",
        "src_ip": "45.33.32.156",
        "dst_ip": "192.168.1.10",
        "protocol": "TCP",
    }


@pytest.fixture
def sample_packet():
    """A sample parsed packet record."""
    return {
        "id": 1,
        "timestamp": 1691234567.123,
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "src_port": 54321,
        "dst_port": 53,
        "protocol": "UDP",
        "length": 64,
        "summary": "DNS query for example.com",
        "layers": {"DNS": {"qname": "example.com", "qtype": "A"}},
    }


@pytest.fixture
def sample_flow():
    """A mock flow object for IDS testing."""
    flow = MagicMock()
    flow.src_ip = "192.168.1.100"
    flow.dst_ip = "10.0.0.1"
    flow.protocol = "TCP"
    flow.total_packets = 5
    flow.total_bytes = 500
    flow.dst_port = 80
    flow.distinct_dst_ports = set()
    flow.duration = 10.0
    flow.payload_sizes = [100, 100, 100, 100, 100]
    flow.packet_times = [1.0, 2.0, 3.0, 4.0, 5.0]
    return flow


def pytest_sessionfinish(session, exitstatus):
    """Cleanup: remove test database file after all tests."""
    try:
        if os.path.exists("test_deepguard.db"):
            os.remove("test_deepguard.db")
    except Exception:
        pass
