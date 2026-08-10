"""
UEBA Behavior Engine
=====================
Processes user events, compares against baselines, and generates alerts
for anomalous behavior (off-hours logins, new country, data exfil, etc.)

Event schema:
{
  "username": "ayush",
  "event_type": "login" | "file_access" | "auth_failure" | "logout",
  "timestamp": 1234567890.0,
  "src_ip": "1.2.3.4",
  "country": "IN",
  "hour": 10,                  # 0–23 UTC
  "file_count": 20,            # for file_access events
  "success": true,             # for login/auth events
}
"""
from __future__ import annotations

import time
from collections import deque
from typing import Any, Optional

from backend.ueba.baseline import UserBaseline


# ── Thresholds ────────────────────────────────────────────────────────────────
HOUR_ZSCORE_THRESHOLD      = 2.5   # ~99th percentile
FILE_ZSCORE_THRESHOLD      = 3.0   # >3x typical volume
AUTH_FAILURE_THRESHOLD     = 5     # failures in 24h
MIN_EVENTS_FOR_BASELINE    = 5     # minimum events before flagging anomalies


class UEBAEngine:
    """
    Core UEBA processing engine.
    Thread-safe via Python's GIL for single-process FastAPI usage.
    """

    def __init__(self):
        self._baselines: dict[str, UserBaseline] = {}
        self._alerts: deque[dict[str, Any]] = deque(maxlen=500)

    def _get_or_create(self, username: str) -> UserBaseline:
        if username not in self._baselines:
            self._baselines[username] = UserBaseline(username=username)
        return self._baselines[username]

    # ── Public API ────────────────────────────────────────────────────────────

    def process_event(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """
        Ingest a user event, update baseline, and check for anomalies.
        Returns an alert dict if anomalous, else None.
        """
        username   = event.get("username", "unknown")
        event_type = event.get("event_type", "")
        timestamp  = event.get("timestamp", time.time())
        src_ip     = event.get("src_ip", "")
        country    = event.get("country", "")
        hour       = int(event.get("hour", 12))
        file_count = int(event.get("file_count", 0))
        success    = event.get("success", True)

        baseline = self._get_or_create(username)
        alerts: list[str] = []

        if event_type == "login":
            if success:
                # Check BEFORE updating baseline so we see deviations
                if baseline.total_events >= MIN_EVENTS_FOR_BASELINE:
                    # Off-hours login
                    hz = baseline.login_hour_zscore(hour)
                    if hz > HOUR_ZSCORE_THRESHOLD:
                        alerts.append(f"Login at unusual hour ({hour:02d}:00 UTC, z={hz:.1f}σ)")

                    # New country
                    if baseline.is_new_country(country) and country:
                        known = ", ".join(list(baseline.known_countries)[:3]) or "none"
                        alerts.append(f"Login from new country: {country} (known: {known})")

                    # New IP
                    if baseline.is_new_ip(src_ip) and src_ip:
                        alerts.append(f"Login from new IP address: {src_ip}")

                baseline.record_login(hour, country, src_ip)
            else:
                baseline.record_auth_failure()
                if baseline.auth_failures >= AUTH_FAILURE_THRESHOLD:
                    alerts.append(f"Excessive authentication failures: {baseline.auth_failures} in 24h")

        elif event_type == "file_access":
            if baseline.total_events >= MIN_EVENTS_FOR_BASELINE and file_count > 0:
                fz = baseline.file_access_zscore(file_count)
                if fz > FILE_ZSCORE_THRESHOLD:
                    alerts.append(
                        f"Abnormal file access volume: {file_count} files "
                        f"(baseline avg={baseline.file_access_mean:.0f}, z={fz:.1f}σ) — possible data exfiltration"
                    )
            baseline.record_file_access(file_count)

        elif event_type == "auth_failure":
            baseline.record_auth_failure()
            if baseline.auth_failures >= AUTH_FAILURE_THRESHOLD:
                alerts.append(f"Excessive auth failures: {baseline.auth_failures} in 24h")

        # Build alert if anomalies found
        if alerts:
            alert = {
                "id":         f"ueba-{username}-{int(timestamp)}",
                "username":   username,
                "event_type": event_type,
                "src_ip":     src_ip,
                "country":    country,
                "hour":       hour,
                "timestamp":  timestamp,
                "anomalies":  alerts,
                "message":    " | ".join(alerts),
                "severity":   self._severity(alerts),
                "title":      f"UEBA Alert: {username}",
                "source":     "ueba",
            }
            self._alerts.appendleft(alert)
            return alert

        return None

    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        return list(self._alerts)[:limit]

    def get_baseline(self, username: str) -> Optional[dict]:
        if username in self._baselines:
            return self._baselines[username].to_dict()
        return None

    def all_baselines(self) -> list[dict]:
        return [b.to_dict() for b in self._baselines.values()]

    def get_stats(self) -> dict[str, Any]:
        return {
            "tracked_users": len(self._baselines),
            "total_alerts":  len(self._alerts),
            "recent_alerts": list(self._alerts)[:5],
        }

    @staticmethod
    def _severity(anomalies: list[str]) -> str:
        text = " ".join(anomalies).lower()
        if "country" in text or "exfiltration" in text or "excessive" in text:
            return "high"
        if "unusual hour" in text or "new ip" in text:
            return "medium"
        return "low"


# Singleton
ueba_engine = UEBAEngine()
