"""
UEBA — User Baseline Tracker
==============================
Maintains rolling statistics per user for behavior analysis.
Uses Welford's online algorithm for running mean & variance (memory efficient).
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class UserBaseline:
    username: str

    # Login hour statistics (0–23)
    login_hour_count: int   = 0
    login_hour_mean:  float = 12.0
    login_hour_m2:    float = 0.0    # For Welford variance

    # Known login countries (set)
    known_countries: set[str] = field(default_factory=set)
    login_country_counts: dict[str, int] = field(default_factory=dict)

    # File access statistics (files/session)
    file_access_count: int   = 0
    file_access_mean:  float = 20.0
    file_access_m2:    float = 0.0

    # Auth failures (rolling 24h)
    auth_failures: int = 0
    auth_failure_reset: float = field(default_factory=time.time)

    # Source IP history
    known_ips: set[str] = field(default_factory=set)

    # Timestamps
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)
    total_events: int = 0

    def _welford_update(self, count: int, mean: float, m2: float, value: float):
        """Welford's online algorithm for running mean + variance."""
        count += 1
        delta  = value - mean
        mean  += delta / count
        delta2 = value - mean
        m2    += delta * delta2
        return count, mean, m2

    @staticmethod
    def _variance(count: int, m2: float) -> float:
        if count < 2:
            return 0.0
        return m2 / (count - 1)

    @staticmethod
    def _std(count: int, m2: float) -> float:
        return math.sqrt(UserBaseline._variance(count, m2))

    # ── Update methods ────────────────────────────────────────────────────────

    def record_login(self, hour: int, country: str, src_ip: str):
        self.login_hour_count, self.login_hour_mean, self.login_hour_m2 = \
            self._welford_update(self.login_hour_count, self.login_hour_mean, self.login_hour_m2, hour)
        if country:
            self.known_countries.add(country)
            self.login_country_counts[country] = self.login_country_counts.get(country, 0) + 1
        if src_ip:
            self.known_ips.add(src_ip)
        self.last_seen = time.time()
        self.total_events += 1

    def record_file_access(self, file_count: int):
        self.file_access_count, self.file_access_mean, self.file_access_m2 = \
            self._welford_update(self.file_access_count, self.file_access_mean, self.file_access_m2, file_count)
        self.total_events += 1

    def record_auth_failure(self):
        # Reset counter after 24h
        if time.time() - self.auth_failure_reset > 86400:
            self.auth_failures = 0
            self.auth_failure_reset = time.time()
        self.auth_failures += 1

    # ── Z-score helpers ───────────────────────────────────────────────────────

    def login_hour_zscore(self, hour: int) -> float:
        std = self._std(self.login_hour_count, self.login_hour_m2)
        if std < 0.5:
            return 0.0
        return abs(hour - self.login_hour_mean) / std

    def file_access_zscore(self, file_count: int) -> float:
        std = self._std(self.file_access_count, self.file_access_m2)
        if std < 1.0:
            return 0.0
        return (file_count - self.file_access_mean) / max(std, 1.0)

    def is_new_country(self, country: str) -> bool:
        return bool(country) and country not in self.known_countries

    def is_new_ip(self, src_ip: str) -> bool:
        return bool(src_ip) and src_ip not in self.known_ips

    def to_dict(self) -> dict[str, Any]:
        return {
            "username":     self.username,
            "login_hour_mean": round(self.login_hour_mean, 1),
            "login_hour_std":  round(self._std(self.login_hour_count, self.login_hour_m2), 2),
            "known_countries": list(self.known_countries),
            "login_country_counts": self.login_country_counts,
            "file_access_mean": round(self.file_access_mean, 1),
            "file_access_std":  round(self._std(self.file_access_count, self.file_access_m2), 2),
            "auth_failures_24h": self.auth_failures,
            "known_ips_count":   len(self.known_ips),
            "total_events":      self.total_events,
            "first_seen":        self.first_seen,
            "last_seen":         self.last_seen,
        }
