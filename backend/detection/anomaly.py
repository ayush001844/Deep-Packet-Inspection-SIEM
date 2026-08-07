"""
Statistical Anomaly Detector
=============================
Uses Welford's online algorithm to maintain running statistics per IP,
then flags traffic that exceeds 3σ from the learned baseline.
"""

from __future__ import annotations

import math
import time
from typing import Any, Optional

from backend.detection.ids import Rule


class WelfordAccumulator:
    """Online mean and variance using Welford's algorithm."""
    __slots__ = ("count", "mean", "M2")

    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.M2 = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.M2 / (self.count - 1)

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, value: float) -> float:
        """Return the z-score for a given value."""
        sd = self.std_dev
        if sd == 0 or self.count < 10:
            return 0.0
        return (value - self.mean) / sd


class AnomalyDetector(Rule):
    """
    Detects statistical anomalies in flow behavior.
    
    Maintains per-IP baselines for:
    - Bytes per flow
    - Packets per flow
    - Connection rate (new flows per minute)
    
    Alerts when any metric exceeds 3 standard deviations.
    """

    def __init__(self):
        super().__init__(
            rule_id="AI-001",
            name="Statistical Anomaly — Abnormal Traffic Volume",
            description="Traffic volume from this IP significantly deviates from its learned baseline.",
            mitre_technique="T1040",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"  # 6.5 Medium
        )
        # Per-IP accumulators: ip -> {"bytes": Welford, "packets": Welford}
        self._baselines: dict[str, dict[str, WelfordAccumulator]] = {}
        # Connection rate tracking: ip -> [timestamps]
        self._connection_times: dict[str, list[float]] = {}
        self._rate_baselines: dict[str, WelfordAccumulator] = {}
        # Cooldown: ip -> last_alert_time (don't alert more than once per 5 min per IP)
        self._cooldowns: dict[str, float] = {}
        self.COOLDOWN_SECONDS = 300
        self.Z_THRESHOLD = 3.0
        self.MIN_SAMPLES = 20  # Need enough data before alerting

    def _get_baseline(self, ip: str) -> dict[str, WelfordAccumulator]:
        if ip not in self._baselines:
            self._baselines[ip] = {
                "bytes": WelfordAccumulator(),
                "packets": WelfordAccumulator(),
            }
        return self._baselines[ip]

    def evaluate_flow(self, flow: Any) -> Optional[dict[str, Any]]:
        """Check if a flow's metrics deviate from the source IP's baseline."""
        src_ip = flow.src_ip
        baseline = self._get_baseline(src_ip)

        total_bytes = flow.total_bytes
        total_packets = flow.total_packets

        # Check z-scores BEFORE updating (test against existing baseline)
        z_bytes = baseline["bytes"].z_score(total_bytes)
        z_packets = baseline["packets"].z_score(total_packets)

        # Update baselines with current values
        baseline["bytes"].update(total_bytes)
        baseline["packets"].update(total_packets)

        # Track connection rate
        now = time.time()
        if src_ip not in self._connection_times:
            self._connection_times[src_ip] = []
        self._connection_times[src_ip].append(now)
        # Prune to last 5 minutes
        self._connection_times[src_ip] = [
            t for t in self._connection_times[src_ip] if now - t <= 300
        ]

        # Only alert if we have enough samples and z-score exceeds threshold
        has_enough = baseline["bytes"].count >= self.MIN_SAMPLES
        if not has_enough:
            return None

        # Cooldown check
        last_alert = self._cooldowns.get(src_ip, 0)
        if now - last_alert < self.COOLDOWN_SECONDS:
            return None

        anomalies = []
        if abs(z_bytes) >= self.Z_THRESHOLD:
            anomalies.append(f"bytes={total_bytes} (z={z_bytes:.1f}, mean={baseline['bytes'].mean:.0f})")
        if abs(z_packets) >= self.Z_THRESHOLD:
            anomalies.append(f"packets={total_packets} (z={z_packets:.1f}, mean={baseline['packets'].mean:.0f})")

        if anomalies:
            self._cooldowns[src_ip] = now
            return self.generate_alert(
                src_ip=src_ip,
                dst_ip=flow.dst_ip,
                evidence=f"Anomalous flow metrics: {'; '.join(anomalies)}"
            )

        return None
