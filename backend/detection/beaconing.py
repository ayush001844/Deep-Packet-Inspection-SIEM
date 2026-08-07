"""
C2 Beaconing Detector
======================
Detects Command & Control beaconing by analyzing the regularity of
connection intervals. Periodic, low-variance communication patterns
are strong indicators of automated C2 check-ins.

Detection method:
  - Track inter-arrival times for flows to each (dst_ip, dst_port) pair.
  - Compute coefficient of variation (CV = stddev / mean) of intervals.
  - CV < 0.3 with ≥10 samples → high-confidence beaconing.
  - Also check data-size variance (heartbeats tend to have uniform size).
"""

from __future__ import annotations

import math
import time
from typing import Any, Optional

from backend.detection.ids import Rule


class BeaconingDetector(Rule):
    """Detects periodic C2 beaconing patterns in network flows."""

    def __init__(self):
        super().__init__(
            rule_id="AI-003",
            name="C2 Beaconing Detected",
            description="Periodic connection pattern consistent with Command & Control beaconing behavior.",
            mitre_technique="T1071",  # Application Layer Protocol
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"  # 10.0 Critical
        )
        # Track: (src_ip, dst_ip, dst_port) -> {"times": [float], "sizes": [int]}
        self._tracker: dict[str, dict[str, list]] = {}
        self.MIN_SAMPLES = 10
        self.CV_THRESHOLD = 0.3  # Low CV = high periodicity
        self.COOLDOWN = 600  # Don't alert same beacon pattern within 10 min
        self._cooldowns: dict[str, float] = {}

    def _key(self, src_ip: str, dst_ip: str, dst_port: int) -> str:
        return f"{src_ip}->{dst_ip}:{dst_port}"

    def evaluate_flow(self, flow: Any) -> Optional[dict[str, Any]]:
        """Track flow timing and detect periodic patterns."""
        if not flow.syn_seen:
            return None  # Only track new connections

        key = self._key(flow.src_ip, flow.dst_ip, flow.dst_port)
        now = time.time()

        # Initialize tracker
        if key not in self._tracker:
            self._tracker[key] = {"times": [], "sizes": []}

        tracker = self._tracker[key]
        tracker["times"].append(now)
        tracker["sizes"].append(flow.total_bytes)

        # Prune old entries (keep last 2 hours)
        cutoff = now - 7200
        while tracker["times"] and tracker["times"][0] < cutoff:
            tracker["times"].pop(0)
            tracker["sizes"].pop(0)

        # Need enough samples
        if len(tracker["times"]) < self.MIN_SAMPLES:
            return None

        # Cooldown check
        last_alert = self._cooldowns.get(key, 0)
        if now - last_alert < self.COOLDOWN:
            return None

        # Compute inter-arrival intervals
        times = tracker["times"]
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]

        if not intervals:
            return None

        # Compute coefficient of variation for intervals
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            return None

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        cv_interval = std_dev / mean_interval

        # Also compute CV for data sizes
        sizes = tracker["sizes"]
        mean_size = sum(sizes) / len(sizes) if sizes else 0
        if mean_size > 0:
            size_variance = sum((x - mean_size) ** 2 for x in sizes) / len(sizes)
            cv_size = math.sqrt(size_variance) / mean_size
        else:
            cv_size = 1.0  # High variance = not suspicious

        # Detection: low interval CV indicates periodic behavior
        is_periodic = cv_interval < self.CV_THRESHOLD
        is_uniform_size = cv_size < 0.5

        if is_periodic:
            self._cooldowns[key] = now
            confidence = "HIGH" if is_uniform_size else "MEDIUM"
            return self.generate_alert(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                evidence=(
                    f"Periodic beaconing detected → {flow.dst_ip}:{flow.dst_port}. "
                    f"Interval CV={cv_interval:.3f} (threshold <{self.CV_THRESHOLD}), "
                    f"mean interval={mean_interval:.1f}s, samples={len(intervals)}, "
                    f"size CV={cv_size:.3f}, confidence={confidence}"
                )
            )

        return None

    def evaluate_packet(self, packet: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Not used — beaconing is flow-based."""
        return None
