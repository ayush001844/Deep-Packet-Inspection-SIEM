"""
Zero Trust Risk Scoring Engine
================================
Assigns a composite 0–100 risk score to each IP based on multiple weighted factors.
"""

from __future__ import annotations

import time
from typing import Any


# Risk factor weights (total can exceed 100; score is capped at 100)
WEIGHTS = {
    "threat_feed_hit": 30,
    "anomalous_volume": 20,
    "known_bad_ja3": 25,
    "beaconing": 20,
    "cleartext_protocol": 10,
    "geo_risk": 15,
}

# High-risk country codes (for geo-risk scoring)
HIGH_RISK_COUNTRIES = {
    "RU", "CN", "KP", "IR", "SY", "BY", "VE", "CU",
}


class RiskScorer:
    """
    Maintains risk scores per IP.
    
    Scores are computed as the sum of weighted risk factors:
      - Threat feed hit:       +30
      - Anomalous traffic:     +20
      - Known-bad JA3:         +25
      - Beaconing behavior:    +20
      - Cleartext protocols:   +10
      - Geo-risk (high-risk):  +15
    
    Score is capped at 100.
    """

    def __init__(self):
        # ip -> {factor_name: True/False, ...}
        self._factors: dict[str, dict[str, bool]] = {}
        # ip -> last_update_time
        self._updated: dict[str, float] = {}

    def _ensure_ip(self, ip: str) -> None:
        if ip not in self._factors:
            self._factors[ip] = {k: False for k in WEIGHTS}
            self._updated[ip] = time.time()

    def add_factor(self, ip: str, factor: str) -> None:
        """Mark a risk factor as present for an IP."""
        if factor not in WEIGHTS:
            return
        self._ensure_ip(ip)
        self._factors[ip][factor] = True
        self._updated[ip] = time.time()

    def get_score(self, ip: str) -> int:
        """Compute the composite risk score for an IP."""
        if ip not in self._factors:
            return 0
        score = sum(
            WEIGHTS[factor]
            for factor, active in self._factors[ip].items()
            if active
        )
        return min(100, score)

    def get_risk_level(self, ip: str) -> str:
        """Return a human-readable risk level."""
        score = self.get_score(ip)
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        elif score > 0:
            return "low"
        return "clean"

    def get_all_scores(self) -> list[dict[str, Any]]:
        """Return risk scores for all tracked IPs."""
        results = []
        for ip in self._factors:
            score = self.get_score(ip)
            if score > 0:
                results.append({
                    "ip": ip,
                    "score": score,
                    "level": self.get_risk_level(ip),
                    "factors": {
                        k: v for k, v in self._factors[ip].items() if v
                    },
                    "last_updated": self._updated.get(ip, 0),
                })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    def check_geo_risk(self, ip: str, country_code: str) -> None:
        """Check if the IP's country is in the high-risk set."""
        if country_code and country_code.upper() in HIGH_RISK_COUNTRIES:
            self.add_factor(ip, "geo_risk")


# Global singleton
risk_scorer = RiskScorer()
