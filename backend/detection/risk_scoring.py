"""
Dynamic ML Risk Scoring Engine
================================
Composite risk score formula:

  Risk = (ml_confidence × 40)
       + (threat_reputation × 25)
       + (attack_severity_score × 20)
       + (asset_importance × 15)

All components are 0–1 normalised; final score is 0–100.
"""
from __future__ import annotations

import time
from typing import Any


# ── Severity → numeric weight ─────────────────────────────────────────────────
SEVERITY_SCORE = {
    "critical": 1.0,
    "high":     0.75,
    "medium":   0.50,
    "low":      0.25,
    "info":     0.05,
}

# ── Classic rule-based factors (still supported for IDS alerts) ──────────────
RULE_WEIGHTS = {
    "ids_alert":          15,
    "ml_high_confidence": 10,
    "threat_feed_hit":    12,
    "anomalous_volume":   10,
    "known_bad_ja3":      12,
    "beaconing":          10,
    "cleartext_protocol":  5,
    "geo_risk":            8,
}

# ── High-risk country codes ───────────────────────────────────────────────────
HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "SY", "BY", "VE", "CU"}


class RiskScorer:
    """
    Per-IP composite risk scorer combining:
      1. ML model confidence (from ml_engine)
      2. Threat reputation (from threat feeds / external APIs)
      3. Attack severity   (from IDS / ML labels)
      4. Asset importance  (from asset_registry)
      5. Classic rule-based factors (backward-compat)
    """

    def __init__(self):
        self._factors:    dict[str, dict[str, bool]] = {}
        self._ml:         dict[str, dict]  = {}   # ip → {confidence, attack, severity}
        self._reputation: dict[str, float] = {}   # ip → 0–1
        self._updated:    dict[str, float] = {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _ensure(self, ip: str):
        if ip not in self._factors:
            self._factors[ip] = {k: False for k in RULE_WEIGHTS}
            self._updated[ip] = time.time()

    # ── Classic factor API (backward-compatible) ───────────────────────────────

    def add_factor(self, ip: str, factor: str) -> None:
        if factor not in RULE_WEIGHTS:
            return
        self._ensure(ip)
        self._factors[ip][factor] = True
        self._updated[ip] = time.time()

    def check_geo_risk(self, ip: str, country_code: str) -> None:
        if country_code and country_code.upper() in HIGH_RISK_COUNTRIES:
            self.add_factor(ip, "geo_risk")

    # ── ML / reputation enrichment ────────────────────────────────────────────

    def set_ml_factor(self, ip: str, attack: str, confidence: float, severity: str = "high") -> None:
        """Call this when the ML engine detects an attack on a flow from this IP."""
        self._ensure(ip)
        self._ml[ip] = {"attack": attack, "confidence": float(confidence), "severity": severity.lower()}
        self._updated[ip] = time.time()

    def set_threat_reputation(self, ip: str, reputation_score: float) -> None:
        """0.0 = clean, 1.0 = fully malicious."""
        self._ensure(ip)
        self._reputation[ip] = max(0.0, min(1.0, float(reputation_score)))
        self._updated[ip] = time.time()

    # ── Composite scoring ─────────────────────────────────────────────────────

    def get_score(self, ip: str, dst_port: int = 0) -> int:
        if ip not in self._factors and ip not in self._ml and ip not in self._reputation:
            return 0

        # 1. ML confidence component (0–40)
        ml_info   = self._ml.get(ip, {})
        ml_conf   = ml_info.get("confidence", 0.0)
        ml_sev    = SEVERITY_SCORE.get(ml_info.get("severity", "medium"), 0.5)
        ml_part   = ml_conf * ml_sev * 40

        # 2. Threat reputation component (0–25)
        rep       = self._reputation.get(ip, 0.0)
        rep_part  = rep * 25

        # 3. Attack severity component (0–20)
        sev_part  = ml_sev * 20 if ml_info else 0

        # 4. Asset importance component (0–15)
        try:
            from backend.detection.asset_registry import asset_registry
            importance = asset_registry.get_importance(ip, dst_port)
        except Exception:
            importance = 0.5
        asset_part = importance * 15

        # 5. Rule-based add-ons
        rule_score = sum(
            RULE_WEIGHTS[f]
            for f, active in self._factors.get(ip, {}).items()
            if active
        )

        raw = ml_part + rep_part + sev_part + asset_part + rule_score
        return min(100, int(round(raw)))

    def get_risk_level(self, ip: str, dst_port: int = 0) -> str:
        s = self.get_score(ip, dst_port)
        if s >= 75: return "critical"
        if s >= 50: return "high"
        if s >= 25: return "medium"
        if s > 0:   return "low"
        return "clean"

    def get_all_scores(self) -> list[dict[str, Any]]:
        all_ips = set(self._factors) | set(self._ml) | set(self._reputation)
        results = []
        for ip in all_ips:
            score = self.get_score(ip)
            if score == 0:
                continue
            ml_info = self._ml.get(ip, {})
            results.append({
                "ip":                  ip,
                "score":               score,
                "level":               self.get_risk_level(ip),
                "ml_attack":           ml_info.get("attack", ""),
                "ml_confidence":       ml_info.get("confidence", 0.0),
                "ml_contribution":     round(ml_info.get("confidence", 0.0) * SEVERITY_SCORE.get(ml_info.get("severity", "medium"), 0.5) * 40, 1),
                "reputation_score":    self._reputation.get(ip, 0.0),
                "reputation_contribution": round(self._reputation.get(ip, 0.0) * 25, 1),
                "factors":             {k: v for k, v in self._factors.get(ip, {}).items() if v},
                "last_updated":        self._updated.get(ip, 0),
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results


# Global singleton
risk_scorer = RiskScorer()
