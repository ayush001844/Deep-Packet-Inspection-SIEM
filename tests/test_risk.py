"""
Tests for the Risk Scoring Engine.
====================================
Covers: scoring arithmetic, risk levels, boundary conditions,
geo-risk, factor deduplication, and multi-IP sorting.
"""

import pytest


class TestRiskScorer:
    """Tests for the Zero-Trust RiskScorer."""

    def test_initial_score_is_zero(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs.get_score("192.168.1.1")
        assert score == 0

    def test_add_single_factor(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("192.168.1.1", "threat_feed_hit")
        score = rs.get_score("192.168.1.1")
        assert score == 30  # Weight of threat_feed_hit

    def test_add_multiple_factors(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.1", "threat_feed_hit")  # +30
        rs.add_factor("10.0.0.1", "anomalous_volume")  # +20
        score = rs.get_score("10.0.0.1")
        assert score == 50

    def test_score_capped_at_100(self):
        from backend.detection.risk_scoring import RiskScorer, WEIGHTS
        rs = RiskScorer()
        # Add ALL factors
        for factor_name in WEIGHTS:
            rs.add_factor("10.0.0.2", factor_name)
        score = rs.get_score("10.0.0.2")
        assert score <= 100

    def test_duplicate_factor_not_double_counted(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.3", "threat_feed_hit")
        rs.add_factor("10.0.0.3", "threat_feed_hit")
        score = rs.get_score("10.0.0.3")
        assert score == 30  # Should not be 60

    def test_get_all_scores(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.1", "threat_feed_hit")
        rs.add_factor("10.0.0.2", "anomalous_volume")
        all_scores = rs.get_all_scores()
        assert isinstance(all_scores, list)
        assert len(all_scores) == 2

    def test_unknown_factor_ignored(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.4", "nonexistent_factor")
        score = rs.get_score("10.0.0.4")
        assert score == 0

    # ---- Risk level boundary tests ----

    def test_risk_level_clean(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        assert rs.get_risk_level("unknown_ip") == "clean"

    def test_risk_level_low(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.1", "cleartext_protocol")  # +10
        assert rs.get_risk_level("10.0.0.1") == "low"

    def test_risk_level_medium(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.1", "threat_feed_hit")  # +30
        assert rs.get_risk_level("10.0.0.1") == "medium"

    def test_risk_level_high(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.1", "threat_feed_hit")   # +30
        rs.add_factor("10.0.0.1", "anomalous_volume")  # +20 = 50
        assert rs.get_risk_level("10.0.0.1") == "high"

    def test_risk_level_critical(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.1", "threat_feed_hit")   # +30
        rs.add_factor("10.0.0.1", "known_bad_ja3")     # +25
        rs.add_factor("10.0.0.1", "anomalous_volume")  # +20 = 75
        assert rs.get_risk_level("10.0.0.1") == "critical"

    # ---- Geo risk ----

    def test_geo_risk_high_risk_country(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.check_geo_risk("10.0.0.1", "RU")
        score = rs.get_score("10.0.0.1")
        assert score == 15  # geo_risk weight

    def test_geo_risk_safe_country_no_impact(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.check_geo_risk("10.0.0.1", "US")
        score = rs.get_score("10.0.0.1")
        assert score == 0

    def test_geo_risk_case_insensitive(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.check_geo_risk("10.0.0.1", "cn")
        score = rs.get_score("10.0.0.1")
        assert score == 15

    def test_geo_risk_empty_country_no_impact(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.check_geo_risk("10.0.0.1", "")
        score = rs.get_score("10.0.0.1")
        assert score == 0

    # ---- Sorting ----

    def test_get_all_scores_sorted_descending(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.1", "cleartext_protocol")   # +10
        rs.add_factor("10.0.0.2", "threat_feed_hit")       # +30
        rs.add_factor("10.0.0.3", "anomalous_volume")      # +20

        all_scores = rs.get_all_scores()
        scores = [s["score"] for s in all_scores]
        assert scores == sorted(scores, reverse=True)

    # ---- get_all_scores structure ----

    def test_get_all_scores_entry_structure(self):
        from backend.detection.risk_scoring import RiskScorer
        rs = RiskScorer()
        rs.add_factor("10.0.0.1", "threat_feed_hit")
        all_scores = rs.get_all_scores()
        assert len(all_scores) == 1
        entry = all_scores[0]
        assert "ip" in entry
        assert "score" in entry
        assert "level" in entry
        assert "factors" in entry
        assert "last_updated" in entry
        assert entry["ip"] == "10.0.0.1"
        assert entry["score"] == 30
        assert "threat_feed_hit" in entry["factors"]
