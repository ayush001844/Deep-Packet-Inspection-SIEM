"""
Tests for the Risk Scoring Engine.
====================================
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
