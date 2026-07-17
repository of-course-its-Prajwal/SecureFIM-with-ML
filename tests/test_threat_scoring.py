"""Tests for the combined threat-scoring model (server.features.calculate_threat_score).

Verifies each signal's point contribution, the 0-100 cap, and the
score-to-severity level mapping used across the dashboard and alerting.
"""
from server.features import calculate_threat_score

EVENT = {"event_type": "MODIFIED", "file_path": "/tmp/plain.tmp"}


class TestIndividualSignals:
    def test_no_signals_scores_zero_low(self):
        r = calculate_threat_score(EVENT)
        assert r["score"] == 0
        assert r["level"] == "low"

    def test_ransomware_alone_is_critical(self):
        r = calculate_threat_score(EVENT, is_ransomware=True)
        assert r["score"] >= 70
        assert r["level"] == "critical"

    def test_high_sensitivity_adds_40(self):
        r = calculate_threat_score(EVENT, sensitivity="HIGH")
        assert r["score"] == 40

    def test_medium_sensitivity_adds_20(self):
        r = calculate_threat_score(EVENT, sensitivity="MEDIUM")
        assert r["score"] == 20

    def test_after_hours_adds_30_plus_mitre_tag(self):
        r = calculate_threat_score(EVENT, outside_hours=True)
        # 30 for after-hours + 5 for the resulting MITRE tag (T1059)
        assert r["score"] == 35

    def test_anomaly_points_scale_with_ml_score_capped_at_40(self):
        weak = calculate_threat_score(EVENT, ml_score=0.1, is_anomaly=True)
        strong = calculate_threat_score(EVENT, ml_score=5.0, is_anomaly=True)
        assert 0 < weak["score"] < strong["score"] <= 40

    def test_high_sensitivity_deletion_bonus(self):
        ev = {"event_type": "DELETED", "file_path": "/tmp/plain.tmp"}
        r = calculate_threat_score(ev, sensitivity="HIGH")
        # 40 (HIGH) + 20 (HIGH file deleted)
        assert r["score"] >= 60


class TestAggregation:
    def test_score_is_capped_at_100(self):
        ev = {"event_type": "DELETED", "file_path": "/etc/shadow"}
        r = calculate_threat_score(ev, ml_score=5.0, is_ransomware=True,
                                   is_anomaly=True, outside_hours=True,
                                   sensitivity="HIGH")
        assert r["score"] == 100

    def test_level_boundaries(self):
        # medium starts at 20, high at 40, critical at 70
        assert calculate_threat_score(EVENT, sensitivity="MEDIUM")["level"] == "medium"
        assert calculate_threat_score(EVENT, sensitivity="HIGH")["level"] == "high"
        assert calculate_threat_score(EVENT, is_ransomware=True)["level"] == "critical"

    def test_reasons_are_reported(self):
        r = calculate_threat_score(EVENT, outside_hours=True, sensitivity="MEDIUM")
        joined = " ".join(r["reasons"])
        assert "Outside business hours" in joined
        assert "Sensitivity MEDIUM" in joined
