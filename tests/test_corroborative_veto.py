"""Tests for the corroborative scoring gate — the mechanism behind hypothesis H2.

Under corroborative scoring the One-Class SVM can VETO a volumetric
ransomware alert (mass rename/create/delete/modify) when it considers the
activity normal, e.g. a clerk bulk-importing scanned records. Signature
alerts (encrypted extension, ransom note, encryption keyword) are trusted
unconditionally and can never be vetoed.

These tests pin down the exact conditions of the veto, since the thesis
evaluation (FP 30 -> 8, F1 90.9%) depends on them.
"""
from server.features import calculate_threat_score, is_volumetric_alert

EVENT = {"event_type": "CREATED", "file_path": "/data/scan_batch_0042.pdf"}


class TestAlertClassification:
    def test_signature_titles_are_not_volumetric(self):
        for title in ("Ransomware Extension Detected",
                      "Ransom Note Detected",
                      "Encryption Keyword Detected"):
            assert is_volumetric_alert({"title": title}) is False

    def test_mass_pattern_titles_are_volumetric(self):
        for title in ("Mass File Rename Detected",
                      "Mass File Deletion Detected",
                      "Mass File Creation Detected",
                      "Mass File Modification Detected"):
            assert is_volumetric_alert({"title": title}) is True

    def test_no_alert_is_not_volumetric(self):
        assert is_volumetric_alert(None) is False
        assert is_volumetric_alert({}) is False  # empty dict is falsy -> no alert


class TestVeto:
    def test_svm_vetoes_volumetric_alert_when_pattern_is_normal(self):
        """Bulk import: volumetric rule fired, SVM says normal -> suppressed."""
        r = calculate_threat_score(EVENT, is_ransomware=True, is_anomaly=False,
                                   ransomware_volumetric=True, corroborative=True)
        assert r["ransomware_suppressed"] is True
        assert r["score"] < 70  # the +70 ransomware contribution is gone
        assert any("suppressed" in reason for reason in r["reasons"])

    def test_svm_corroboration_keeps_volumetric_alert(self):
        """Volumetric rule fired AND SVM also flags anomaly -> alert stands."""
        r = calculate_threat_score(EVENT, ml_score=1.0, is_ransomware=True,
                                   is_anomaly=True, ransomware_volumetric=True,
                                   corroborative=True)
        assert r["ransomware_suppressed"] is False
        assert r["level"] == "critical"

    def test_signature_alert_can_never_be_vetoed(self):
        """Signature evidence is always trusted, even when SVM says normal."""
        r = calculate_threat_score(EVENT, is_ransomware=True, is_anomaly=False,
                                   ransomware_volumetric=False, corroborative=True)
        assert r["ransomware_suppressed"] is False
        assert r["score"] >= 70

    def test_legacy_additive_mode_never_suppresses(self):
        """corroborative=False reproduces the original additive behaviour."""
        r = calculate_threat_score(EVENT, is_ransomware=True, is_anomaly=False,
                                   ransomware_volumetric=True, corroborative=False)
        assert r["ransomware_suppressed"] is False
        assert r["score"] >= 70
