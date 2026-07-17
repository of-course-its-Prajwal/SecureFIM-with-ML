"""Tests for volumetric (mass-activity) ransomware detection.

These rules infer ransomware from event VOLUME inside a sliding window:
mass renames (>=15), deletes (>=20), creates (>=30), modifies (>=50).
They are the rules subject to the corroborative SVM veto, so their exact
trigger points matter to the thesis evaluation.
"""
import pytest

from server.ransomware import RansomwareDetector


@pytest.fixture()
def det():
    return RansomwareDetector(detection_window=120)


def feed(det, etype, n, prefix="/data/f"):
    """Feed n events of one type; return the last alert produced."""
    alert = None
    for i in range(n):
        alert = det.record_event(etype, f"{prefix}{i}.dat",
                                 dest_path=f"{prefix}{i}.dat.new" if etype == "MOVED" else "")
    return alert


class TestThresholds:
    def test_mass_rename_triggers_at_threshold(self, det):
        assert feed(det, "MOVED", det.mass_rename_threshold - 1) is None
        alert = det.record_event("MOVED", "/data/x.dat", dest_path="/data/x.dat.new")
        assert alert is not None
        assert alert["title"] == "Mass File Rename Detected"
        assert alert["severity"] == "critical"

    def test_mass_delete_triggers_at_threshold(self, det):
        assert feed(det, "DELETED", det.mass_delete_threshold - 1) is None
        alert = det.record_event("DELETED", "/data/x.dat")
        assert alert is not None
        assert alert["title"] == "Mass File Deletion Detected"

    def test_mass_create_is_warning_not_critical(self, det):
        alert = feed(det, "CREATED", det.mass_create_threshold)
        assert alert is not None
        assert alert["severity"] == "warning"

    def test_mass_modify_triggers_at_threshold(self, det):
        alert = feed(det, "MODIFIED", det.mass_modify_threshold)
        assert alert is not None
        assert alert["title"] == "Mass File Modification Detected"


class TestWindowBehaviour:
    def test_events_outside_window_are_evicted(self, det, monkeypatch):
        import time as _time
        base = _time.time()
        clock = {"now": base}
        monkeypatch.setattr("server.ransomware.time.time", lambda: clock["now"])

        # 14 renames now (below threshold of 15)
        for i in range(14):
            det.record_event("MOVED", f"/d/a{i}", dest_path=f"/d/b{i}")

        # jump past the window; the 15th rename should NOT trigger
        clock["now"] = base + det.detection_window + 1
        alert = det.record_event("MOVED", "/d/a14", dest_path="/d/b14")
        assert alert is None

    def test_counts_reported_in_status(self, det):
        feed(det, "DELETED", 5)
        status = det.status()
        assert status["recent_deletes"] == 5
        assert status["thresholds"]["mass_delete"] == det.mass_delete_threshold
