"""Tests for MITRE ATT&CK tagging and the working-hours detector."""
from server.features import WorkingHoursDetector, get_mitre_tags


class TestMitreTags:
    def test_encrypted_extension_maps_to_t1486(self):
        ev = {"event_type": "MOVED", "file_path": "/data/rec.docx.encrypted"}
        ids = [t["id"] for t in get_mitre_tags(ev, is_ransomware=True)]
        assert "T1486" in ids  # Data Encrypted for Impact

    def test_ransom_note_maps_to_t1491(self):
        ev = {"event_type": "CREATED", "file_path": "/data/README_DECRYPT.txt"}
        ids = [t["id"] for t in get_mitre_tags(ev, is_ransomware=True)]
        assert "T1491.001" in ids

    def test_credential_file_maps_to_t1552(self):
        ev = {"event_type": "MODIFIED", "file_path": "/etc/shadow"}
        ids = [t["id"] for t in get_mitre_tags(ev)]
        assert "T1552.001" in ids

    def test_log_deletion_maps_to_log_tampering(self):
        ev = {"event_type": "DELETED", "file_path": "/var/log/auth.log"}
        ids = [t["id"] for t in get_mitre_tags(ev)]
        assert "T1070.002" in ids

    def test_config_modification_maps_to_t1562(self):
        ev = {"event_type": "MODIFIED", "file_path": "/etc/nginx/nginx.conf"}
        ids = [t["id"] for t in get_mitre_tags(ev)]
        assert "T1562.001" in ids

    def test_benign_event_gets_no_tags(self):
        ev = {"event_type": "CREATED", "file_path": "/tmp/scratch.tmp"}
        assert get_mitre_tags(ev) == []


class TestWorkingHours:
    def test_inside_business_hours_weekday(self):
        det = WorkingHoursDetector(start_hour=9, end_hour=18)
        # Wed 2026-07-15 11:00 (weekday=2)
        r = det.is_outside_hours("2026-07-15T11:00:00")
        assert r["outside_hours"] is False

    def test_after_hours_weekday_flagged(self):
        det = WorkingHoursDetector(start_hour=9, end_hour=18)
        r = det.is_outside_hours("2026-07-15T22:30:00")
        assert r["outside_hours"] is True
        assert "After-hours" in r["reason"]

    def test_weekend_flagged_even_during_day_hours(self):
        det = WorkingHoursDetector(start_hour=9, end_hour=18)
        # Sat 2026-07-18 11:00 (weekday=5)
        r = det.is_outside_hours("2026-07-18T11:00:00")
        assert r["outside_hours"] is True
        assert r["is_weekend"] is True

    def test_boundary_end_hour_is_outside(self):
        det = WorkingHoursDetector(start_hour=9, end_hour=18)
        r = det.is_outside_hours("2026-07-15T18:00:00")
        assert r["outside_hours"] is True  # 18:00 itself is after hours

    def test_custom_business_days(self):
        # Nepali working week: Sunday-Friday (Python weekday: Sun=6 ... Fri=4)
        det = WorkingHoursDetector(start_hour=10, end_hour=17,
                                   business_days="6,0,1,2,3,4")
        sat = det.is_outside_hours("2026-07-18T12:00:00")  # Saturday
        sun = det.is_outside_hours("2026-07-19T12:00:00")  # Sunday
        assert sat["is_weekend"] is True
        assert sun["is_weekend"] is False
