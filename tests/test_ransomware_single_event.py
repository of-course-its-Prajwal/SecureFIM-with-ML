"""Tests for single-event ransomware signatures (server.ransomware.RansomwareDetector).

Covers the three signature checks: suspicious extensions (including double
extensions), ransom-note filename patterns, and encryption keywords inside
small text files.
"""
import pytest

from server.ransomware import RansomwareDetector


@pytest.fixture()
def det():
    return RansomwareDetector(detection_window=120)


class TestSuspiciousExtensions:
    def test_encrypted_extension_flagged(self, det):
        assert det.check_extension("/data/report.encrypted") == ".encrypted"

    def test_locky_extension_flagged(self, det):
        assert det.check_extension("C:/files/photo.locky") == ".locky"

    def test_double_extension_flagged(self, det):
        result = det.check_extension("/data/lalpurja_113.docx.encrypted")
        assert result is not None
        assert "double extension" in result

    def test_clean_docx_not_flagged(self, det):
        assert det.check_extension("/data/citizenship_form.docx") is None

    def test_extension_check_is_case_insensitive(self, det):
        assert det.check_extension("/data/REPORT.ENCRYPTED") == ".encrypted"

    def test_record_event_returns_critical_alert_for_extension(self, det):
        alert = det.record_event("CREATED", "/data/record.wncry")
        assert alert is not None
        assert alert["alert_type"] == "ransomware"
        assert alert["severity"] == "critical"

    def test_moved_event_checks_destination_path(self, det):
        # rename to an encrypted name must alert on the DEST path
        alert = det.record_event("MOVED", "/data/a.docx", dest_path="/data/a.docx.locked")
        assert alert is not None
        assert alert["file_path"].endswith(".locked")


class TestRansomNotes:
    def test_readme_decrypt_txt_on_create_alerts(self, det):
        alert = det.record_event("CREATED", "/data/README_DECRYPT.txt")
        assert alert is not None
        assert alert["title"] == "Ransom Note Detected"

    def test_note_pattern_requires_text_extension(self, det):
        # same name but .exe is not treated as a ransom note
        assert det.check_ransom_note("/data/README_DECRYPT.exe") is None

    def test_note_only_alerts_on_created_events(self, det):
        # modifying an existing HOW_TO file is not a note-creation signature
        alert = det.record_event("MODIFIED", "/data/HOW_TO_RESTORE.txt")
        assert alert is None

    def test_benign_readme_matches_pattern_known_limitation(self, det):
        # documented limitation: a plain project README.txt matches "README".
        # This behaviour is asserted so any future fix updates this test.
        assert det.check_ransom_note("/repo/README.txt") == "README"


class TestEncryptionKeywords:
    def test_keyword_in_small_text_file(self, det, tmp_path):
        note = tmp_path / "note.txt"
        note.write_text("your files have been encrypted. pay to decrypt.")
        assert det.check_content_keywords(str(note)) is not None

    def test_large_files_are_skipped(self, det, tmp_path):
        big = tmp_path / "big.txt"
        big.write_text("bitcoin " * 5000)  # > 10 KB
        assert det.check_content_keywords(str(big)) is None

    def test_missing_file_returns_none(self, det):
        assert det.check_content_keywords("/nonexistent/file.txt") is None
