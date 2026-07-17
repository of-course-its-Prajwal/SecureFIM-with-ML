"""Tests for the path-based sensitivity classifier (server.features.classify_sensitivity).

The classifier is the first stage of threat scoring: HIGH-sensitivity paths
add +40 to an event's threat score, so misclassification directly changes
alert severity.
"""
from server.features import classify_sensitivity


class TestHighSensitivityGovernmentRecords:
    """Nepal government record patterns — the core protection target."""

    def test_citizenship_record_is_high(self):
        assert classify_sensitivity("D:/records/citizenship/ram_bahadur.pdf") == "HIGH"

    def test_nagarikta_devanagari_romanised_is_high(self):
        assert classify_sensitivity("/srv/dao/nagarikta_2081_0455.docx") == "HIGH"

    def test_land_record_lalpurja_is_high(self):
        assert classify_sensitivity("E:/malpot/lalpurja_transfer_113.xlsx") == "HIGH"

    def test_voter_id_is_high(self):
        assert classify_sensitivity("C:/data/voter_id_ward_4.csv") == "HIGH"

    def test_tax_record_is_high(self):
        assert classify_sensitivity("/data/tax_record_fy2082.db") == "HIGH"


class TestHighSensitivityCredentials:
    """Credential and system files."""

    def test_etc_shadow_is_high(self):
        assert classify_sensitivity("/etc/shadow") == "HIGH"

    def test_ssh_private_key_is_high(self):
        assert classify_sensitivity("/home/clerk/.ssh/id_rsa") == "HIGH"

    def test_dotenv_is_high(self):
        assert classify_sensitivity("/opt/app/.env") == "HIGH"

    def test_windows_backslash_paths_are_normalised(self):
        # classifier lowercases and converts backslashes before matching
        assert classify_sensitivity("C:\\Windows\\System32\\config\\SAM") == "HIGH"


class TestMediumAndLow:
    def test_office_document_is_medium(self):
        assert classify_sensitivity("/home/user/notes/meeting.docx") == "MEDIUM"

    def test_syslog_is_medium(self):
        assert classify_sensitivity("/var/log/syslog") == "MEDIUM"

    def test_plain_temp_file_is_low(self):
        assert classify_sensitivity("/tmp/scratch_0001.tmp") == "LOW"

    def test_case_insensitive_matching(self):
        assert classify_sensitivity("D:/RECORDS/CITIZENSHIP/FILE.PDF") == "HIGH"
