"""Tests for baseline creation and file hashing (server.features)."""
import hashlib

from server.features import compute_file_hash, create_baseline_entry


class TestFileHashing:
    def test_hash_matches_hashlib_reference(self, tmp_path):
        f = tmp_path / "record.txt"
        f.write_bytes(b"citizenship record 0455")
        expected = hashlib.sha256(b"citizenship record 0455").hexdigest()
        assert compute_file_hash(str(f)) == expected

    def test_hash_changes_when_content_changes(self, tmp_path):
        f = tmp_path / "record.txt"
        f.write_bytes(b"original")
        h1 = compute_file_hash(str(f))
        f.write_bytes(b"tampered")
        assert compute_file_hash(str(f)) != h1

    def test_missing_file_returns_none(self):
        assert compute_file_hash("/nonexistent/path.bin") is None


class TestBaselineEntries:
    def test_entry_contains_required_fields(self, tmp_path):
        f = tmp_path / "lalpurja_113.pdf"
        f.write_bytes(b"%PDF-1.4 land record")
        entry = create_baseline_entry(str(f), agent_id="agent-01",
                                      baseline_name="dao-bhaktapur")
        assert entry is not None
        for field in ("agent_id", "file_path", "file_hash", "file_size",
                      "permissions", "baseline_name", "status", "timestamp"):
            assert field in entry
        assert entry["file_size"] == len(b"%PDF-1.4 land record")
        assert entry["status"] == "ok"

    def test_missing_file_returns_none(self):
        assert create_baseline_entry("/nope/x.pdf", "a", "b") is None
