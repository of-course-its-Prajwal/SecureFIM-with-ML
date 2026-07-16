"""
SecureFIM Pro  Ransomware Detection Module

Detects ransomware activity through:
  - Suspicious file extensions (.encrypted, .locked, .cerber, etc.)
  - Ransom note file patterns (README_DECRYPT, HOW_TO_RESTORE, etc.)
  - Mass rename/delete/create patterns within a time window
  - Encryption keyword detection in small text files
"""

import os
import time
import logging
from typing import Optional
from collections import deque

log = logging.getLogger("securefim.ransomware")

SUSPICIOUS_EXTENSIONS = {
    ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
    ".locky", ".zepto", ".odin", ".aesir", ".thor",
    ".cerber", ".wallet", ".wncry", ".wcry", ".aaa",
    ".ccc", ".vvv", ".xxx", ".zzz", ".abc", ".xyz",
    ".ransom", ".crypz", ".cryp1", ".cryptolocker", ".cryptowall",
    ".onion", ".dharma", ".arena", ".phobos", ".rapid",
}

RANSOM_NOTE_PATTERNS = [
    "README", "DECRYPT", "RESTORE", "HOW_TO", "HELP",
    "INSTRUCTIONS", "RANSOM", "PAYMENT", "BITCOIN",
    "PAY", "RECOVER", "ENCRYPTED", "YOUR_FILES", "_INFO_",
    "_README_", "_DECRYPT_", "RECOVERY_KEY", "PERSONAL_KEY",
]

ENCRYPTION_KEYWORDS = [
    "encryption_key", "decryption_key", "bitcoin_address",
    "wallet", "send_money", "payment", "tor", "ransom",
    "bitcoin", "crypto", "recover_files", "decrypt_files",
    "your files have been encrypted", "pay to decrypt",
]


class RansomwareDetector:
    """Detects ransomware-like file system behaviour."""

    def __init__(self, detection_window: int = 120):
        self.detection_window = detection_window  # seconds
        self.mass_rename_threshold = 15
        self.mass_create_threshold = 30
        self.mass_delete_threshold = 20
        self.mass_modify_threshold = 50

        self.recent_renames: deque = deque(maxlen=500)
        self.recent_creates: deque = deque(maxlen=500)
        self.recent_deletes: deque = deque(maxlen=500)
        self.recent_modifies: deque = deque(maxlen=500)

    #  single-event checks 

    def check_extension(self, file_path: str) -> Optional[str]:
        """Return suspicious extension or None."""
        name = os.path.basename(file_path).lower()
        parts = name.split(".")
        # Double extension (e.g. report.docx.encrypted)
        if len(parts) > 2 and f".{parts[-1]}" in SUSPICIOUS_EXTENSIONS:
            return f".{parts[-1]} (double extension)"
        _, ext = os.path.splitext(name)
        if ext in SUSPICIOUS_EXTENSIONS:
            return ext
        return None

    def check_ransom_note(self, file_path: str) -> Optional[str]:
        """Return matched pattern or None."""
        name = os.path.basename(file_path).upper()
        text_exts = {".txt", ".html", ".htm", ".rtf", ".md", ".log", ".hta"}
        _, ext = os.path.splitext(file_path.lower())
        if ext not in text_exts:
            return None
        for pattern in RANSOM_NOTE_PATTERNS:
            if pattern in name:
                return pattern
        return None

    def check_content_keywords(self, file_path: str) -> Optional[str]:
        """Scan small text files for encryption keywords."""
        try:
            if not os.path.isfile(file_path):
                return None
            if os.path.getsize(file_path) > 10240:  # skip files > 10 KB
                return None
            with open(file_path, "r", errors="ignore") as f:
                content = f.read(5000).lower()
            for kw in ENCRYPTION_KEYWORDS:
                if kw in content:
                    return kw
        except Exception:
            pass
        return None

    #  pattern-based (mass activity) 

    def _clean(self, q: deque):
        cutoff = time.time() - self.detection_window
        while q and q[0][0] < cutoff:
            q.popleft()

    def record_event(self, event_type: str, file_path: str,
                     dest_path: str = "") -> Optional[dict]:
        """
        Record an event and return an alert dict if ransomware-like
        behaviour is detected, otherwise None.
        """
        now = time.time()
        etype = event_type.upper()

        # Single-event checks
        alert = self._check_single(etype, file_path, dest_path)
        if alert:
            return alert

        # Record for mass-pattern detection
        if etype == "MOVED":
            self.recent_renames.append((now, file_path, dest_path))
        elif etype == "CREATED":
            self.recent_creates.append((now, file_path))
        elif etype == "DELETED":
            self.recent_deletes.append((now, file_path))
        elif etype == "MODIFIED":
            self.recent_modifies.append((now, file_path))

        # Mass-pattern checks
        return self._check_mass_patterns()

    def _check_single(self, etype: str, path: str,
                       dest: str = "") -> Optional[dict]:
        """Run single-event ransomware checks."""
        check_path = dest if dest else path

        ext = self.check_extension(check_path)
        if ext:
            return {
                "alert_type": "ransomware",
                "severity": "critical",
                "title": "Ransomware Extension Detected",
                "message": f"Suspicious extension {ext} on file: {check_path}",
                "file_path": check_path,
            }

        note = self.check_ransom_note(check_path)
        if note and etype == "CREATED":
            return {
                "alert_type": "ransomware",
                "severity": "critical",
                "title": "Ransom Note Detected",
                "message": f"Possible ransom note ({note}) created: {check_path}",
                "file_path": check_path,
            }

        if etype == "CREATED":
            kw = self.check_content_keywords(check_path)
            if kw:
                return {
                    "alert_type": "ransomware",
                    "severity": "critical",
                    "title": "Encryption Keyword Detected",
                    "message": f"File contains keyword '{kw}': {check_path}",
                    "file_path": check_path,
                }

        return None

    def _check_mass_patterns(self) -> Optional[dict]:
        """Check for mass rename/create/delete/modify within the window."""
        self._clean(self.recent_renames)
        self._clean(self.recent_creates)
        self._clean(self.recent_deletes)
        self._clean(self.recent_modifies)

        if len(self.recent_renames) >= self.mass_rename_threshold:
            return {
                "alert_type": "ransomware",
                "severity": "critical",
                "title": "Mass File Rename Detected",
                "message": (f"{len(self.recent_renames)} files renamed in "
                            f"{self.detection_window}s — possible encryption"),
                "count": len(self.recent_renames),
            }

        if len(self.recent_deletes) >= self.mass_delete_threshold:
            return {
                "alert_type": "ransomware",
                "severity": "critical",
                "title": "Mass File Deletion Detected",
                "message": (f"{len(self.recent_deletes)} files deleted in "
                            f"{self.detection_window}s — possible ransomware"),
                "count": len(self.recent_deletes),
            }

        if len(self.recent_creates) >= self.mass_create_threshold:
            return {
                "alert_type": "ransomware",
                "severity": "warning",
                "title": "Mass File Creation Detected",
                "message": (f"{len(self.recent_creates)} files created in "
                            f"{self.detection_window}s"),
                "count": len(self.recent_creates),
            }

        if len(self.recent_modifies) >= self.mass_modify_threshold:
            return {
                "alert_type": "ransomware",
                "severity": "warning",
                "title": "Mass File Modification Detected",
                "message": (f"{len(self.recent_modifies)} files modified in "
                            f"{self.detection_window}s"),
                "count": len(self.recent_modifies),
            }

        return None

    def status(self) -> dict:
        return {
            "detection_window_s": self.detection_window,
            "recent_renames": len(self.recent_renames),
            "recent_creates": len(self.recent_creates),
            "recent_deletes": len(self.recent_deletes),
            "recent_modifies": len(self.recent_modifies),
            "thresholds": {
                "mass_rename": self.mass_rename_threshold,
                "mass_create": self.mass_create_threshold,
                "mass_delete": self.mass_delete_threshold,
                "mass_modify": self.mass_modify_threshold,
            },
        }
