"""
SecureFIM Pro — Advanced Features Module

1. File Hash Baseline — snapshot known-good state, compare later
2. Sensitivity Labels & Watchlist — mark files as HIGH/MEDIUM/LOW
3. Working Hours Anomaly — flag changes outside business hours
4. MITRE ATT&CK Mapping — tag detections with technique IDs
5. Threat Scoring — combine multiple signals into a single score
6. Data Retention — auto-delete old events
7. IOC Database — known malicious hashes/extensions
"""

import logging
import time
import hashlib
import os
from datetime import datetime, timezone

log = logging.getLogger("securefim.features")

# ── MITRE ATT&CK Mappings ────────────────────────────────────────────────

MITRE_TECHNIQUES = {
    "ransomware_extension": {
        "id": "T1486", "name": "Data Encrypted for Impact",
        "tactic": "Impact", "description": "Adversary encrypts files to deny access",
    },
    "ransom_note": {
        "id": "T1491.001", "name": "Internal Defacement",
        "tactic": "Impact", "description": "Ransom note file created",
    },
    "mass_delete": {
        "id": "T1485", "name": "Data Destruction",
        "tactic": "Impact", "description": "Mass file deletion detected",
    },
    "mass_rename": {
        "id": "T1486", "name": "Data Encrypted for Impact",
        "tactic": "Impact", "description": "Mass file renaming (encryption pattern)",
    },
    "config_modification": {
        "id": "T1562.001", "name": "Disable or Modify Tools",
        "tactic": "Defense Evasion", "description": "System configuration file modified",
    },
    "credential_access": {
        "id": "T1552.001", "name": "Credentials in Files",
        "tactic": "Credential Access", "description": "Credential/key file accessed",
    },
    "persistence": {
        "id": "T1547.001", "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence", "description": "Startup/autorun file modified",
    },
    "log_tampering": {
        "id": "T1070.002", "name": "Clear Linux or Mac System Logs",
        "tactic": "Defense Evasion", "description": "Log file deleted or modified",
    },
    "after_hours": {
        "id": "T1059", "name": "Command and Scripting Interpreter",
        "tactic": "Execution", "description": "File changes outside business hours",
    },
    "burst_activity": {
        "id": "T1059", "name": "Automated Collection",
        "tactic": "Collection", "description": "Unusual burst of file operations",
    },
}

# ── IOC Database — Known malicious indicators ─────────────────────────────

KNOWN_MALICIOUS_HASHES = set()  # Populate from threat feeds in production

SENSITIVE_PATH_PATTERNS = {
    "HIGH": [
        # System credential files (Linux/Unix)
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        ".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/known_hosts",
        "/etc/ssl/", "/var/lib/secrets/",

        # Generic credential keywords
        "credentials", "password", "secret", "private_key", ".pem", ".key", ".pfx",
        "web.config", "wp-config.php", ".env", "appsettings.json",

        # Windows system files
        "System32\\config\\", "SAM", "SECURITY", "SYSTEM",

        # Database files (where government records are typically stored)
        ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",

        # Nepal government records — citizenship
        "citizenship", "nagarikta", "nagrikta",

        # Nepal government records — land/property
        "land_record", "lalpurja", "malpot", "property_record",
        "land_ownership", "land_registry", "bhumi",

        # Identity documents
        "passport", "license", "driving_license", "voter_id", "nid",

        # Nepal government records — tax
        "tax_record", "revenue", "pan_record", "vat_record",

        # Nepal government records — HR/payroll
        "hr_record", "payroll", "salary", "employee_record",

        # Critical business files
        "balance_sheet", "ledger", "transaction_record", "bank_statement",
        "audit_report", "financial_statement",

        # Backup files (often targeted by ransomware)
        ".backup", ".bak",

        # Exam/Education critical files (for schools)
        "exam_result", "answer_key", "question_paper", "marks_sheet",
        "student_record", "admission_record",

        # Medical records
        "patient_record", "medical_record", "prescription", "diagnosis_report",
        ".hl7",
    ],
    "MEDIUM": [
        # System config (Linux)
        "/etc/crontab", "/etc/hosts", "/etc/resolv.conf",
        ".bashrc", ".profile", ".bash_profile", ".zshrc",
        "httpd.conf", "nginx.conf", "my.cnf", "postgresql.conf",

        # Windows startup/config
        "Startup\\", "AppData\\Roaming\\Microsoft\\Windows\\Start Menu",

        # Log files
        "/var/log/", "syslog", "auth.log", "kern.log",

        # Office documents that often contain sensitive info
        ".xlsx", ".xls", ".docx", ".doc", ".pdf",

        # Spreadsheets/reports
        "report", "summary", "register", "list",
    ],
    "LOW": [],
}


# ── Working Hours Detection ───────────────────────────────────────────────

class WorkingHoursDetector:
    """Detects file changes outside configured business hours."""

    def __init__(self, start_hour: int = 9, end_hour: int = 18,
                 business_days: str = "0,1,2,3,4"):
        self.start_hour = start_hour
        self.end_hour = end_hour
        self.business_days = [int(d) for d in business_days.split(",")]

    def is_outside_hours(self, timestamp: str = None) -> dict:
        """Check if a timestamp falls outside business hours."""
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except Exception:
                dt = datetime.now()
        else:
            dt = datetime.now()

        hour = dt.hour
        weekday = dt.weekday()
        outside = hour < self.start_hour or hour >= self.end_hour
        weekend = weekday not in self.business_days

        return {
            "outside_hours": outside or weekend,
            "is_weekend": weekend,
            "hour": hour,
            "weekday": weekday,
            "reason": (
                f"Weekend activity (day={weekday})" if weekend
                else f"After-hours activity ({hour}:00)" if outside
                else ""
            ),
        }


# ── Sensitivity Classifier ───────────────────────────────────────────────

def classify_sensitivity(file_path: str) -> str:
    """Classify file sensitivity based on path patterns. Returns HIGH/MEDIUM/LOW."""
    path_lower = file_path.lower().replace("\\", "/")

    for pattern in SENSITIVE_PATH_PATTERNS["HIGH"]:
        if pattern.lower() in path_lower:
            return "HIGH"

    for pattern in SENSITIVE_PATH_PATTERNS["MEDIUM"]:
        if pattern.lower() in path_lower:
            return "MEDIUM"

    return "LOW"


def get_mitre_tags(event: dict, is_ransomware: bool = False,
                   is_anomaly: bool = False, outside_hours: bool = False) -> list:
    """Get applicable MITRE ATT&CK tags for an event."""
    tags = []
    etype = (event.get("event_type") or "").upper()
    path = (event.get("file_path") or "").lower()

    if is_ransomware:
        if any(ext in path for ext in [".encrypted", ".locked", ".crypto", ".crypt"]):
            tags.append(MITRE_TECHNIQUES["ransomware_extension"])
        if any(p in path.upper() for p in ["DECRYPT", "RANSOM", "README", "HOW_TO"]):
            tags.append(MITRE_TECHNIQUES["ransom_note"])

    if etype == "DELETED" and is_anomaly:
        tags.append(MITRE_TECHNIQUES["mass_delete"])

    if outside_hours:
        tags.append(MITRE_TECHNIQUES["after_hours"])

    # Credential file access
    sensitivity = classify_sensitivity(event.get("file_path", ""))
    if sensitivity == "HIGH":
        if any(k in path for k in ["password", "credential", "secret", ".key", ".pem", "shadow", "sam"]):
            tags.append(MITRE_TECHNIQUES["credential_access"])
        elif any(k in path for k in [".bashrc", "startup", "autorun", "crontab"]):
            tags.append(MITRE_TECHNIQUES["persistence"])

    # Log tampering
    if any(k in path for k in ["syslog", "auth.log", "audit", ".log"]) and etype in ("DELETED", "MODIFIED"):
        tags.append(MITRE_TECHNIQUES["log_tampering"])

    # Config modification
    if any(k in path for k in ["etc/", "config", ".conf", ".cfg", ".ini", "web.config"]) and etype == "MODIFIED":
        tags.append(MITRE_TECHNIQUES["config_modification"])

    return tags


# ── Threat Scoring ────────────────────────────────────────────────────────

# Ransomware alerts fall into two classes. SIGNATURE alerts rest on specific
# evidence — an encrypted extension, a ransom note, an encryption keyword — and
# are trusted unconditionally. VOLUMETRIC alerts are statistical inferences from
# event volume ("many creates in a short window"), and legitimate bulk
# administrative work produces exactly the same volume. Only the volumetric class
# is subject to corroboration.
SIGNATURE_ALERT_TITLES = (
    "Ransomware Extension Detected",
    "Ransom Note Detected",
    "Encryption Keyword Detected",
)


def is_volumetric_alert(rw_alert: dict) -> bool:
    """True if a ransomware alert was inferred from event volume, not a signature."""
    if not rw_alert:
        return False
    return rw_alert.get("title", "") not in SIGNATURE_ALERT_TITLES


def calculate_threat_score(event: dict, ml_score: float = 0.0,
                           is_ransomware: bool = False,
                           is_anomaly: bool = False,
                           outside_hours: bool = False,
                           sensitivity: str = "LOW",
                           ransomware_volumetric: bool = False,
                           corroborative: bool = True) -> dict:
    """
    Calculate a combined threat score (0-100) from multiple signals.
    Higher = more suspicious.

    CORROBORATIVE SCORING
    ---------------------
    The scoring model was originally purely additive: every signal could only
    ADD points, so the anomaly detector could raise a score but never lower one
    or veto a rule. That made it structurally impossible for machine learning to
    reduce false positives, because it had no mechanism through which to express
    disagreement with the rules.

    Under corroborative scoring the classifier is given a veto. A VOLUMETRIC
    ransomware alert is only credited if the One-Class SVM corroborates it. If
    the SVM has observed this pattern during training and considers it normal —
    as it does for a clerk bulk-importing scanned records — the volumetric rule
    is suppressed and no alert is raised. Signature-based alerts are unaffected.

    Set corroborative=False to reproduce the original additive behaviour.
    """
    score = 0
    reasons = []

    # ── Corroborative gate ────────────────────────────────────────────────
    ransomware_suppressed = False
    if (corroborative and is_ransomware
            and ransomware_volumetric and not is_anomaly):
        is_ransomware = False
        ransomware_suppressed = True
        reasons.append("Volumetric ransomware rule suppressed: "
                       "anomaly detector considers this pattern normal")

    # ML anomaly contribution (0-40 points)
    if is_anomaly:
        ml_points = min(40, int(abs(ml_score) * 40) + 10)
        score += ml_points
        reasons.append(f"ML anomaly (+{ml_points})")

    # Ransomware contribution (0-70 points — ransomware alone = critical)
    if is_ransomware:
        score += 70
        reasons.append("Ransomware detected (+70)")

    # Sensitivity contribution (0-40 points — HIGH sensitivity is very suspicious)
    sens_points = {"HIGH": 40, "MEDIUM": 20, "LOW": 0}
    sp = sens_points.get(sensitivity, 0)
    if sp:
        score += sp
        reasons.append(f"Sensitivity {sensitivity} (+{sp})")

    # After-hours contribution (0-30 points — major red flag)
    if outside_hours:
        score += 30
        reasons.append("Outside business hours (+30)")

    # Event type contribution — deletion of sensitive files is critical
    etype = (event.get("event_type") or "").upper()
    if etype == "DELETED":
        if sensitivity == "HIGH":
            score += 20
            reasons.append("HIGH sensitivity file deleted (+20)")
        else:
            score += 10
            reasons.append("File deletion (+10)")

    # MITRE tags contribution (0-15 points)
    mitre_tags = get_mitre_tags(event, is_ransomware, is_anomaly, outside_hours)
    if mitre_tags:
        mitre_points = min(15, len(mitre_tags) * 5)
        score += mitre_points
        reasons.append(f"{len(mitre_tags)} MITRE tags (+{mitre_points})")

    score = min(100, score)

    level = "low"
    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 20:
        level = "medium"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "ransomware_suppressed": ransomware_suppressed,
        "mitre_tags": [{"id": t["id"], "name": t["name"], "tactic": t["tactic"]} for t in mitre_tags],
    }


# ── Data Retention ────────────────────────────────────────────────────────

def apply_retention(os_client, index: str, days: int = 30) -> int:
    """Delete documents older than N days from an index."""
    body = {
        "query": {
            "range": {
                "timestamp": {"lt": f"now-{days}d"}
            }
        }
    }
    return os_client.delete_by_query(index, body)


# ── Baseline Functions ────────────────────────────────────────────────────

def compute_file_hash(file_path: str) -> str | None:
    """Compute SHA-256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def create_baseline_entry(file_path: str, agent_id: str, baseline_name: str) -> dict | None:
    """Create a baseline entry for a single file."""
    if not os.path.isfile(file_path):
        return None
    try:
        stat = os.stat(file_path)
        return {
            "agent_id": agent_id,
            "file_path": file_path,
            "file_hash": compute_file_hash(file_path),
            "file_size": stat.st_size,
            "permissions": oct(stat.st_mode)[-3:],
            "baseline_name": baseline_name,
            "status": "ok",
            "last_verified": datetime.now(timezone.utc).isoformat(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        log.error("Baseline entry error for %s: %s", file_path, exc)
        return None
