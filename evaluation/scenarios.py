"""
SecureFIM Pro — Evaluation Dataset Generator

Produces LABELLED windows of file-integrity events with known ground truth,
so detector output can be scored against a confusion matrix.

Design notes (important for the thesis write-up):

  * The unit of classification is an EVENT WINDOW (a burst of activity over a
    short period), not a single event. This matches how the One-Class SVM
    actually operates in SecureFIM Pro (server/ml extract_features works on
    windows), so the evaluation measures the deployed system, not a proxy.

  * The BENIGN class deliberately includes HARD cases — a legitimate bulk
    import of records, and legitimate edits to HIGH-sensitivity government
    files during office hours. Without these, the false-positive rate would
    be artificially near zero and the evaluation would be worthless. These
    cases are what a rule-only detector tends to get wrong, and they are
    the basis of the H2 comparison.

  * All data is synthetic. No real citizen records are used.
"""

import hashlib
import random
from datetime import datetime, timedelta

# ── File universe (mirrors the DAO Bhaktapur use case) ───────────────────

SENSITIVE_FILES = [
    "records/citizenship/nagarikta_{n}.pdf",
    "records/landholding/lalpurja_ward{n}_2080.pdf",
    "records/voter/voter_id_ward{n}.pdf",
    "records/tax/malpot_record_{n}.xlsx",
    "records/passport/passport_records_{n}.db",
    "records/staff/staff_register_{n}.xlsx",
]

CREDENTIAL_FILES = [
    "config/password.txt",
    "config/api_key.pem",
    "config/.env",
    "config/db_credentials.json",
]

ROUTINE_FILES = [
    "office/memo_{n}.docx",
    "office/notice_{n}.docx",
    "office/minutes_{n}.docx",
    "office/attendance_{n}.xlsx",
    "temp/draft_{n}.tmp",
    "temp/scan_{n}.jpg",
]

RANSOM_NOTES = [
    "HOW_TO_DECRYPT.txt",
    "README_RESTORE_FILES.txt",
    "DECRYPT_INSTRUCTIONS.txt",
]

ENCRYPTED_EXTS = [".encrypted", ".locked", ".wncry", ".cerber", ".phobos"]


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _pick(rng, templates):
    t = rng.choice(templates)
    return t.format(n=rng.randint(1, 60)) if "{n}" in t else t


def _event(etype, path, ts, rng, changed=True, dest=""):
    """Build one event dict in the shape server/ml.extract_features expects."""
    new_h = _hash(f"{path}{ts}{rng.random()}")
    old_h = _hash(f"{path}old") if changed else new_h
    ev = {
        "event_type": etype,
        "file_path": path,
        "file_size": rng.randint(2_000, 5_000_000),
        "file_hash": new_h,
        "old_hash": old_h,
        "timestamp": ts.isoformat(),
    }
    if dest:
        ev["dest_path"] = dest
    return ev


def _work_time(rng, day_offset=0):
    """A timestamp inside office hours (Sun-Fri 10:00-17:00, Nepal week)."""
    base = datetime(2026, 3, 2) + timedelta(days=day_offset)   # a Monday
    return base.replace(hour=rng.randint(10, 16),
                        minute=rng.randint(0, 59),
                        second=rng.randint(0, 59))


def _after_hours(rng, day_offset=0):
    """A timestamp outside office hours (late night)."""
    base = datetime(2026, 3, 2) + timedelta(days=day_offset)
    return base.replace(hour=rng.choice([1, 2, 3, 22, 23]),
                        minute=rng.randint(0, 59),
                        second=rng.randint(0, 59))


# ══ BENIGN SCENARIOS ═════════════════════════════════════════════════════

def benign_routine_edit(rng, d):
    """Staff editing ordinary office documents during work hours."""
    t0 = _work_time(rng, d)
    evs = []
    for i in range(rng.randint(3, 10)):
        t = t0 + timedelta(seconds=rng.randint(0, 280))
        evs.append(_event("MODIFIED", _pick(rng, ROUTINE_FILES), t, rng))
    return evs, "benign_routine_edit"


def benign_document_creation(rng, d):
    """New notices/memos created during the working day."""
    t0 = _work_time(rng, d)
    evs = []
    for i in range(rng.randint(2, 8)):
        t = t0 + timedelta(seconds=rng.randint(0, 290))
        evs.append(_event("CREATED", _pick(rng, ROUTINE_FILES), t, rng))
    return evs, "benign_document_creation"


def benign_routine_cleanup(rng, d):
    """Deleting temp/draft files — deletions that are NOT an attack."""
    t0 = _work_time(rng, d)
    evs = []
    for i in range(rng.randint(3, 9)):
        t = t0 + timedelta(seconds=rng.randint(0, 200))
        evs.append(_event("DELETED", f"temp/draft_{rng.randint(1,99)}.tmp", t, rng))
    return evs, "benign_routine_cleanup"


def benign_bulk_import(rng, d):
    """
    HARD BENIGN CASE — a clerk bulk-imports a batch of scanned records.
    High event rate + high burst score, which superficially resembles an
    attack. This is the case that produces false positives.
    """
    t0 = _work_time(rng, d)
    evs = []
    for i in range(rng.randint(25, 45)):
        t = t0 + timedelta(seconds=rng.randint(0, 90))
        evs.append(_event("CREATED", _pick(rng, SENSITIVE_FILES), t, rng))
    return evs, "benign_bulk_import"


def benign_sensitive_workhours(rng, d):
    """
    HARD BENIGN CASE — an officer legitimately updates citizenship/land
    records during office hours. HIGH sensitivity, but entirely legitimate.
    A sensitivity-only rule will flag this; it should not.
    """
    t0 = _work_time(rng, d)
    evs = []
    for i in range(rng.randint(2, 7)):
        t = t0 + timedelta(seconds=rng.randint(0, 270))
        evs.append(_event("MODIFIED", _pick(rng, SENSITIVE_FILES), t, rng))
    return evs, "benign_sensitive_workhours"


# ══ MALICIOUS SCENARIOS ══════════════════════════════════════════════════

def attack_ransomware(rng, d):
    """Mass encryption: files renamed to encrypted extensions + ransom note."""
    t0 = _after_hours(rng, d) if rng.random() < 0.6 else _work_time(rng, d)
    evs = []
    ext = rng.choice(ENCRYPTED_EXTS)
    for i in range(rng.randint(20, 40)):
        t = t0 + timedelta(seconds=rng.randint(0, 60))
        src = _pick(rng, SENSITIVE_FILES)
        evs.append(_event("MOVED", src, t, rng, dest=src + ext))
    note = rng.choice(RANSOM_NOTES)
    evs.append(_event("CREATED", f"records/{note}",
                      t0 + timedelta(seconds=65), rng))
    return evs, "attack_ransomware"


def attack_mass_deletion(rng, d):
    """Data destruction — bulk deletion of government records."""
    t0 = _after_hours(rng, d)
    evs = []
    for i in range(rng.randint(22, 45)):
        t = t0 + timedelta(seconds=rng.randint(0, 80))
        evs.append(_event("DELETED", _pick(rng, SENSITIVE_FILES), t, rng))
    return evs, "attack_mass_deletion"


def attack_record_tampering(rng, d):
    """
    Insider tampering — quietly altering land/citizenship records at night.
    LOW event volume: this is the stealthy case that volume-based rules miss.
    """
    t0 = _after_hours(rng, d)
    evs = []
    for i in range(rng.randint(2, 6)):
        t = t0 + timedelta(seconds=rng.randint(0, 240))
        evs.append(_event("MODIFIED", _pick(rng, SENSITIVE_FILES), t, rng))
    return evs, "attack_record_tampering"


def attack_credential_theft(rng, d):
    """Access and modification of credential/key material."""
    t0 = _after_hours(rng, d)
    evs = []
    for f in rng.sample(CREDENTIAL_FILES, rng.randint(2, 4)):
        t = t0 + timedelta(seconds=rng.randint(0, 200))
        evs.append(_event("MODIFIED", f, t, rng))
    return evs, "attack_credential_theft"


def attack_staged_exfil(rng, d):
    """
    Staged exfiltration — sensitive records copied out to a staging folder
    after hours, then originals touched. Moderate volume, high sensitivity.
    """
    t0 = _after_hours(rng, d)
    evs = []
    for i in range(rng.randint(10, 20)):
        t = t0 + timedelta(seconds=rng.randint(0, 150))
        src = _pick(rng, SENSITIVE_FILES)
        evs.append(_event("CREATED", f"staging/{src.split('/')[-1]}", t, rng))
        evs.append(_event("MODIFIED", src, t + timedelta(seconds=1), rng))
    return evs, "attack_staged_exfil"


def attack_inplace_encryption(rng, d):
    """
    EVASIVE ATTACK — ransomware that encrypts files IN PLACE.

    No renamed extension and no ransom note, so every signature check in
    server/ransomware is bypassed. It also runs during office hours, so the
    working-hours rule contributes nothing. The only remaining signal is
    behavioural: a very high rate of modifications with a near-total hash
    turnover. This is the case that tests whether the One-Class SVM adds
    genuine detection capability beyond the rule engine.
    """
    t0 = _work_time(rng, d)
    evs = []
    for i in range(rng.randint(30, 55)):
        t = t0 + timedelta(seconds=rng.randint(0, 70))
        evs.append(_event("MODIFIED", _pick(rng, SENSITIVE_FILES), t, rng))
    return evs, "attack_inplace_encryption"


def attack_slow_drip_deletion(rng, d):
    """
    EVASIVE ATTACK — 'low and slow' destruction. Deletions are spread thinly
    across the window so the mass-deletion thresholds (20 deletes / 120 s) are
    never tripped, and it runs during office hours to defeat the time rule.
    """
    t0 = _work_time(rng, d)
    evs = []
    for i in range(rng.randint(8, 14)):
        t = t0 + timedelta(seconds=rng.randint(0, 290))
        evs.append(_event("DELETED", _pick(rng, SENSITIVE_FILES), t, rng))
    return evs, "attack_slow_drip_deletion"


def attack_stealth_tampering(rng, d):
    """
    HARDEST CASE — an insider alters two or three land records during normal
    office hours, at a normal pace, from a legitimate account.

    By construction this is almost indistinguishable from
    benign_sensitive_workhours. It is included deliberately: a detector that
    claims to catch this would be over-fitting, and an honest evaluation must
    show where the system's limits lie.
    """
    t0 = _work_time(rng, d)
    evs = []
    for i in range(rng.randint(2, 4)):
        t = t0 + timedelta(seconds=rng.randint(0, 250))
        evs.append(_event("MODIFIED", _pick(rng, SENSITIVE_FILES), t, rng))
    return evs, "attack_stealth_tampering"


BENIGN_SCENARIOS = [
    benign_routine_edit,
    benign_document_creation,
    benign_routine_cleanup,
    benign_bulk_import,
    benign_sensitive_workhours,
]

ATTACK_SCENARIOS = [
    # Overt attacks — signature and rule detectable
    attack_ransomware,
    attack_mass_deletion,
    attack_record_tampering,
    attack_credential_theft,
    attack_staged_exfil,
    # Evasive attacks — designed to defeat the rule engine
    attack_inplace_encryption,
    attack_slow_drip_deletion,
    attack_stealth_tampering,
]


def generate_dataset(n_benign=400, n_attack=100, seed=42):
    """
    Returns a list of dicts:
        {"events": [...], "label": 0|1, "scenario": str}
    label 1 = malicious, 0 = benign.

    Scenarios are drawn round-robin so each type is evenly represented,
    which keeps per-scenario recall statistics meaningful.
    """
    rng = random.Random(seed)
    windows = []

    for i in range(n_benign):
        fn = BENIGN_SCENARIOS[i % len(BENIGN_SCENARIOS)]
        evs, name = fn(rng, d=i % 5)
        windows.append({"events": evs, "label": 0, "scenario": name})

    for i in range(n_attack):
        fn = ATTACK_SCENARIOS[i % len(ATTACK_SCENARIOS)]
        evs, name = fn(rng, d=i % 5)
        windows.append({"events": evs, "label": 1, "scenario": name})

    rng.shuffle(windows)
    return windows
