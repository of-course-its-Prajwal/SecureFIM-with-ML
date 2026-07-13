"""
SecureFIM Pro — Detector Configurations Under Evaluation

Three configurations are compared on the SAME labelled test set:

  A. CHECKSUM-ONLY  (classical FIM baseline, e.g. Tripwire/AIDE style)
       Alerts on any detected integrity change. No context, no intelligence.
       This is the H1 baseline.

  B. RULE-BASED     (SecureFIM Pro with the ML detector disabled)
       Ransomware signatures + mass-pattern rules + Nepali sensitivity
       classification + working-hours check + composite threat score.
       This is the H2 baseline.

  C. FULL SYSTEM    (SecureFIM Pro as deployed)
       Configuration B plus the One-Class SVM anomaly detector feeding the
       composite threat score.

Configurations B and C call the PRODUCTION modules directly
(server.ransomware, server.features, server.ml) — this evaluates the real
deployed logic rather than a reimplementation of it.
"""

import os

# Point the ML model cache at a scratch dir so the evaluation NEVER
# overwrites the production model in models/.
os.environ.setdefault("ML_MODEL_DIR", os.path.join("evaluation", "_model_cache"))
os.environ.setdefault("ML_MIN_TRAINING_SAMPLES", "50")

from server.ransomware import RansomwareDetector          # noqa: E402
from server.features import (                             # noqa: E402
    WorkingHoursDetector,
    classify_sensitivity,
    calculate_threat_score,
)
from server.ml import AnomalyDetector                     # noqa: E402


# ── A. Checksum-only baseline ────────────────────────────────────────────

def detect_checksum_only(window):
    """
    Classical FIM: raise an alert if the integrity of any monitored file
    changed. It cannot distinguish a clerk editing a memo from ransomware
    encrypting the records directory — which is precisely its weakness.

    Returns (flagged: bool, score: float)
    """
    for e in window["events"]:
        etype = e.get("event_type", "").upper()
        if etype in ("CREATED", "DELETED", "MOVED"):
            return True, 100.0
        if etype == "MODIFIED" and e.get("old_hash") != e.get("file_hash"):
            return True, 100.0
    return False, 0.0


# ── Shared scoring core for B and C ──────────────────────────────────────

def _score_window(window, anomaly_detector=None):
    """
    Score one window with the production rule engine.
    If anomaly_detector is supplied, its ML verdict is folded into the
    composite threat score (configuration C); otherwise ML is off (config B).

    Returns the maximum composite threat score across the window's events.
    """
    events = window["events"]

    # Fresh ransomware detector per window: the 120-second sliding window
    # inside the detector is per-window state, so it must not leak between
    # independent test windows (that would contaminate the results).
    rw = RansomwareDetector()
    wh = WorkingHoursDetector()

    # ML verdict for the whole window (the SVM operates on windows).
    is_anomaly, ml_score = False, 0.0
    if anomaly_detector is not None:
        verdict = anomaly_detector.predict(events)
        is_anomaly = bool(verdict["is_anomaly"])
        ml_score = float(verdict["score"])

    max_score = 0.0
    for e in events:
        rw_alert = rw.record_event(
            e.get("event_type", ""),
            e.get("file_path", ""),
            e.get("dest_path", ""),
        )
        is_ransomware = rw_alert is not None

        sensitivity = classify_sensitivity(e.get("file_path", ""))
        outside = wh.is_outside_hours(e.get("timestamp"))["outside_hours"]

        result = calculate_threat_score(
            event=e,
            ml_score=ml_score,
            is_ransomware=is_ransomware,
            is_anomaly=is_anomaly,
            outside_hours=outside,
            sensitivity=sensitivity,
            corroborative=False,      # Config B/C = original additive model
        )
        max_score = max(max_score, float(result["score"]))

    return max_score


def detect_rules_only(window, threshold=70.0):
    """Configuration B — SecureFIM Pro with ML disabled."""
    score = _score_window(window, anomaly_detector=None)
    return score >= threshold, score


def detect_full_system(window, anomaly_detector, threshold=70.0):
    """Configuration C — SecureFIM Pro as deployed (rules + One-Class SVM)."""
    score = _score_window(window, anomaly_detector=anomaly_detector)
    return score >= threshold, score


# ── ML training helper ───────────────────────────────────────────────────

def train_anomaly_detector(benign_training_windows):
    """
    Train the One-Class SVM on BENIGN windows only.

    This is the methodologically correct protocol for one-class learning:
    the model learns the boundary of normal behaviour and never sees an
    attack during training. Attack windows appear only at test time.
    """
    det = AnomalyDetector()
    # Discard any previously persisted model so the run is reproducible.
    det.model = None
    det.scaler = None
    det.is_trained = False
    det.training_data = []

    for w in benign_training_windows:
        det.add_training_sample(w["events"])

    trained = det.train()
    if not trained:
        raise RuntimeError(
            f"One-Class SVM training failed — only {len(det.training_data)} "
            f"samples collected. Increase n_benign or lower "
            f"ML_MIN_TRAINING_SAMPLES."
        )
    return det


# ── D. Corroborative scoring (now implemented in production) ─────────────

from server.features import is_volumetric_alert                # noqa: E402


def _score_window_corroborative(window, anomaly_detector):
    """
    Configuration D — SecureFIM Pro with corroborative scoring.

    This calls the SAME production function as Configuration C, with
    corroborative=True, so the evaluation exercises the deployed logic. A
    VOLUMETRIC ransomware rule (mass create / rename / delete / modify) is only
    credited if the One-Class SVM corroborates it; signature evidence (encrypted
    extension, ransom note) is always trusted. The classifier can therefore veto
    a rule, which the additive architecture structurally prevented.
    """
    events = window["events"]
    rw = RansomwareDetector()
    wh = WorkingHoursDetector()

    verdict = anomaly_detector.predict(events)
    is_anomaly = bool(verdict["is_anomaly"])
    ml_score = float(verdict["score"])

    max_score = 0.0
    for e in events:
        rw_alert = rw.record_event(
            e.get("event_type", ""), e.get("file_path", ""), e.get("dest_path", "")
        )
        volumetric = is_volumetric_alert(rw_alert)

        result = calculate_threat_score(
            event=e,
            ml_score=ml_score,
            is_ransomware=rw_alert is not None,
            is_anomaly=is_anomaly,
            outside_hours=wh.is_outside_hours(e.get("timestamp"))["outside_hours"],
            sensitivity=classify_sensitivity(e.get("file_path", "")),
            ransomware_volumetric=volumetric,
            corroborative=True,
        )
        max_score = max(max_score, float(result["score"]))

    return max_score


def detect_corroborative(window, anomaly_detector, threshold=70.0):
    """Configuration D — corroborative (veto-capable) scoring."""
    score = _score_window_corroborative(window, anomaly_detector)
    return score >= threshold, score
