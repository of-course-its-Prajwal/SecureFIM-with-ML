"""
SecureFIM Pro  ML Anomaly Detection (One-Class SVM)

"""

import os
import logging
import threading
import time
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

import numpy as np
import joblib
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

from server.config import ML_MODEL_DIR, ML_MIN_TRAINING_SAMPLES, ML_RETRAIN_INTERVAL

log = logging.getLogger("securefim.ml")

FEATURE_NAMES = [
    "event_rate", "modify_ratio", "delete_ratio", "create_ratio",
    "unique_paths", "path_depth_mean", "hash_change_rate", "size_std",
    "burst_score", "hour_sin", "hour_cos",
]

MODEL_FILE = os.path.join(ML_MODEL_DIR, "ocsvm_model.joblib")
SCALER_FILE = os.path.join(ML_MODEL_DIR, "ocsvm_scaler.joblib")


def _path_depth(p: str) -> int:
    return p.count("/") + p.count("\\")


def extract_features(events: list[dict], window_seconds: int = 300) -> np.ndarray:
    """
    Extract an 11-dimensional feature vector from a list of event dicts.
    Each event should have: event_type, file_path, file_size, file_hash, timestamp.
    """
    if not events:
        return np.zeros(len(FEATURE_NAMES))

    n = len(events)

    # Parse timestamps
    timestamps = []
    for e in events:
        ts = e.get("timestamp")
        if isinstance(ts, str):
            try:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
            except Exception:
                timestamps.append(time.time())
        elif isinstance(ts, (int, float)):
            timestamps.append(ts)
        else:
            timestamps.append(time.time())

    span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else window_seconds
    span = max(span, 1.0)

    event_rate = n / (span / 60.0)

    types = [e.get("event_type", "UNKNOWN").upper() for e in events]
    type_counts = Counter(types)
    modify_ratio = type_counts.get("MODIFIED", 0) / n
    delete_ratio = type_counts.get("DELETED", 0) / n
    create_ratio = type_counts.get("CREATED", 0) / n

    paths = [e.get("file_path", "") for e in events]
    unique_paths = len(set(paths))
    path_depth_mean = np.mean([_path_depth(p) for p in paths]) if paths else 0.0

    hashes = [e.get("file_hash") for e in events if e.get("file_hash")]
    old_hashes = [e.get("old_hash") for e in events if e.get("old_hash")]
    hash_change_rate = 0.0
    if old_hashes:
        changes = sum(1 for e in events if e.get("old_hash") and e.get("file_hash") and e["old_hash"] != e["file_hash"])
        hash_change_rate = changes / n

    sizes = [e.get("file_size", 0) for e in events if isinstance(e.get("file_size"), (int, float))]
    size_std = float(np.std(sizes)) if len(sizes) > 1 else 0.0

    # Burst score: max events in any 10s sub-window
    sorted_ts = sorted(timestamps)
    burst_score = 0
    for i, t in enumerate(sorted_ts):
        count = sum(1 for t2 in sorted_ts[i:] if t2 - t <= 10.0)
        burst_score = max(burst_score, count)

    # Cyclical hour encoding
    if timestamps:
        avg_ts = np.mean(timestamps)
        hour = datetime.fromtimestamp(avg_ts).hour + datetime.fromtimestamp(avg_ts).minute / 60.0
    else:
        hour = 12.0
    hour_sin = math.sin(2 * math.pi * hour / 24.0)
    hour_cos = math.cos(2 * math.pi * hour / 24.0)

    return np.array([
        event_rate, modify_ratio, delete_ratio, create_ratio,
        unique_paths, path_depth_mean, hash_change_rate, size_std,
        burst_score, hour_sin, hour_cos,
    ], dtype=np.float64)


class AnomalyDetector:
    

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.model: Optional[OneClassSVM] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained = False
        self.training_data: list[np.ndarray] = []
        self.lock = threading.Lock()
        self._last_train_time = 0.0

        os.makedirs(ML_MODEL_DIR, exist_ok=True)
        self._load_model()

    #  persistence 

    def _load_model(self):
        try:
            if os.path.exists(MODEL_FILE) and os.path.exists(SCALER_FILE):
                self.model = joblib.load(MODEL_FILE)
                self.scaler = joblib.load(SCALER_FILE)
                self.is_trained = True
                log.info("Loaded ML model from %s", MODEL_FILE)
        except Exception as exc:
            log.warning("Could not load ML model: %s", exc)

    def _save_model(self):
        try:
            joblib.dump(self.model, MODEL_FILE)
            joblib.dump(self.scaler, SCALER_FILE)
            log.info("Saved ML model to %s", MODEL_FILE)
        except Exception as exc:
            log.error("Could not save ML model: %s", exc)

    #  training 

    def add_training_sample(self, events: list[dict]):
        """Add a window of events as a normal training sample."""
        features = extract_features(events, self.window_seconds)
        with self.lock:
            self.training_data.append(features)
            log.debug("Training samples: %d / %d", len(self.training_data), ML_MIN_TRAINING_SAMPLES)

    def can_train(self) -> bool:
        return len(self.training_data) >= ML_MIN_TRAINING_SAMPLES

    def train(self) -> bool:
        """Train the One-Class SVM on collected normal samples."""
        with self.lock:
            if len(self.training_data) < ML_MIN_TRAINING_SAMPLES:
                log.warning("Not enough training data: %d / %d",
                            len(self.training_data), ML_MIN_TRAINING_SAMPLES)
                return False

            X = np.array(self.training_data)
            log.info("Training One-Class SVM on %d samples, %d features", X.shape[0], X.shape[1])

            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)

            self.model = OneClassSVM(
                kernel="rbf",
                gamma="scale",
                nu=0.05,        # expect ~5 % outlier rate
            )
            self.model.fit(X_scaled)
            self.is_trained = True
            self._last_train_time = time.time()

            self._save_model()
            log.info("One-Class SVM training complete")
            return True

    def maybe_retrain(self):
        """Retrain if enough time has passed and we have new data."""
        if time.time() - self._last_train_time > ML_RETRAIN_INTERVAL and self.can_train():
            self.train()

    #  inference 

    def predict(self, events: list[dict]) -> dict:
        """
        Run anomaly detection on a window of events.
        Returns {is_anomaly, score, features, description}.
        """
        features = extract_features(events, self.window_seconds)
        result = {
            "is_anomaly": False,
            "score": 0.0,
            "features": dict(zip(FEATURE_NAMES, features.tolist())),
            "description": "",
        }

        if not self.is_trained or self.model is None or self.scaler is None:
            # Fallback: simple rule-based detection
            return self._rule_based_detect(features, result)

        with self.lock:
            X = self.scaler.transform(features.reshape(1, -1))
            prediction = self.model.predict(X)[0]          # +1 normal, -1 anomaly
            score = self.model.decision_function(X)[0]      # distance to boundary

        result["score"] = float(score)
        if prediction == -1:
            result["is_anomaly"] = True
            result["description"] = self._describe_anomaly(features, score)

        return result

    #  rule-based fallback 

    def _rule_based_detect(self, features: np.ndarray, result: dict) -> dict:
        """
        Simple threshold checks before the model is trained.
        Requires minimum event counts to avoid false positives on
        normal single-file operations (e.g. one delete is NOT an anomaly).
        """
        event_rate = features[0]
        delete_ratio = features[2]
        unique_paths = features[4]
        burst_score = features[8]

        reasons = []

        # High event rate: >120 events/min is suspicious
        if event_rate > 120:
            reasons.append(f"very high event rate ({event_rate:.0f}/min)")

        # Mass deletion: >60% deletes AND at least 10 unique paths
        if delete_ratio > 0.6 and unique_paths >= 10:
            reasons.append(f"mass deletion ({delete_ratio:.0%} of {int(unique_paths)} paths)")

        # Burst: >30 events in a 10-second window
        if burst_score > 30:
            reasons.append(f"burst of {int(burst_score)} events in 10s")

        if reasons:
            result["is_anomaly"] = True
            result["score"] = -1.0
            result["description"] = "Rule-based: " + "; ".join(reasons)
        return result

    def _describe_anomaly(self, features: np.ndarray, score: float) -> str:
        parts = [f"SVM score={score:.3f}"]
        if features[0] > 60:
            parts.append(f"high rate ({features[0]:.0f}/min)")
        if features[2] > 0.4:
            parts.append(f"many deletions ({features[2]:.0%})")
        if features[8] > 15:
            parts.append(f"burst={int(features[8])}")
        if features[6] > 0.5:
            parts.append(f"hash changes ({features[6]:.0%})")
        return "; ".join(parts)

    #  status 

    def status(self) -> dict:
        return {
            "is_trained": self.is_trained,
            "training_samples": len(self.training_data),
            "min_required": ML_MIN_TRAINING_SAMPLES,
            "model_file_exists": os.path.exists(MODEL_FILE),
            "feature_names": FEATURE_NAMES,
        }
