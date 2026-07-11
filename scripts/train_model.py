#!/usr/bin/env python3
"""
SecureFIM Pro — ML Training Data Generator
Generates synthetic normal FIM events and trains the One-Class SVM model.

Usage:
    python scripts/train_model.py [--server http://localhost:8443] [--samples 200]
"""

import argparse
import random
import time
import math
import json
from datetime import datetime, timezone, timedelta

import requests
import numpy as np

NORMAL_PATHS = [
    "/var/log/syslog", "/var/log/auth.log", "/etc/crontab",
    "/home/user/documents/report.docx", "/home/user/documents/notes.txt",
    "/opt/app/config.yaml", "/opt/app/data/cache.db",
    "/tmp/session_001.tmp", "/var/www/html/index.html",
    "/home/user/.bashrc", "/etc/hosts", "/var/log/kern.log",
]

EVENT_TYPES = ["CREATED", "MODIFIED", "DELETED", "MOVED"]
EVENT_WEIGHTS = [0.2, 0.5, 0.15, 0.15]  # Normal distribution


def generate_normal_window(window_minutes: int = 5) -> list[dict]:
    """Generate a realistic window of normal FIM events."""
    # Normal activity: 5-20 events per 5 minutes
    n_events = random.randint(5, 20)
    now = datetime.now(timezone.utc)
    events = []

    for _ in range(n_events):
        t = now - timedelta(seconds=random.uniform(0, window_minutes * 60))
        etype = random.choices(EVENT_TYPES, weights=EVENT_WEIGHTS, k=1)[0]
        path = random.choice(NORMAL_PATHS)
        size = random.randint(100, 500000) if etype != "DELETED" else 0
        fake_hash = f"{random.getrandbits(128):032x}" if etype != "DELETED" else None

        events.append({
            "agent_id": "training-agent",
            "event_type": etype,
            "file_path": path,
            "file_size": size,
            "file_hash": fake_hash,
            "old_hash": f"{random.getrandbits(128):032x}" if etype == "MODIFIED" and random.random() > 0.5 else None,
            "severity": "info" if etype in ("CREATED", "MODIFIED") else "warning",
            "hostname": "training-host",
            "os_type": "Linux",
            "timestamp": t.isoformat(),
        })

    return events


def main():
    parser = argparse.ArgumentParser(description="Train SecureFIM ML model")
    parser.add_argument("--server", default="http://localhost:8443")
    parser.add_argument("--samples", type=int, default=200,
                        help="Number of training windows to generate")
    parser.add_argument("--send-to-server", action="store_true",
                        help="Send events to server (also trains via API)")
    args = parser.parse_args()

    print(f"Generating {args.samples} normal activity windows...")
    print()

    if args.send_to_server:
        # Send events to server which will collect training data
        for i in range(args.samples):
            window = generate_normal_window()
            try:
                resp = requests.post(f"{args.server}/api/events", json=window, timeout=10)
                if resp.status_code == 200:
                    result = resp.json()
                    print(f"  Window {i+1}/{args.samples}: sent {len(window)} events "
                          f"(anomalies: {result.get('anomalies', 0)})")
                else:
                    print(f"  Window {i+1}: server error {resp.status_code}")
            except requests.ConnectionError:
                print(f"  Cannot reach server at {args.server}")
                return
            time.sleep(0.1)

        # Trigger training
        print()
        print("Triggering model training...")
        try:
            resp = requests.post(f"{args.server}/api/ml/train", timeout=60)
            result = resp.json()
            print(f"  Training result: {result}")
        except Exception as exc:
            print(f"  Training error: {exc}")

    else:
        # Train locally using the ML module directly
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from server.ml import AnomalyDetector

        detector = AnomalyDetector(window_seconds=300)
        for i in range(args.samples):
            window = generate_normal_window()
            detector.add_training_sample(window)
            if (i + 1) % 50 == 0:
                print(f"  Collected {i+1}/{args.samples} samples")

        print()
        print("Training model...")
        success = detector.train()
        print(f"  Training {'succeeded' if success else 'failed'}")
        print(f"  Model saved: {detector.status()['model_file_exists']}")

        # Test with a normal window
        test_window = generate_normal_window()
        result = detector.predict(test_window)
        print(f"  Normal test: anomaly={result['is_anomaly']}, score={result['score']:.3f}")

        # Test with an anomalous window (lots of deletes)
        anomalous = []
        now = datetime.now(timezone.utc)
        for j in range(100):  # burst of 100 deletes
            anomalous.append({
                "event_type": "DELETED",
                "file_path": f"/home/user/documents/file_{j}.docx",
                "file_size": 0,
                "file_hash": None,
                "timestamp": (now - timedelta(seconds=random.uniform(0, 30))).isoformat(),
            })
        result = detector.predict(anomalous)
        print(f"  Anomaly test: anomaly={result['is_anomaly']}, score={result['score']:.3f}")


if __name__ == "__main__":
    main()
