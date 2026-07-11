#!/usr/bin/env python3
"""
SecureFIM Pro — Event Simulator
Simulates agent events for testing the dashboard and anomaly detection.

Usage:
    python scripts/simulate_events.py [--server http://localhost:8443] [--mode normal|attack|mixed]
"""

import argparse
import random
import time
from datetime import datetime, timezone

import requests

SERVER = "http://localhost:8443"

NORMAL_PATHS = [
    "/var/log/syslog", "/var/log/auth.log", "/home/user/docs/report.txt",
    "/opt/app/config.yml", "/tmp/cache.db", "/var/www/index.html",
]

SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys",
    "/etc/sudoers", "/var/lib/secrets/key.pem",
]


def register_agent(server: str, agent_id: str):
    try:
        resp = requests.post(f"{server}/api/agents/register", json={
            "agent_id": agent_id,
            "hostname": f"sim-{agent_id}",
            "os_type": "Linux",
            "os_version": "Ubuntu 22.04",
            "agent_version": "4.0.0",
            "monitored_paths": ["/var/log", "/home/user", "/etc"],
        }, timeout=5)
        print(f"  Registered agent {agent_id}: {resp.json()}")
    except Exception as exc:
        print(f"  Registration failed: {exc}")


def send_events(server: str, events: list):
    try:
        resp = requests.post(f"{server}/api/events", json=events, timeout=10)
        result = resp.json()
        print(f"  Sent {len(events)} events — anomalies: {result.get('anomalies', 0)}")
    except Exception as exc:
        print(f"  Send failed: {exc}")


def send_heartbeat(server: str, agent_id: str):
    try:
        requests.post(f"{server}/api/agents/{agent_id}/heartbeat", json={
            "cpu_percent": random.uniform(5, 85),
            "memory_percent": random.uniform(30, 75),
            "disk_percent": random.uniform(20, 60),
            "event_count": random.randint(10, 500),
            "uptime": random.randint(100, 86400),
        }, timeout=5)
    except Exception:
        pass


def normal_event(agent_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "event_type": random.choice(["CREATED", "MODIFIED", "MODIFIED", "MODIFIED"]),
        "file_path": random.choice(NORMAL_PATHS),
        "file_size": random.randint(100, 100000),
        "file_hash": f"{random.getrandbits(256):064x}",
        "severity": "info",
        "hostname": f"sim-{agent_id}",
        "os_type": "Linux",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def attack_event(agent_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "event_type": random.choice(["DELETED", "MODIFIED", "DELETED"]),
        "file_path": random.choice(SENSITIVE_PATHS),
        "file_size": 0 if random.random() > 0.5 else random.randint(10, 500),
        "file_hash": f"{random.getrandbits(256):064x}",
        "old_hash": f"{random.getrandbits(256):064x}",
        "severity": "critical",
        "hostname": f"sim-{agent_id}",
        "os_type": "Linux",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default=SERVER)
    parser.add_argument("--mode", choices=["normal", "attack", "mixed"], default="mixed")
    parser.add_argument("--agents", type=int, default=2)
    parser.add_argument("--duration", type=int, default=120, help="Duration in seconds")
    args = parser.parse_args()

    agent_ids = [f"sim-agent-{i}" for i in range(1, args.agents + 1)]

    print(f"Registering {len(agent_ids)} simulated agents...")
    for aid in agent_ids:
        register_agent(args.server, aid)

    print(f"\nSimulating {args.mode} events for {args.duration}s...")
    start = time.time()
    cycle = 0

    try:
        while time.time() - start < args.duration:
            cycle += 1
            for aid in agent_ids:
                if args.mode == "normal":
                    events = [normal_event(aid) for _ in range(random.randint(1, 5))]
                elif args.mode == "attack":
                    events = [attack_event(aid) for _ in range(random.randint(10, 40))]
                else:
                    # Mixed: mostly normal with occasional bursts
                    if cycle % 10 == 0:
                        events = [attack_event(aid) for _ in range(random.randint(15, 30))]
                        print(f"  ** ATTACK BURST from {aid} **")
                    else:
                        events = [normal_event(aid) for _ in range(random.randint(1, 4))]

                send_events(args.server, events)
                send_heartbeat(args.server, aid)

            time.sleep(3)

    except KeyboardInterrupt:
        pass

    print("\nSimulation complete.")


if __name__ == "__main__":
    main()
