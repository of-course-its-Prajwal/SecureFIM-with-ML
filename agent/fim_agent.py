#!/usr/bin/env python3
"""
SecureFIM Pro — Agent
Runs on endpoint devices. Monitors configured paths for file changes,
computes hashes, and sends events + heartbeats to the SecureFIM server.

Usage:
    python -m agent.fim_agent \
        --server http://localhost:8443 \
        --paths /etc /var/www \
        --agent-id myhost-01
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import signal
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

import psutil
import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

#  Logging 

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Agent] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("agent")

# Configuration 

DEFAULT_SERVER = os.getenv("SECUREFIM_SERVER", "http://localhost:8443")
DEFAULT_HEARTBEAT = int(os.getenv("AGENT_HEARTBEAT_INTERVAL", "30"))
DEFAULT_BATCH_INTERVAL = int(os.getenv("AGENT_BATCH_INTERVAL", "5"))
CONFIG_FILE = os.getenv("AGENT_CONFIG_FILE", "agent_config.json")


def generate_agent_id() -> str:
    hostname = socket.gethostname()
    return f"{hostname}-{uuid.uuid4().hex[:8]}"


# File hash helper 

def file_hash(path: str, algo: str = "sha256") -> str | None:
    try:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


#  Watchdog Handler 

class FIMHandler(FileSystemEventHandler):
    """Captures file system events and queues them for batch sending."""

    SKIP_EXT = {".tmp", ".swp", ".pyc", ".log", ".cache"}
    SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".idea"}

    def __init__(self, agent_id: str, hash_db: dict, backup_dir: str = None, backup_enabled: bool = True):
        super().__init__()
        self.agent_id = agent_id
        self.hash_db = hash_db  # path -> last_hash
        self.queue: list[dict] = []
        self.lock = threading.Lock()
        self.event_count = 0
        self.backup_enabled = backup_enabled
        self.backup_dir = backup_dir or os.path.join(os.path.expanduser("~"), ".securefim_backup")
        if self.backup_enabled:
            os.makedirs(self.backup_dir, exist_ok=True)
            log.info("Backup directory: %s", self.backup_dir)

    def _is_sensitive(self, path: str) -> bool:
        """Check if a file path matches HIGH sensitivity patterns (for auto-backup)."""
        path_lower = path.lower().replace("\\", "/")
        sensitive_keywords = [
            # Nepal government records
            "citizenship", "nagarikta", "lalpurja", "malpot", "bhumi",
            "passport", "license", "voter_id", "tax_record",
            "land_record", "land_ownership", "property_record",
            # Critical files
            "password", "credentials", "secret", "private_key",
            ".pem", ".key", ".pfx", ".env",
            # Databases
            ".db", ".sqlite", ".mdb", ".accdb",
            # Backups
            ".backup", ".bak",
            # Education
            "exam_result", "answer_key", "marks_sheet", "student_record",
            # Medical
            "patient_record", "medical_record",
            # Financial
            "balance_sheet", "ledger", "bank_statement",
        ]
        return any(kw in path_lower for kw in sensitive_keywords)

    def _backup_file(self, path: str) -> str | None:
        """
        Create a backup copy of a sensitive file before it's modified/deleted.
        Returns the backup path, or None if not backed up.
        """
        if not self.backup_enabled:
            return None
        if not os.path.isfile(path):
            return None
        if not self._is_sensitive(path):
            return None

        try:
            import shutil
            # Generate a unique backup filename: original_name.YYYYMMDD_HHMMSS.hash.bak
            filename = os.path.basename(path)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Add short hash to avoid collisions
            try:
                h = file_hash(path) or ""
                h_short = h[:8] if h else "nohash"
            except Exception:
                h_short = "nohash"
            backup_name = f"{filename}.{ts}.{h_short}.bak"

            # Preserve directory structure in backup
            rel_path = path.replace(":", "").replace("\\", "/").lstrip("/")
            backup_subdir = os.path.join(self.backup_dir, os.path.dirname(rel_path))
            os.makedirs(backup_subdir, exist_ok=True)
            backup_path = os.path.join(backup_subdir, backup_name)

            shutil.copy2(path, backup_path)
            log.info("Backed up sensitive file: %s → %s", path, backup_path)
            return backup_path
        except Exception as exc:
            log.error("Backup failed for %s: %s", path, exc)
            return None

    def _skip(self, path: str) -> bool:
        _, ext = os.path.splitext(path)
        if ext.lower() in self.SKIP_EXT:
            return True
        parts = path.replace("\\", "/").split("/")
        return any(p in self.SKIP_DIRS for p in parts)

    def _get_file_owner(self, path: str) -> tuple[str, str]:
        """
        Get the user who owns/last modified the file.
        Returns (username, process_info).
        """
        username = "unknown"
        process_info = ""
        try:
            if platform.system() == "Windows":
                # Windows: use os.environ for current logged-in user
                username = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
                # Try to get file owner via win32 if available
                try:
                    import win32security
                    sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
                    owner_sid = sd.GetSecurityDescriptorOwner()
                    name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
                    username = f"{domain}\\{name}" if domain else name
                except Exception:
                    pass
            else:
                # Linux/Mac: use pwd module
                try:
                    import pwd
                    stat_info = os.stat(path)
                    username = pwd.getpwuid(stat_info.st_uid).pw_name
                except Exception:
                    username = os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"
        except Exception:
            pass

        # Try to identify the process (best-effort)
        try:
            # Get active user sessions
            users = psutil.users()
            if users:
                process_info = f"session:{users[0].name}@{users[0].host or 'local'}"
        except Exception:
            pass

        return username, process_info

    def _make_event(self, event_type: str, src: str, dest: str = "") -> dict | None:
        if self._skip(src):
            return None

        size = 0
        new_hash = None
        old_hash = self.hash_db.get(src)

        if event_type != "DELETED" and os.path.isfile(src):
            try:
                size = os.path.getsize(src)
                new_hash = file_hash(src)
            except Exception:
                pass

        # Skip if hash didn't change for MODIFIED events
        if event_type == "MODIFIED" and new_hash and old_hash and new_hash == old_hash:
            return None

        if new_hash:
            self.hash_db[src] = new_hash

        if event_type == "DELETED" and src in self.hash_db:
            del self.hash_db[src]

        severity = "info"
        if event_type == "DELETED":
            severity = "warning"
        elif event_type == "MODIFIED" and old_hash and new_hash and old_hash != new_hash:
            severity = "warning"

        # User attribution
        check_path = src if event_type != "DELETED" else os.path.dirname(src)
        username, process_info = self._get_file_owner(check_path)

        # Auto-backup sensitive files (on CREATED and MODIFIED)
        backup_path = None
        if event_type in ("CREATED", "MODIFIED") and self.backup_enabled:
            backup_path = self._backup_file(src)

        return {
            "agent_id": self.agent_id,
            "event_type": event_type,
            "file_path": src,
            "dest_path": dest or None,
            "file_size": size,
            "file_hash": new_hash,
            "old_hash": old_hash,
            "severity": severity,
            "hostname": socket.gethostname(),
            "os_type": platform.system(),
            "username": username,
            "process_info": process_info,
            "backup_path": backup_path,
            "backed_up": backup_path is not None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _enqueue(self, evt: dict | None):
        if evt is None:
            return
        with self.lock:
            self.queue.append(evt)
            self.event_count += 1

    def flush(self) -> list[dict]:
        with self.lock:
            batch = self.queue[:]
            self.queue.clear()
        return batch

    # Watchdog callbacks
    def on_created(self, event):
        if not event.is_directory:
            self._enqueue(self._make_event("CREATED", event.src_path))

    def on_modified(self, event):
        if not event.is_directory:
            self._enqueue(self._make_event("MODIFIED", event.src_path))

    def on_deleted(self, event):
        if not event.is_directory:
            self._enqueue(self._make_event("DELETED", event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            self._enqueue(self._make_event("MOVED", event.src_path, event.dest_path))


#  Agent 

class FIMAgent:
    """
    File Integrity Monitoring agent.
    Registers with the server, monitors paths, sends events and heartbeats.
    """

    def __init__(self, server_url: str, agent_id: str, paths: list[str],
                 recursive: bool = True, heartbeat_interval: int = DEFAULT_HEARTBEAT,
                 batch_interval: int = DEFAULT_BATCH_INTERVAL,
                 backup_enabled: bool = True, backup_dir: str = None):
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.paths = [os.path.abspath(p) for p in paths]
        self.recursive = recursive
        self.heartbeat_interval = heartbeat_interval
        self.batch_interval = batch_interval
        self.backup_enabled = backup_enabled
        self.backup_dir = backup_dir

        self.hash_db: dict[str, str] = {}
        self.handler = FIMHandler(self.agent_id, self.hash_db, backup_dir=backup_dir, backup_enabled=backup_enabled)
        self.observers: list[Observer] = []
        self.running = False
        self.start_time = time.time()

        self._load_config()

    #  Config persistence 

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    cfg = json.load(f)
                saved_paths = cfg.get("monitored_paths", [])
                if saved_paths and not self.paths:
                    self.paths = saved_paths
                    log.info("Loaded paths from config: %s", self.paths)
                self.hash_db = cfg.get("hash_db", {})
            except Exception as exc:
                log.warning("Could not load config: %s", exc)

    def _save_config(self):
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump({
                    "agent_id": self.agent_id,
                    "server_url": self.server_url,
                    "monitored_paths": self.paths,
                    "hash_db": self.hash_db,
                }, f, indent=2)
        except Exception as exc:
            log.warning("Could not save config: %s", exc)

    #  Server communication 

    def _post(self, endpoint: str, data: dict | list) -> dict | None:
        url = f"{self.server_url}/api{endpoint}"
        try:
            resp = requests.post(url, json=data, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.ConnectionError:
            log.warning("Cannot reach server at %s", url)
        except Exception as exc:
            log.error("POST %s failed: %s", endpoint, exc)
        return None

    def _get(self, endpoint: str) -> dict | None:
        url = f"{self.server_url}/api{endpoint}"
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log.error("GET %s failed: %s", endpoint, exc)
        return None

    def register(self) -> bool:
        data = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "os_type": platform.system(),
            "os_version": platform.version(),
            "agent_version": "4.0.0",
            "monitored_paths": self.paths,
            "metadata": {
                "cpu_count": psutil.cpu_count(),
                "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 1),
                "python_version": platform.python_version(),
            },
        }
        result = self._post("/agents/register", data)
        if result and result.get("status") == "registered":
            log.info("Registered with server as %s", self.agent_id)
            return True
        log.error("Registration failed")
        return False

    def send_heartbeat(self):
        data = {
            "cpu_percent": psutil.cpu_percent(interval=0),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "event_count": self.handler.event_count,
            "uptime": int(time.time() - self.start_time),
        }
        self._post(f"/agents/{self.agent_id}/heartbeat", data)

    def send_events(self, events: list[dict]):
        if not events:
            return
        result = self._post("/events", events)
        if result:
            log.info("Sent %d events (anomalies: %s)", len(events), result.get("anomalies", 0))

    def fetch_paths(self) -> list[str] | None:
        """Fetch monitored paths from server (allows remote path management)."""
        result = self._get(f"/agents/{self.agent_id}/paths")
        if result:
            return result.get("monitored_paths")
        return None

    def update_paths(self, new_paths: list[str]):
        """Update monitored paths both locally and on server."""
        self.paths = [os.path.abspath(p) for p in new_paths]
        self._post(f"/agents/{self.agent_id}/paths",
                    {"monitored_paths": self.paths})  # Uses PUT but agent sends as POST body
        self._save_config()
        log.info("Updated monitored paths: %s", self.paths)

    #  Monitoring 

    def _start_observers(self):
        for obs in self.observers:
            try:
                obs.stop()
            except Exception:
                pass
        self.observers.clear()

        for path in self.paths:
            if not os.path.isdir(path):
                log.warning("Path does not exist, skipping: %s", path)
                continue
            obs = Observer()
            obs.schedule(self.handler, path, recursive=self.recursive)
            obs.start()
            self.observers.append(obs)
            log.info("Monitoring: %s (recursive=%s)", path, self.recursive)

    def _heartbeat_loop(self):
        while self.running:
            try:
                self.send_heartbeat()
            except Exception as exc:
                log.error("Heartbeat error: %s", exc)
            time.sleep(self.heartbeat_interval)

    def _batch_loop(self):
        while self.running:
            time.sleep(self.batch_interval)
            try:
                batch = self.handler.flush()
                if batch:
                    self.send_events(batch)
            except Exception as exc:
                log.error("Batch send error: %s", exc)

    def _path_sync_loop(self):
        """Periodically check server for path updates."""
        while self.running:
            time.sleep(60)
            try:
                server_paths = self.fetch_paths()
                if server_paths is not None and set(server_paths) != set(self.paths):
                    log.info("Server path update detected, reconfiguring...")
                    self.paths = server_paths
                    self._start_observers()
                    self._save_config()
            except Exception as exc:
                log.debug("Path sync error: %s", exc)

    def _restore_loop(self):
        """Periodically check server for pending restore requests for this agent."""
        import shutil
        log.info("Restore polling loop started (every 15s)")
        poll_count = 0
        while self.running:
            time.sleep(15)  # Check every 15 seconds
            poll_count += 1
            try:
                result = self._get(f"/agents/{self.agent_id}/restore-requests")
                if not result:
                    if poll_count % 20 == 0:  # Log every 5 min if silent
                        log.debug("Restore poll #%d: no response from server", poll_count)
                    continue
                requests_list = result.get("requests", [])
                if not requests_list:
                    if poll_count % 20 == 0:  # Log every 5 min if silent
                        log.debug("Restore poll #%d: no pending requests", poll_count)
                    continue
                log.info("Found %d pending restore request(s)!", len(requests_list))
                for req in requests_list:
                    req_id = req.get("_id") or req.get("id")
                    file_path = req.get("file_path")
                    backup_path = req.get("backup_path")
                    log.info("Processing restore: id=%s file=%s backup=%s",
                             req_id, file_path, backup_path)
                    if not file_path or not backup_path:
                        log.warning("Skipping restore %s: missing file_path or backup_path", req_id)
                        continue
                    # Perform the restore
                    try:
                        if not os.path.isfile(backup_path):
                            log.error("Backup file NOT FOUND on disk: %s", backup_path)
                            self._post(f"/agents/{self.agent_id}/restore-complete",
                                       {"request_id": req_id, "status": "failed",
                                        "error": "Backup file not found on disk"})
                            continue
                        # Make sure target directory exists
                        target_dir = os.path.dirname(file_path)
                        if target_dir:
                            os.makedirs(target_dir, exist_ok=True)
                        # Copy backup over to original location
                        shutil.copy2(backup_path, file_path)
                        log.info("✓ RESTORED: %s <-- %s", file_path, backup_path)
                        # Update hash_db so the restore isn't re-flagged
                        new_hash = file_hash(file_path)
                        if new_hash:
                            self.handler.hash_db[file_path] = new_hash
                        # Notify server
                        self._post(f"/agents/{self.agent_id}/restore-complete",
                                   {"request_id": req_id, "status": "completed",
                                    "restored_to": file_path, "restored_from": backup_path})
                    except Exception as exc:
                        log.error("Restore failed for %s: %s", file_path, exc)
                        self._post(f"/agents/{self.agent_id}/restore-complete",
                                   {"request_id": req_id, "status": "failed", "error": str(exc)})
            except Exception as exc:
                log.error("Restore poll error: %s", exc)

    def _verify_loop(self):
        """Poll server for pending baseline verification requests."""
        log.info("Verification polling loop started (every 15s)")
        poll_count = 0
        while self.running:
            time.sleep(15)
            poll_count += 1
            try:
                result = self._get(f"/agents/{self.agent_id}/verify-requests")
                if not result:
                    if poll_count % 20 == 0:
                        log.debug("Verify poll #%d: no response from server", poll_count)
                    continue
                requests_list = result.get("requests", [])
                if not requests_list:
                    if poll_count % 20 == 0:
                        log.debug("Verify poll #%d: no pending verifications", poll_count)
                    continue

                log.info("Found %d pending baseline verification(s)", len(requests_list))
                for req in requests_list:
                    req_id = req.get("request_id")
                    baseline_name = req.get("baseline_name")
                    files = req.get("files", [])
                    if not req_id or not baseline_name:
                        log.warning("Skipping verify request: missing id or baseline name")
                        continue

                    log.info("Verifying baseline '%s' (%d files)...",
                             baseline_name, len(files))

                    # Re-hash every file in the baseline
                    current = []
                    for f in files:
                        path = f.get("path")
                        if not path:
                            continue
                        try:
                            if os.path.isfile(path):
                                h = file_hash(path)
                                size = os.path.getsize(path) if h else 0
                                current.append({"path": path, "hash": h, "size": size})
                            else:
                                # File missing — report it so server can mark as deleted
                                current.append({"path": path, "hash": None, "size": 0,
                                                "missing": True})
                        except Exception as exc:
                            log.warning("Hash failed for %s: %s", path, exc)
                            current.append({"path": path, "hash": None, "size": 0,
                                            "error": str(exc)})

                    # Report back to server
                    try:
                        resp = self._post(f"/agents/{self.agent_id}/verify-complete", {
                            "request_id": req_id,
                            "baseline_name": baseline_name,
                            "files": current,
                        })
                        if resp:
                            log.info("✓ Verification complete: %s integrity=%s drift=%s",
                                     baseline_name,
                                     resp.get("integrity_score"),
                                     resp.get("drift_detected"))
                        else:
                            log.warning("Verify-complete got empty response")
                    except Exception as exc:
                        log.error("Failed to report verification: %s", exc)

            except Exception as exc:
                log.error("Verify poll error: %s", exc)

    def start(self):
        log.info("Starting FIM Agent: %s", self.agent_id)
        log.info("Server: %s", self.server_url)
        log.info("Paths: %s", self.paths)

        # Validate paths
        valid_paths = [p for p in self.paths if os.path.isdir(p)]
        if not valid_paths:
            log.error("No valid paths to monitor!")
            return False

        self.paths = valid_paths

        # Register with server
        for attempt in range(5):
            if self.register():
                break
            log.warning("Registration attempt %d failed, retrying in 5s...", attempt + 1)
            time.sleep(5)
        else:
            log.error("Could not register with server after 5 attempts")
            return False

        self.running = True
        self._save_config()

        # Start file watchers
        self._start_observers()

        # Start background threads
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._batch_loop, daemon=True).start()
        threading.Thread(target=self._path_sync_loop, daemon=True).start()
        threading.Thread(target=self._restore_loop, daemon=True).start()
        threading.Thread(target=self._verify_loop, daemon=True).start()

        log.info("Agent running. Press Ctrl+C to stop.")
        return True

    def stop(self):
        log.info("Stopping agent...")
        self.running = False
        for obs in self.observers:
            try:
                obs.stop()
                obs.join(timeout=3)
            except Exception:
                pass
        self.observers.clear()
        self._save_config()
        log.info("Agent stopped.")


#  CLI 

def parse_args():
    parser = argparse.ArgumentParser(description="SecureFIM Pro Agent")
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help="Server URL (default: %(default)s)")
    parser.add_argument("--agent-id", default=None,
                        help="Unique agent ID (auto-generated if omitted)")
    parser.add_argument("--paths", nargs="+", default=[],
                        help="Directories to monitor")
    parser.add_argument("--no-recursive", action="store_true",
                        help="Disable recursive monitoring")
    parser.add_argument("--heartbeat", type=int, default=DEFAULT_HEARTBEAT,
                        help="Heartbeat interval in seconds")
    parser.add_argument("--batch-interval", type=int, default=DEFAULT_BATCH_INTERVAL,
                        help="Event batch send interval in seconds")
    parser.add_argument("--no-backup", action="store_true",
                        help="Disable automatic backup of sensitive files")
    parser.add_argument("--backup-dir", default=None,
                        help="Backup directory (default: ~/.securefim_backup)")
    return parser.parse_args()


def main():
    args = parse_args()

    agent_id = args.agent_id or generate_agent_id()
    paths = args.paths

    # If no paths given, try loading from config
    if not paths and os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            paths = cfg.get("monitored_paths", [])
            if cfg.get("agent_id"):
                agent_id = cfg["agent_id"]
        except Exception:
            pass

    if not paths:
        print("ERROR: No paths specified. Use --paths /dir1 /dir2 ...")
        print("       Or create agent_config.json with monitored_paths.")
        sys.exit(1)

    agent = FIMAgent(
        server_url=args.server,
        agent_id=agent_id,
        paths=paths,
        recursive=not args.no_recursive,
        heartbeat_interval=args.heartbeat,
        batch_interval=args.batch_interval,
        backup_enabled=not args.no_backup,
        backup_dir=args.backup_dir,
    )

    def shutdown(signum, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if not agent.start():
        sys.exit(1)

    try:
        while agent.running:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
