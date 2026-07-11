"""
SecureFIM Pro — Discord Alert System

Sends real-time alerts to Discord channels via bot token or user token.
Supports embeds with colour coding by severity, queued sending with rate limiting.

Configuration file: discord_config.json
{
    "enabled": true,
    "bot_token": "YOUR_TOKEN_HERE",
    "channels": { "alerts": "CHANNEL_ID" },
    "default_channel": "alerts",
    "token_type": "user",        // "user" or "bot"
    "alert_levels": {
        "CRITICAL": true, "WARNING": true, "INFO": false,
        "ANOMALY": true, "RANSOMWARE": true
    },
    "ping_on_critical": true
}
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests

log = logging.getLogger("securefim.discord")

DEFAULT_CONFIG_FILE = "discord_config.json"

SEVERITY_COLORS = {
    "critical":   0xFF0000,  # red
    "ransomware": 0x800080,  # purple
    "anomaly":    0xFFA500,  # orange
    "warning":    0xFFFF00,  # yellow
    "info":       0x00FF00,  # green
}


class DiscordAlerter:
    """Send alerts to Discord via bot/user token and channel API."""

    DISCORD_API = "https://discord.com/api/v9"

    def __init__(self, config_file: str = DEFAULT_CONFIG_FILE):
        self.config_file = config_file
        self.config = self._load_config()
        self.enabled = self.config.get("enabled", False)
        self.bot_token = self.config.get("bot_token", "")
        self.channels = self.config.get("channels", {})
        self.default_channel = self.config.get("default_channel", "alerts")
        self.token_type = self.config.get("token_type", "user")
        self.alert_levels = self.config.get("alert_levels", {
            "CRITICAL": True, "WARNING": True, "INFO": False,
            "ANOMALY": True, "RANSOMWARE": True,
        })
        self.ping_on_critical = self.config.get("ping_on_critical", True)

        self._rate_limit = 1.0  # min seconds between messages
        self._last_sent = 0.0
        self._queue: list[dict] = []
        self._lock = threading.Lock()

        if self.enabled and self.bot_token:
            self._worker = threading.Thread(target=self._process_queue, daemon=True)
            self._worker.start()
            log.info("Discord alerter started (token_type=%s, channel=%s)",
                     self.token_type, self.default_channel)
        else:
            log.info("Discord alerter disabled (enabled=%s, token=%s)",
                     self.enabled, bool(self.bot_token))

    # ── config ────────────────────────────────────────────────────────────

    def _load_config(self) -> dict:
        default = {
            "enabled": False,
            "bot_token": "",
            "channels": {},
            "default_channel": "alerts",
            "token_type": "user",
            "alert_levels": {
                "CRITICAL": True, "WARNING": True, "INFO": False,
                "ANOMALY": True, "RANSOMWARE": True,
            },
            "ping_on_critical": True,
        }
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file) as f:
                    cfg = json.load(f)
                for k, v in default.items():
                    cfg.setdefault(k, v)
                return cfg
        except Exception as exc:
            log.warning("Could not load Discord config: %s", exc)
        return default

    def save_config(self):
        try:
            with open(self.config_file, "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception as exc:
            log.error("Could not save Discord config: %s", exc)

    # ── public API ────────────────────────────────────────────────────────

    def send_alert(self, title: str, message: str,
                   severity: str = "info",
                   fields: Optional[dict] = None,
                   channel_name: Optional[str] = None):
        """Queue an alert for sending to Discord."""
        if not self.enabled or not self.bot_token:
            return

        sev_upper = severity.upper()
        if not self.alert_levels.get(sev_upper, True):
            return

        embed = self._build_embed(title, message, severity, fields)
        channel_id = self.channels.get(channel_name or self.default_channel)
        if not channel_id:
            log.warning("No channel ID for '%s'", channel_name or self.default_channel)
            return

        # Always include 'content' field — required by Discord API v9
        content_text = f"**{title}**"
        if self.ping_on_critical and sev_upper in ("CRITICAL", "RANSOMWARE"):
            content_text = f"⚠️ **CRITICAL ALERT** ⚠️ — {title}"

        payload = {
            "content": content_text[:2000],
            "embeds": [embed],
        }

        with self._lock:
            self._queue.append({"channel_id": channel_id, "payload": payload})

    def send_event_alert(self, event: dict):
        """Send a FIM event as a Discord alert."""
        etype = event.get("event_type", "UNKNOWN")
        severity = event.get("severity", "info")
        path = event.get("file_path", "unknown")
        agent = event.get("agent_id", "unknown")

        fields = {
            "Agent": agent,
            "Event Type": etype,
            "File": path,
        }
        if event.get("file_hash"):
            fields["Hash"] = event["file_hash"][:16] + "…"
        if event.get("file_size"):
            fields["Size"] = f"{event['file_size']:,} bytes"

        self.send_alert(
            title=f"File {etype}",
            message=f"`{path}`",
            severity=severity,
            fields=fields,
        )

    def send_anomaly_alert(self, anomaly: dict):
        """Send an anomaly detection result as a Discord alert."""
        self.send_alert(
            title="🚨 Anomaly Detected",
            message=anomaly.get("description", "Suspicious activity detected"),
            severity="anomaly",
            fields={
                "Agent": anomaly.get("agent_id", "unknown"),
                "Score": str(anomaly.get("anomaly_score", 0)),
                "Type": anomaly.get("anomaly_type", "ml_ocsvm"),
                "Related Events": str(anomaly.get("related_events", 0)),
            },
        )

    def send_ransomware_alert(self, alert: dict):
        """Send a ransomware detection alert."""
        self.send_alert(
            title=f"🔴 {alert.get('title', 'Ransomware Alert')}",
            message=alert.get("message", ""),
            severity="ransomware",
            fields={
                "File": alert.get("file_path", ""),
            },
        )

    # ── internals ─────────────────────────────────────────────────────────

    def _build_embed(self, title: str, description: str,
                     severity: str, fields: Optional[dict] = None) -> dict:
        color = SEVERITY_COLORS.get(severity.lower(), 0x808080)
        embed: dict = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": "SecureFIM Pro v4.0"},
        }
        if fields:
            embed["fields"] = [
                {"name": k, "value": str(v), "inline": True}
                for k, v in fields.items() if v
            ]
        return embed

    def _auth_header(self) -> dict:
        if self.token_type == "bot":
            return {"Authorization": f"Bot {self.bot_token}",
                    "Content-Type": "application/json"}
        else:
            return {"Authorization": self.bot_token,
                    "Content-Type": "application/json"}

    def _send_message(self, channel_id: str, payload: dict) -> bool:
        url = f"{self.DISCORD_API}/channels/{channel_id}/messages"
        try:
            resp = requests.post(url, json=payload,
                                 headers=self._auth_header(), timeout=10)
            if resp.status_code in (200, 201, 204):
                return True
            log.warning("Discord API %d: %s", resp.status_code, resp.text[:200])
            return False
        except Exception as exc:
            log.error("Discord send error: %s", exc)
            return False

    def _process_queue(self):
        """Background worker that sends queued messages with rate limiting."""
        while True:
            time.sleep(0.2)
            with self._lock:
                if not self._queue:
                    continue
                item = self._queue.pop(0)

            # Rate limit
            elapsed = time.time() - self._last_sent
            if elapsed < self._rate_limit:
                time.sleep(self._rate_limit - elapsed)

            self._send_message(item["channel_id"], item["payload"])
            self._last_sent = time.time()

    # ── status ────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "token_set": bool(self.bot_token),
            "token_type": self.token_type,
            "channels": list(self.channels.keys()),
            "default_channel": self.default_channel,
            "queue_size": len(self._queue),
        }
