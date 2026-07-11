"""
SecureFIM Pro — Email Alert System

Sends real-time email alerts for critical security events, reusing the
Gmail SMTP infrastructure already wired for OTP password reset.

Configuration files:
  data/email_config.json          — SMTP credentials (shared with OTP)
  data/email_alerts_config.json   — alert-specific settings (this module)
"""

import json
import logging
import os
import smtplib
import threading
import time
from collections import deque
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

log = logging.getLogger("securefim.email_alert")

SMTP_CONFIG_FILE = "data/email_config.json"
ALERTS_CONFIG_FILE = "data/email_alerts_config.json"

SEVERITY_COLORS = {
    "critical":   "#cf222e",
    "ransomware": "#800080",
    "anomaly":    "#d29922",
    "warning":    "#9a6700",
    "info":       "#1a7f37",
}

SEVERITY_RANK = {
    "info": 0, "low": 1, "warning": 2, "medium": 2,
    "high": 3, "anomaly": 3, "critical": 4, "ransomware": 5,
}


def _load_json(path: str) -> dict:
    try:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception as exc:
        log.warning("Could not load %s: %s", path, exc)
    return {}


def _save_json(path: str, data: dict):
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:
        log.error("Could not save %s: %s", path, exc)


class EmailAlerter:
    """Queue-based email alerter with throttling and type/severity filtering."""

    def __init__(self,
                 smtp_config_file: str = SMTP_CONFIG_FILE,
                 alerts_config_file: str = ALERTS_CONFIG_FILE):
        self.smtp_config_file = smtp_config_file
        self.alerts_config_file = alerts_config_file

        self.smtp = self._load_smtp_config()
        self.config = self._load_alerts_config()

        self._queue: list[dict] = []
        self._lock = threading.Lock()
        self._recent_sends: deque = deque(maxlen=200)
        self._worker: Optional[threading.Thread] = None
        self._stop = False

        if self.enabled and self._smtp_ready():
            self._worker = threading.Thread(target=self._process_queue, daemon=True)
            self._worker.start()
            log.info("Email alerter started (recipients=%d, throttle=%d/min)",
                     len(self.recipients), self.throttle_per_minute)
        else:
            log.info("Email alerter idle (enabled=%s, smtp_ready=%s, recipients=%d)",
                     self.enabled, self._smtp_ready(), len(self.recipients))

    # ── config ────────────────────────────────────────────────────────────

    def _load_smtp_config(self) -> dict:
        cfg = _load_json(self.smtp_config_file)
        cfg.setdefault("smtp_server", "smtp.gmail.com")
        cfg.setdefault("smtp_port", 587)
        cfg.setdefault("sender_email", "")
        cfg.setdefault("sender_password", "")
        return cfg

    def _load_alerts_config(self) -> dict:
        default = {
            "enabled": False,
            "recipients": [],
            "alert_types": {
                "ransomware": True,
                "critical_threat": True,
                "watchlist_match": True,
                "anomaly": False,
                "agent_offline": False,
                "restore_complete": False,
                "test": True,
            },
            "throttle_per_minute": 10,
            "min_severity": "critical",
        }
        cfg = _load_json(self.alerts_config_file)
        if not cfg:
            _save_json(self.alerts_config_file, default)
            return default
        for k, v in default.items():
            cfg.setdefault(k, v)
        for k, v in default["alert_types"].items():
            cfg["alert_types"].setdefault(k, v)
        return cfg

    def save_config(self):
        _save_json(self.alerts_config_file, self.config)

    # ── properties ────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return bool(self.config.get("enabled", False))

    @property
    def recipients(self) -> list[str]:
        return list(self.config.get("recipients", []))

    @property
    def alert_types(self) -> dict:
        return dict(self.config.get("alert_types", {}))

    @property
    def throttle_per_minute(self) -> int:
        return int(self.config.get("throttle_per_minute", 10))

    @property
    def min_severity(self) -> str:
        return str(self.config.get("min_severity", "critical")).lower()

    def _smtp_ready(self) -> bool:
        return bool(self.smtp.get("sender_email") and self.smtp.get("sender_password"))

    # ── public API ────────────────────────────────────────────────────────

    def send_alert(self, title: str, message: str,
                   severity: str = "info",
                   alert_type: str = "critical_threat",
                   fields: Optional[dict] = None) -> bool:
        if not self.enabled:
            return False
        if not self._smtp_ready():
            log.debug("SMTP not configured — dropping email alert")
            return False
        if not self.recipients:
            log.debug("No recipients configured — dropping email alert")
            return False

        if not self.alert_types.get(alert_type, False):
            log.debug("Alert type '%s' disabled — dropping", alert_type)
            return False

        sev_rank = SEVERITY_RANK.get(severity.lower(), 0)
        min_rank = SEVERITY_RANK.get(self.min_severity, 4)
        if sev_rank < min_rank:
            log.debug("Severity '%s' below min '%s' — dropping",
                      severity, self.min_severity)
            return False

        if not self._throttle_check():
            log.warning("Email throttle exceeded (%d/min) — dropping alert: %s",
                        self.throttle_per_minute, title)
            return False

        payload = {
            "title": title,
            "message": message,
            "severity": severity,
            "alert_type": alert_type,
            "fields": fields or {},
            "queued_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._queue.append(payload)
        return True

    def send_event_alert(self, event: dict):
        etype = event.get("event_type", "UNKNOWN")
        severity = event.get("severity", "info")
        path = event.get("file_path", "unknown")

        if event.get("watchlist_match"):
            at = "watchlist_match"
        elif event.get("threat_level") == "CRITICAL" or severity == "critical":
            at = "critical_threat"
        else:
            at = "critical_threat"

        fields = {
            "Agent": event.get("agent_id", "unknown"),
            "Username": event.get("username", "unknown"),
            "Event Type": etype,
            "File": path,
            "Sensitivity": event.get("sensitivity", ""),
            "Threat Score": event.get("threat_score", ""),
            "Outside Hours": "Yes" if event.get("outside_hours") else "No",
        }
        if event.get("mitre_tags"):
            fields["MITRE"] = ", ".join(event["mitre_tags"]) \
                if isinstance(event["mitre_tags"], list) else str(event["mitre_tags"])

        self.send_alert(
            title=f"File {etype} — {severity.upper()}",
            message=f"File integrity event detected: {path}",
            severity=severity,
            alert_type=at,
            fields=fields,
        )

    def send_ransomware_alert(self, alert: dict):
        self.send_alert(
            title=f"🔴 {alert.get('title', 'Ransomware Detected')}",
            message=alert.get("message", "Ransomware indicators detected."),
            severity="ransomware",
            alert_type="ransomware",
            fields={
                "File": alert.get("file_path", ""),
                "Agent": alert.get("agent_id", ""),
            },
        )

    def send_anomaly_alert(self, anomaly: dict):
        self.send_alert(
            title="🚨 Anomaly Detected",
            message=anomaly.get("description", "Suspicious activity detected"),
            severity="anomaly",
            alert_type="anomaly",
            fields={
                "Agent": anomaly.get("agent_id", "unknown"),
                "Score": str(anomaly.get("anomaly_score", 0)),
                "Type": anomaly.get("anomaly_type", "ml_ocsvm"),
                "Related Events": str(anomaly.get("related_events", 0)),
            },
        )

    def send_test_email(self, to: Optional[str] = None) -> tuple[bool, str]:
        if not self._smtp_ready():
            return False, "SMTP not configured (data/email_config.json missing sender_email/password)"
        recipient = to or (self.recipients[0] if self.recipients else None)
        if not recipient:
            return False, "No recipient supplied and no recipients configured"
        try:
            body = self._render_html(
                title="✅ SecureFIM Pro Email Alert Test",
                message="This is a test email from SecureFIM Pro. "
                        "If you received it, email alerts are working correctly.",
                severity="info",
                fields={
                    "Deployment": "District Administration Office, Bhaktapur, Nepal",
                    "Generated At": datetime.now(timezone.utc).isoformat(),
                    "Test": "Yes",
                },
            )
            self._smtp_send(recipient,
                            "[SecureFIM Pro] Email alert test",
                            body)
            return True, f"Test email sent to {recipient}"
        except Exception as exc:
            log.error("Test email failed: %s", exc)
            return False, f"Failed: {exc}"

    # ── throttling ────────────────────────────────────────────────────────

    def _throttle_check(self) -> bool:
        now = time.time()
        cutoff = now - 60.0
        while self._recent_sends and self._recent_sends[0] < cutoff:
            self._recent_sends.popleft()
        return len(self._recent_sends) < self.throttle_per_minute

    # ── worker ────────────────────────────────────────────────────────────

    def _process_queue(self):
        while not self._stop:
            time.sleep(0.5)
            item = None
            with self._lock:
                if self._queue:
                    item = self._queue.pop(0)
            if not item:
                continue
            try:
                subject = f"[SecureFIM Pro] {item['title']}"
                body = self._render_html(
                    item["title"], item["message"],
                    item["severity"], item["fields"],
                )
                for r in self.recipients:
                    try:
                        self._smtp_send(r, subject, body)
                        self._recent_sends.append(time.time())
                    except Exception as exc:
                        log.error("Failed to send email to %s: %s", r, exc)
            except Exception as exc:
                log.error("Email worker error: %s", exc)

    # ── SMTP ──────────────────────────────────────────────────────────────

    def _smtp_send(self, recipient: str, subject: str, html_body: str):
        msg = MIMEMultipart("alternative")
        msg["From"] = self.smtp["sender_email"]
        msg["To"] = recipient
        msg["Subject"] = subject
        import re
        plain = re.sub(r"<[^>]+>", "", html_body)
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(self.smtp["smtp_server"],
                          int(self.smtp["smtp_port"]), timeout=20) as sv:
            sv.starttls()
            sv.login(self.smtp["sender_email"], self.smtp["sender_password"])
            sv.sendmail(self.smtp["sender_email"], recipient, msg.as_string())

    # ── HTML rendering ────────────────────────────────────────────────────

    def _render_html(self, title: str, message: str,
                     severity: str, fields: dict) -> str:
        color = SEVERITY_COLORS.get(severity.lower(), "#656d76")
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        rows = ""
        for k, v in (fields or {}).items():
            if v in (None, ""):
                continue
            rows += (
                f'<tr><td style="padding:6px 10px;border-bottom:1px solid #e0e0e0;'
                f'font-weight:600;color:#444;width:140px">{_esc(str(k))}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #e0e0e0;'
                f'color:#222;font-family:monospace;font-size:12px">{_esc(str(v))}</td></tr>'
            )
        return f"""\
<html><body style="margin:0;padding:20px;background:#f6f8fa;font-family:-apple-system,Segoe UI,sans-serif;color:#222">
  <div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #d0d7de;border-radius:8px;overflow:hidden">
    <div style="background:{color};color:#fff;padding:14px 20px;font-size:18px;font-weight:600">
      🛡️ SecureFIM Pro — {_esc(severity.upper())}
    </div>
    <div style="padding:20px">
      <h2 style="margin:0 0 10px;font-size:18px;color:#1f2328">{_esc(title)}</h2>
      <p style="margin:0 0 16px;color:#444;line-height:1.5">{_esc(message)}</p>
      <table style="width:100%;border-collapse:collapse;border:1px solid #e0e0e0;border-radius:6px">
        {rows}
      </table>
      <p style="margin:18px 0 0;font-size:12px;color:#888">
        Sent {_esc(ts)} · District Administration Office, Bhaktapur, Nepal<br>
        This is an automated alert from SecureFIM Pro. Do not reply to this email.
      </p>
    </div>
  </div>
</body></html>"""

    # ── status ────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "smtp_ready": self._smtp_ready(),
            "sender_email": self.smtp.get("sender_email", ""),
            "recipients": self.recipients,
            "alert_types": self.alert_types,
            "throttle_per_minute": self.throttle_per_minute,
            "min_severity": self.min_severity,
            "queue_size": len(self._queue),
            "recent_sends_last_minute": len([t for t in self._recent_sends
                                              if t > time.time() - 60]),
        }


def _esc(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
