"""
SecureFIM Pro — REST API Routes
Handles agent registration, event ingestion, path management,
anomaly results, and dashboard data endpoints.
"""

import logging
import time
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify

from server.config import IDX_EVENTS, IDX_AGENTS, IDX_ANOMALIES, IDX_ALERTS, IDX_HEARTBEATS, AGENT_OFFLINE_THRESHOLD, CORROBORATIVE_SCORING

log = logging.getLogger("securefim.api")

api_bp = Blueprint("api", __name__, url_prefix="/api")

# These are set by main.py after app creation
os_client = None   # type: ignore
ml_detector = None  # type: ignore
socketio_ref = None  # type: ignore
ransomware_detector = None  # type: ignore
discord_alerter = None  # type: ignore
email_alerter = None  # type: ignore
scheduler_ref = None  # type: ignore


def init_api(opensearch_client, anomaly_detector, socketio_instance,
             ransomware_det=None, discord_alert=None, email_alert=None,
             scheduler=None):
    global os_client, ml_detector, socketio_ref, ransomware_detector, discord_alerter, email_alerter, scheduler_ref
    os_client = opensearch_client
    ml_detector = anomaly_detector
    socketio_ref = socketio_instance
    ransomware_detector = ransomware_det
    discord_alerter = discord_alert
    email_alerter = email_alert
    scheduler_ref = scheduler


# ── Health ────────────────────────────────────────────────────────────────

@api_bp.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


# ── Agent Registration ───────────────────────────────────────────────────

@api_bp.route("/agents/register", methods=["POST"])
def register_agent():
    data = request.get_json(force=True)
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id required"}), 400

    now = datetime.now(timezone.utc).isoformat()
    agent_doc = {
        "agent_id": agent_id,
        "hostname": data.get("hostname", "unknown"),
        "os_type": data.get("os_type", "unknown"),
        "os_version": data.get("os_version", ""),
        "agent_version": data.get("agent_version", ""),
        "ip_address": request.remote_addr or "0.0.0.0",
        "monitored_paths": data.get("monitored_paths", []),
        "status": "online",
        "registered_at": now,
        "last_heartbeat": now,
        "event_count": 0,
        "metadata": data.get("metadata", {}),
    }
    os_client.upsert_agent(agent_id, agent_doc)
    log.info("Agent registered: %s (%s)", agent_id, agent_doc["hostname"])

    if socketio_ref:
        socketio_ref.emit("agent_update", {"action": "registered", "agent": agent_doc})

    return jsonify({"status": "registered", "agent_id": agent_id})


# ── Agent Path Management ────────────────────────────────────────────────

@api_bp.route("/agents/<agent_id>/paths", methods=["GET"])
def get_agent_paths(agent_id):
    agent = os_client.get_agent(agent_id)
    if not agent:
        return jsonify({"error": "agent not found"}), 404
    return jsonify({"agent_id": agent_id, "monitored_paths": agent.get("monitored_paths", [])})


@api_bp.route("/agents/<agent_id>/paths", methods=["PUT", "POST"])
def update_agent_paths(agent_id):
    data = request.get_json(force=True)
    paths = data.get("monitored_paths", [])
    if not isinstance(paths, list):
        return jsonify({"error": "monitored_paths must be a list"}), 400

    ok = os_client.update_doc(IDX_AGENTS, agent_id, {"monitored_paths": paths})
    if not ok:
        return jsonify({"error": "agent not found or update failed"}), 404

    log.info("Updated paths for agent %s: %s", agent_id, paths)
    if socketio_ref:
        socketio_ref.emit("agent_update", {"action": "paths_updated", "agent_id": agent_id, "paths": paths})

    return jsonify({"status": "updated", "monitored_paths": paths})


# ── Heartbeat ─────────────────────────────────────────────────────────────

@api_bp.route("/agents/<agent_id>/heartbeat", methods=["POST"])
def agent_heartbeat(agent_id):
    data = request.get_json(force=True)
    now = datetime.now(timezone.utc).isoformat()

    hb_doc = {
        "agent_id": agent_id,
        "cpu_percent": data.get("cpu_percent", 0),
        "memory_percent": data.get("memory_percent", 0),
        "disk_percent": data.get("disk_percent", 0),
        "event_count": data.get("event_count", 0),
        "uptime": data.get("uptime", 0),
        "timestamp": now,
    }
    os_client.index_doc(IDX_HEARTBEATS, hb_doc)
    os_client.update_doc(IDX_AGENTS, agent_id, {
        "last_heartbeat": now,
        "status": "online",
        "event_count": data.get("event_count", 0),
    })
    return jsonify({"status": "ok"})


# ── Event Ingestion ──────────────────────────────────────────────────────

@api_bp.route("/events", methods=["POST"])
def ingest_events():
    data = request.get_json(force=True)
    events = data if isinstance(data, list) else [data]

    indexed = 0
    anomalies_found = 0
    ransomware_found = 0

    # ── ML anomaly verdict for the batch, computed FIRST ──────────────────
    # The One-Class SVM operates on a WINDOW of events, not a single event, so
    # its verdict must be obtained before individual events are scored. This
    # verdict is then fed into calculate_threat_score for every event in the
    # batch, which is what allows the classifier to corroborate — or veto — a
    # volumetric ransomware rule. (Previously the ML ran after the loop and its
    # verdict never reached the threat score at all.)
    batch_is_anomaly = False
    batch_ml_score = 0.0
    ml_result = None
    if ml_detector and events:
        try:
            ml_result = ml_detector.predict(events)
            batch_is_anomaly = bool(ml_result.get("is_anomaly", False))
            batch_ml_score = float(ml_result.get("score", 0.0))
        except Exception as exc:
            log.error("ML prediction error: %s", exc)

    for event in events:
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Default severity
        etype = (event.get("event_type") or "UNKNOWN").upper()
        if "severity" not in event:
            if etype == "DELETED":
                event["severity"] = "warning"
            elif etype in ("MODIFIED", "MOVED"):
                event["severity"] = "info"
            else:
                event["severity"] = "info"

        event["is_anomaly"] = batch_is_anomaly
        event["anomaly_score"] = batch_ml_score

        # ── Ransomware detection (per-event) ──────────────────────────────
        rw_alert = None
        rw_is_volumetric = False
        if ransomware_detector:
            try:
                rw_alert = ransomware_detector.record_event(
                    etype,
                    event.get("file_path", ""),
                    event.get("dest_path", ""),
                )
                if rw_alert:
                    from server.features import is_volumetric_alert
                    rw_is_volumetric = is_volumetric_alert(rw_alert)

                    # A volumetric rule that the anomaly detector does not
                    # corroborate is suppressed: no alert, no severity bump.
                    # Bulk import of scanned records is the case this exists for.
                    if rw_is_volumetric and not batch_is_anomaly:
                        log.info(
                            "Volumetric ransomware rule suppressed (SVM says "
                            "normal): %s", rw_alert.get("title", "")
                        )
                        rw_alert = None

                if rw_alert:
                    ransomware_found += 1
                    event["severity"] = "critical"

                    alert_doc = {
                        "agent_id": event.get("agent_id", "unknown"),
                        "alert_type": "ransomware",
                        "severity": "critical",
                        "title": rw_alert.get("title", "Ransomware Alert"),
                        "message": rw_alert.get("message", ""),
                        "acknowledged": False,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    os_client.index_doc(IDX_ALERTS, alert_doc)

                    if socketio_ref:
                        socketio_ref.emit("new_alert", alert_doc)

                    # Discord alert for ransomware
                    if discord_alerter:
                        discord_alerter.send_ransomware_alert(rw_alert)
                    # Email alert for ransomware
                    if email_alerter:
                        try:
                            email_alerter.send_ransomware_alert(rw_alert)
                        except Exception as exc:
                            log.error("Email ransomware alert error: %s", exc)
            except Exception as exc:
                log.error("Ransomware detection error: %s", exc)

        # ── Threat enrichment ─────────────────────────────────────────────
        try:
            from server.features import classify_sensitivity, calculate_threat_score, get_mitre_tags, WorkingHoursDetector
            from server.config import BUSINESS_HOURS_START, BUSINESS_HOURS_END, BUSINESS_DAYS

            # Ensure hours detector is available
            try:
                hours_det = _hours_detector
            except NameError:
                hours_det = WorkingHoursDetector(BUSINESS_HOURS_START, BUSINESS_HOURS_END, BUSINESS_DAYS)

            event["sensitivity"] = classify_sensitivity(event.get("file_path", ""))
            hours_check = hours_det.is_outside_hours(event.get("timestamp"))
            event["outside_hours"] = hours_check.get("outside_hours", False)
            event["hours_reason"] = hours_check.get("reason", "")

            # rw_alert is None if it was suppressed by the corroborative gate.
            is_rw = rw_alert is not None
            threat = calculate_threat_score(
                event,
                ml_score=batch_ml_score,
                is_ransomware=is_rw,
                is_anomaly=batch_is_anomaly,
                outside_hours=event.get("outside_hours", False),
                sensitivity=event.get("sensitivity", "LOW"),
                ransomware_volumetric=rw_is_volumetric,
                corroborative=CORROBORATIVE_SCORING,
            )
            event["threat_score"] = threat["score"]
            event["threat_level"] = threat["level"]
            event["mitre_tags"] = [t["id"] for t in threat.get("mitre_tags", [])]
            event["threat_reasons"] = threat.get("reasons", [])

            # Upgrade severity based on threat score
            if threat["score"] >= 70 and event["severity"] != "critical":
                event["severity"] = "critical"
            elif threat["score"] >= 40 and event["severity"] == "info":
                event["severity"] = "warning"

            # Check watchlist
            watchlist_items = os_client.search(IDX_WATCHLIST, {"query": {"match_all": {}}}, size=200)
            for wl in watchlist_items:
                wl_path = (wl.get("file_path") or "").lower()
                if wl_path and wl_path in event.get("file_path", "").lower():
                    event["sensitivity"] = wl.get("sensitivity", "HIGH")
                    event["severity"] = "critical"
                    event["watchlist_match"] = True
                    if wl.get("auto_alert") and discord_alerter:
                        discord_alerter.send_alert(
                            title="⚠️ Watchlist File Triggered",
                            message=f"Watched file changed: {event.get('file_path', '')}",
                            severity="critical",
                            fields={"Sensitivity": event["sensitivity"], "Event": etype},
                        )
                    if wl.get("auto_alert") and email_alerter:
                        try:
                            email_alerter.send_alert(
                                title="⚠️ Watchlist File Triggered",
                                message=f"Watched file changed: {event.get('file_path', '')}",
                                severity="critical",
                                alert_type="watchlist_match",
                                fields={
                                    "Sensitivity": event["sensitivity"],
                                    "Event Type": etype,
                                    "Agent": event.get("agent_id", ""),
                                    "User": event.get("username", ""),
                                    "File": event.get("file_path", ""),
                                },
                            )
                        except Exception as exc:
                            log.error("Email watchlist alert error: %s", exc)
                    break
        except Exception as exc:
            log.debug("Threat enrichment error: %s", exc)

        doc_id = os_client.index_doc(IDX_EVENTS, event)
        if doc_id:
            indexed += 1

        if socketio_ref:
            socketio_ref.emit("new_event", event)

        # Send to Discord
        if discord_alerter:
            try:
                discord_alerter.send_event_alert(event)
            except Exception as exc:
                log.error("Discord event alert error: %s", exc)

        # Send to Email (filtered by alert_types + min_severity in the alerter)
        if email_alerter:
            try:
                email_alerter.send_event_alert(event)
            except Exception as exc:
                log.error("Email event alert error: %s", exc)

    # ── ML anomaly recording (verdict already computed above) ─────────────
    if ml_detector and events and ml_result is not None:
        try:
            result = ml_result
            if result["is_anomaly"]:
                anomalies_found += 1
                anomaly_doc = {
                    "agent_id": events[0].get("agent_id", "unknown"),
                    "anomaly_type": "ml_ocsvm",
                    "anomaly_score": result["score"],
                    "severity": "critical" if result["score"] < -0.5 else "warning",
                    "description": result["description"],
                    "related_events": len(events),
                    "feature_vector": list(result["features"].values()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                os_client.index_doc(IDX_ANOMALIES, anomaly_doc)

                alert_doc = {
                    "agent_id": events[0].get("agent_id", "unknown"),
                    "alert_type": "anomaly",
                    "severity": anomaly_doc["severity"],
                    "title": "Anomaly Detected (One-Class SVM)" if ml_detector.is_trained else "Anomaly Detected (Rule-based)",
                    "message": result["description"],
                    "acknowledged": False,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                os_client.index_doc(IDX_ALERTS, alert_doc)

                if socketio_ref:
                    socketio_ref.emit("anomaly_detected", anomaly_doc)
                    socketio_ref.emit("new_alert", alert_doc)

                # Discord alert for anomaly
                if discord_alerter:
                    discord_alerter.send_anomaly_alert(anomaly_doc)
                if email_alerter:
                    try:
                        email_alerter.send_anomaly_alert(anomaly_doc)
                    except Exception as exc:
                        log.error("Email anomaly alert error: %s", exc)

            # Collect training data from normal windows
            if not result["is_anomaly"]:
                ml_detector.add_training_sample(events)
                ml_detector.maybe_retrain()

        except Exception as exc:
            log.error("ML prediction error: %s", exc)

    return jsonify({"indexed": indexed, "anomalies": anomalies_found, "ransomware": ransomware_found})


# ── Event Queries ─────────────────────────────────────────────────────────

@api_bp.route("/events/recent")
def recent_events():
    limit = request.args.get("limit", 50, type=int)
    agent_id = request.args.get("agent_id")
    events = os_client.get_recent_events(limit=limit, agent_id=agent_id)
    return jsonify({"events": events, "total": len(events)})


@api_bp.route("/events/stats")
def event_stats():
    minutes = request.args.get("minutes", 60, type=int)
    stats = os_client.get_event_stats(minutes=minutes)
    return jsonify(stats)


# ── Agents ────────────────────────────────────────────────────────────────

@api_bp.route("/agents")
def list_agents():
    agents = os_client.get_agents()
    # Mark agents as offline if no recent heartbeat
    now_ts = time.time()
    for a in agents:
        hb = a.get("last_heartbeat")
        if hb:
            try:
                hb_ts = datetime.fromisoformat(hb.replace("Z", "+00:00")).timestamp()
                if now_ts - hb_ts > AGENT_OFFLINE_THRESHOLD:
                    a["status"] = "offline"
            except Exception:
                pass
    return jsonify({"agents": agents})


@api_bp.route("/agents/<agent_id>")
def get_agent_detail(agent_id):
    agent = os_client.get_agent(agent_id)
    if not agent:
        return jsonify({"error": "not found"}), 404
    return jsonify(agent)


# ── Anomalies ─────────────────────────────────────────────────────────────

@api_bp.route("/anomalies")
def list_anomalies():
    limit = request.args.get("limit", 20, type=int)
    anomalies = os_client.get_recent_anomalies(limit=limit)
    return jsonify({"anomalies": anomalies})


# ── Alerts ────────────────────────────────────────────────────────────────

@api_bp.route("/alerts")
def list_alerts():
    limit = request.args.get("limit", 30, type=int)
    alerts = os_client.get_recent_alerts(limit=limit)
    return jsonify({"alerts": alerts})


@api_bp.route("/alerts/<alert_id>/acknowledge", methods=["POST"])
def acknowledge_alert(alert_id):
    ok = os_client.update_doc(IDX_ALERTS, alert_id, {"acknowledged": True})
    return jsonify({"status": "acknowledged" if ok else "failed"})


# ── ML Status ─────────────────────────────────────────────────────────────

@api_bp.route("/ml/status")
def ml_status():
    if ml_detector:
        return jsonify(ml_detector.status())
    return jsonify({"error": "ML not initialized"}), 500


@api_bp.route("/ml/train", methods=["POST"])
def ml_train():
    if not ml_detector:
        return jsonify({"error": "ML not initialized"}), 500
    if not ml_detector.can_train():
        return jsonify({
            "error": "Not enough training data",
            "samples": len(ml_detector.training_data),
            "required": ml_detector.training_data and len(ml_detector.training_data) or 0,
        }), 400
    success = ml_detector.train()
    return jsonify({"status": "trained" if success else "failed"})


# ── Dashboard Summary ────────────────────────────────────────────────────

@api_bp.route("/dashboard/summary")
def dashboard_summary():
    stats = os_client.get_event_stats(minutes=60)
    agents = os_client.get_agents()
    anomalies = os_client.get_recent_anomalies(limit=5)
    alerts = os_client.get_recent_alerts(limit=10)
    recent = os_client.get_recent_events(limit=15)

    now_ts = time.time()
    online = 0
    offline = 0
    for a in agents:
        hb = a.get("last_heartbeat")
        if hb:
            try:
                hb_ts = datetime.fromisoformat(hb.replace("Z", "+00:00")).timestamp()
                if now_ts - hb_ts <= AGENT_OFFLINE_THRESHOLD:
                    online += 1
                else:
                    offline += 1
            except Exception:
                offline += 1
        else:
            offline += 1

    all_paths = []
    for a in agents:
        for p in a.get("monitored_paths", []):
            all_paths.append({"agent_id": a.get("agent_id"), "path": p})

    ml_info = ml_detector.status() if ml_detector else {}
    rw_info = ransomware_detector.status() if ransomware_detector else {}
    discord_info = discord_alerter.status() if discord_alerter else {}

    return jsonify({
        "event_stats": stats,
        "agents_online": online,
        "agents_offline": offline,
        "agents_total": len(agents),
        "agents": agents,
        "monitored_paths": all_paths,
        "recent_anomalies": anomalies,
        "recent_alerts": alerts,
        "recent_events": recent,
        "ml_status": ml_info,
        "ransomware_status": rw_info,
        "discord_status": discord_info,
    })


# ── Admin Endpoints ──────────────────────────────────────────────────────

from server.auth import (hash_password as _hash_password, verify_password,
                         authenticate, load_users as _load_admin_users,
                         save_users as _save_admin_users, issue_token,
                         require_admin, guard_blueprint)

# Load on startup (shared, salted store)
ADMIN_USERS = _load_admin_users()

# Guard ONLY the /api/admin/* routes with token auth.
# Agent and dashboard endpoints (/api/agents/register, /api/events, /api/health,
# …) are deliberately left open: agents authenticate at the network layer in
# this deployment, and changing that is out of scope for this fix.
api_bp.before_request(guard_blueprint(
    (
        "/admin/login", "/admin/forgot-password",
        "/admin/verify-otp", "/admin/reset-password",
    ),
    protected_contains="/admin/",
))


@api_bp.route("/admin/login", methods=["POST"])
def admin_login():
    """Authenticate admin user."""
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if authenticate(ADMIN_USERS, username, password):
        log.info("Admin login successful: %s", username)
        return jsonify({"status": "ok", "username": username, "token": issue_token(username)})
    else:
        log.warning("Admin login failed: %s", username)
        return jsonify({"status": "failed", "error": "Invalid username or password"}), 401


# OTP storage: {username: {"otp": "123456", "expires": timestamp, "email": "..."}}
_otp_store = {}


@api_bp.route("/admin/forgot-password", methods=["POST"])
def admin_forgot_password():
    """Send OTP to admin's email for password reset."""
    import smtplib
    import random
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()

    if not username or not email:
        return jsonify({"error": "Username and email required"}), 400

    if username not in ADMIN_USERS:
        return jsonify({"error": "Username not found"}), 404

    # Generate 6-digit OTP
    otp = str(random.randint(100000, 999999))
    expires = time.time() + 180  # 3 minutes

    _otp_store[username] = {"otp": otp, "expires": expires, "email": email}

    # Try to send email
    try:
        # Load email config
        import json as _json
        email_config_file = "data/email_config.json"
        email_cfg = {}
        import os as _os
        if _os.path.exists(email_config_file):
            with open(email_config_file) as f:
                email_cfg = _json.load(f)

        smtp_server = email_cfg.get("smtp_server", "smtp.gmail.com")
        smtp_port = email_cfg.get("smtp_port", 587)
        sender_email = email_cfg.get("sender_email", "")
        sender_password = email_cfg.get("sender_password", "")

        if not sender_email or not sender_password:
            # No email config — log OTP to console for testing
            log.warning("No email configured. OTP for %s: %s (expires in 3 min)", username, otp)
            return jsonify({"status": "ok", "message": "OTP sent (check server console if no email configured)"})

        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = email
        msg["Subject"] = "SecureFIM Pro - Password Reset OTP"

        body = f"""
SecureFIM Pro - Password Reset

Your OTP code is: {otp}

This code is valid for 3 minutes.
If you did not request this, please ignore this email.

— SecureFIM Pro Security System
"""
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())

        log.info("OTP sent to %s for user %s", email, username)
        return jsonify({"status": "ok", "message": "OTP sent to your email"})

    except Exception as exc:
        log.error("Email send failed: %s. OTP for %s: %s", exc, username, otp)
        return jsonify({"status": "ok", "message": "OTP generated (check server console if email failed)"})


@api_bp.route("/admin/verify-otp", methods=["POST"])
def admin_verify_otp():
    """Verify the OTP code."""
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    otp = data.get("otp", "").strip()

    if not username or not otp:
        return jsonify({"error": "Username and OTP required"}), 400

    stored = _otp_store.get(username)
    if not stored:
        return jsonify({"error": "No OTP requested for this user"}), 400

    if time.time() > stored["expires"]:
        del _otp_store[username]
        return jsonify({"error": "OTP expired. Please request a new one."}), 400

    if stored["otp"] != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    # OTP valid — mark as verified
    stored["verified"] = True
    log.info("OTP verified for user %s", username)
    return jsonify({"status": "ok"})


@api_bp.route("/admin/reset-password", methods=["POST"])
def admin_reset_password():
    """Reset password after OTP verification."""
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    new_password = data.get("new_password", "")

    if not username or not new_password:
        return jsonify({"error": "Username and new password required"}), 400

    if len(new_password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    stored = _otp_store.get(username)
    if not stored or not stored.get("verified"):
        return jsonify({"error": "OTP not verified. Please verify OTP first."}), 400

    if username not in ADMIN_USERS:
        return jsonify({"error": "User not found"}), 404

    ADMIN_USERS[username] = _hash_password(new_password)
    _save_admin_users(ADMIN_USERS)
    del _otp_store[username]

    log.info("Password reset for user %s via OTP", username)
    return jsonify({"status": "ok", "message": "Password reset successfully"})


@api_bp.route("/admin/change-password", methods=["POST"])
def admin_change_password():
    """Change admin password. Requires current credentials."""
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not username or not current_password or not new_password:
        return jsonify({"error": "All fields are required"}), 400

    if len(new_password) < 4:
        return jsonify({"error": "New password must be at least 4 characters"}), 400

    if not authenticate(ADMIN_USERS, username, current_password):
        return jsonify({"error": "Current credentials are incorrect"}), 401

    ADMIN_USERS[username] = _hash_password(new_password)
    _save_admin_users(ADMIN_USERS)
    log.info("Password changed for admin user: %s", username)
    return jsonify({"status": "ok", "message": f"Password changed for {username}"})


@api_bp.route("/admin/add-user", methods=["POST"])
def admin_add_user():
    """Add a new admin user. Requires existing admin credentials."""
    data = request.get_json(force=True)
    auth_user = data.get("auth_username", "").strip()
    auth_pass = data.get("auth_password", "")
    new_user = data.get("new_username", "").strip()
    new_pass = data.get("new_password", "")

    if not all([auth_user, auth_pass, new_user, new_pass]):
        return jsonify({"error": "All fields are required"}), 400

    # Verify requesting admin
    if not authenticate(ADMIN_USERS, auth_user, auth_pass):
        return jsonify({"error": "Admin authentication failed"}), 401

    if new_user in ADMIN_USERS:
        return jsonify({"error": f"User '{new_user}' already exists"}), 400

    if len(new_pass) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    ADMIN_USERS[new_user] = _hash_password(new_pass)
    _save_admin_users(ADMIN_USERS)
    log.info("New admin user created: %s (by %s)", new_user, auth_user)
    return jsonify({"status": "ok", "message": f"User '{new_user}' created"})


@api_bp.route("/admin/remove-user", methods=["POST"])
def admin_remove_user():
    """Remove an admin user."""
    data = request.get_json(force=True)
    auth_user = data.get("auth_username", "").strip()
    auth_pass = data.get("auth_password", "")
    remove_user = data.get("remove_username", "").strip()

    if not all([auth_user, auth_pass, remove_user]):
        return jsonify({"error": "All fields are required"}), 400

    if not authenticate(ADMIN_USERS, auth_user, auth_pass):
        return jsonify({"error": "Admin authentication failed"}), 401

    if remove_user == auth_user:
        return jsonify({"error": "Cannot remove yourself"}), 400

    if remove_user not in ADMIN_USERS:
        return jsonify({"error": f"User '{remove_user}' not found"}), 404

    if len(ADMIN_USERS) <= 1:
        return jsonify({"error": "Cannot remove the last admin user"}), 400

    del ADMIN_USERS[remove_user]
    _save_admin_users(ADMIN_USERS)
    log.info("Admin user removed: %s (by %s)", remove_user, auth_user)
    return jsonify({"status": "ok", "message": f"User '{remove_user}' removed"})


@api_bp.route("/admin/list-users")
def admin_list_users():
    """List admin usernames (no passwords)."""
    return jsonify({"users": list(ADMIN_USERS.keys())})

@api_bp.route("/admin/system-health")
def admin_system_health():
    """Get comprehensive system health info."""
    import psutil
    import os as _os

    # OpenSearch index stats
    index_stats = {}
    for idx_name in [IDX_EVENTS, IDX_AGENTS, IDX_ANOMALIES, IDX_ALERTS, IDX_HEARTBEATS]:
        try:
            count = os_client.count(idx_name)
            index_stats[idx_name] = {"doc_count": count}
        except Exception:
            index_stats[idx_name] = {"doc_count": 0, "error": True}

    # Server resource usage
    process = psutil.Process()
    server_info = {
        "cpu_percent": psutil.cpu_percent(interval=0),
        "memory_percent": psutil.virtual_memory().percent,
        "memory_used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
        "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "disk_percent": psutil.disk_usage("/").percent if _os.name != "nt" else psutil.disk_usage("C:\\").percent,
        "disk_used_gb": round((psutil.disk_usage("/") if _os.name != "nt" else psutil.disk_usage("C:\\")).used / (1024**3), 2),
        "disk_total_gb": round((psutil.disk_usage("/") if _os.name != "nt" else psutil.disk_usage("C:\\")).total / (1024**3), 2),
        "server_pid": _os.getpid(),
        "server_memory_mb": round(process.memory_info().rss / (1024**2), 1),
        "server_cpu_percent": process.cpu_percent(interval=0),
        "python_version": _os.sys.version.split()[0] if hasattr(_os, "sys") else "unknown",
        "uptime_seconds": int(time.time() - process.create_time()),
    }

    # OpenSearch cluster health
    os_health = {}
    try:
        os_health = os_client.client.cluster.health()
    except Exception as exc:
        os_health = {"status": "error", "error": str(exc)}

    return jsonify({
        "server": server_info,
        "opensearch": os_health,
        "indices": index_stats,
    })


@api_bp.route("/admin/agent-health")
def admin_agent_health():
    """Get detailed agent health including recent heartbeats."""
    agents = os_client.get_agents()
    result = []
    for a in agents:
        agent_id = a.get("agent_id", "")
        # Get latest heartbeats
        heartbeats = os_client.search(IDX_HEARTBEATS, {
            "query": {"term": {"agent_id": agent_id}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }, size=5)
        a["recent_heartbeats"] = heartbeats
        result.append(a)
    return jsonify({"agents": result})


@api_bp.route("/admin/alerts/acknowledge-all", methods=["POST"])
def acknowledge_all_alerts():
    """Acknowledge all unacknowledged alerts."""
    body = {"query": {"term": {"acknowledged": False}}}
    try:
        os_client.client.update_by_query(index=IDX_ALERTS, body={
            "query": {"term": {"acknowledged": False}},
            "script": {"source": "ctx._source.acknowledged = true"}
        }, refresh=True)
        return jsonify({"status": "ok", "message": "All alerts acknowledged"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/admin/clear/<index_name>", methods=["DELETE"])
def admin_clear_index(index_name):
    """Clear a specific index."""
    valid = {IDX_EVENTS, IDX_ANOMALIES, IDX_ALERTS, IDX_HEARTBEATS}
    if index_name not in valid:
        return jsonify({"error": f"Cannot clear {index_name}"}), 400
    deleted = os_client.delete_by_query(index_name, {"query": {"match_all": {}}})
    return jsonify({"status": "ok", "deleted": deleted, "index": index_name})


@api_bp.route("/admin/ml/reset", methods=["POST"])
def admin_ml_reset():
    """Reset the ML model."""
    if not ml_detector:
        return jsonify({"error": "ML not initialized"}), 500
    import os as _os
    try:
        ml_detector.model = None
        ml_detector.scaler = None
        ml_detector.is_trained = False
        ml_detector.training_data.clear()
        # Remove model files
        model_dir = ml_detector._save_model.__code__.co_filename  # hack to get dir
        for f in ["models/ocsvm_model.joblib", "models/ocsvm_scaler.joblib"]:
            if _os.path.exists(f):
                _os.remove(f)
        return jsonify({"status": "ok", "message": "ML model reset"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/admin/discord/test", methods=["POST"])
def admin_discord_test():
    """Send a test message to Discord."""
    if not discord_alerter or not discord_alerter.enabled:
        return jsonify({"error": "Discord not enabled"}), 400
    try:
        discord_alerter.send_alert(
            title="🧪 Test Alert",
            message="This is a test alert from SecureFIM Pro Admin Panel.",
            severity="info",
        )
        return jsonify({"status": "ok", "message": "Test alert queued"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/admin/export/events")
def admin_export_events():
    """Export events as JSON."""
    limit = request.args.get("limit", 1000, type=int)
    events = os_client.get_recent_events(limit=limit)
    return jsonify({"events": events, "exported": len(events)})

# ── Advanced Features API ─────────────────────────────────────────────────

from server.config import IDX_BASELINES, IDX_WATCHLIST, BUSINESS_HOURS_START, BUSINESS_HOURS_END, BUSINESS_DAYS
from server.features import (
    WorkingHoursDetector, classify_sensitivity, get_mitre_tags,
    calculate_threat_score, apply_retention, create_baseline_entry,
    MITRE_TECHNIQUES,
)

_hours_detector = WorkingHoursDetector(BUSINESS_HOURS_START, BUSINESS_HOURS_END, BUSINESS_DAYS)


# ── Watchlist ─────────────────────────────────────────────────────────────

@api_bp.route("/watchlist", methods=["GET"])
def get_watchlist():
    items = os_client.search(IDX_WATCHLIST, {"query": {"match_all": {}}, "sort": [{"timestamp": {"order": "desc"}}]}, size=200)
    return jsonify({"items": items})


@api_bp.route("/watchlist", methods=["POST"])
def add_to_watchlist():
    data = request.get_json(force=True)
    doc = {
        "file_path": data.get("file_path", ""),
        "sensitivity": data.get("sensitivity", "HIGH"),
        "description": data.get("description", ""),
        "added_by": data.get("added_by", "admin"),
        "mitre_tags": data.get("mitre_tags", []),
        "auto_alert": data.get("auto_alert", True),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    doc_id = os_client.index_doc(IDX_WATCHLIST, doc)
    return jsonify({"status": "added", "id": doc_id})


@api_bp.route("/watchlist/<item_id>", methods=["DELETE"])
def remove_from_watchlist(item_id):
    try:
        os_client.client.delete(index=IDX_WATCHLIST, id=item_id, refresh="wait_for")
        return jsonify({"status": "removed"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Baselines ─────────────────────────────────────────────────────────────

@api_bp.route("/baselines", methods=["GET"])
def get_baselines():
    name = request.args.get("name")
    query = {"term": {"baseline_name": name}} if name else {"match_all": {}}
    items = os_client.search(IDX_BASELINES, {"query": query, "sort": [{"file_path.raw": {"order": "asc"}}]}, size=1000)
    return jsonify({"items": items, "total": len(items)})


@api_bp.route("/baselines/create", methods=["POST"])
def create_baseline():
    """Create a baseline from agent's currently monitored files."""
    data = request.get_json(force=True)
    agent_id = data.get("agent_id", "")
    baseline_name = data.get("name", f"baseline_{int(time.time())}")
    file_entries = data.get("files", [])  # [{path, hash, size}]

    if not file_entries:
        return jsonify({"error": "No files provided"}), 400

    indexed = 0
    for entry in file_entries:
        doc = {
            "agent_id": agent_id,
            "file_path": entry.get("path", ""),
            "file_hash": entry.get("hash", ""),
            "file_size": entry.get("size", 0),
            "permissions": entry.get("permissions", ""),
            "baseline_name": baseline_name,
            "status": "ok",
            "last_verified": datetime.now(timezone.utc).isoformat(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if os_client.index_doc(IDX_BASELINES, doc):
            indexed += 1

    log.info("Baseline '%s' created with %d files for agent %s", baseline_name, indexed, agent_id)
    return jsonify({"status": "created", "name": baseline_name, "files": indexed})


@api_bp.route("/baselines/verify", methods=["POST"])
def verify_baseline():
    """Verify current files against a baseline."""
    data = request.get_json(force=True)
    baseline_name = data.get("name", "")
    current_files = data.get("files", [])  # [{path, hash, size}]

    if not baseline_name:
        return jsonify({"error": "Baseline name required"}), 400

    # Get baseline entries
    baseline_items = os_client.search(IDX_BASELINES, {
        "query": {"term": {"baseline_name": baseline_name}}
    }, size=5000)

    baseline_map = {item["file_path"]: item for item in baseline_items}
    current_map = {f["path"]: f for f in current_files}

    results = {"modified": [], "deleted": [], "new": [], "ok": 0}

    for path, bl in baseline_map.items():
        if path not in current_map:
            results["deleted"].append({"path": path, "baseline_hash": bl.get("file_hash")})
        elif current_map[path].get("hash") != bl.get("file_hash"):
            results["modified"].append({
                "path": path,
                "baseline_hash": bl.get("file_hash"),
                "current_hash": current_map[path].get("hash"),
            })
        else:
            results["ok"] += 1

    for path in current_map:
        if path not in baseline_map:
            results["new"].append({"path": path, "hash": current_map[path].get("hash")})

    results["total_baseline"] = len(baseline_map)
    results["total_current"] = len(current_map)
    results["integrity_score"] = round(results["ok"] / max(len(baseline_map), 1) * 100, 1)

    return jsonify(results)


# ── Threat Analysis ───────────────────────────────────────────────────────

@api_bp.route("/threat/analyze", methods=["POST"])
def analyze_threat():
    """Analyze a single event for threat indicators."""
    event = request.get_json(force=True)
    sensitivity = classify_sensitivity(event.get("file_path", ""))
    hours_check = _hours_detector.is_outside_hours(event.get("timestamp"))
    threat = calculate_threat_score(
        event,
        ml_score=event.get("anomaly_score", 0),
        is_ransomware=event.get("is_ransomware", False),
        is_anomaly=event.get("is_anomaly", False),
        outside_hours=hours_check["outside_hours"],
        sensitivity=sensitivity,
    )
    return jsonify({
        "sensitivity": sensitivity,
        "working_hours": hours_check,
        "threat": threat,
    })


@api_bp.route("/threat/mitre-techniques")
def list_mitre_techniques():
    """List all known MITRE ATT&CK techniques."""
    return jsonify({"techniques": MITRE_TECHNIQUES})


@api_bp.route("/threat/heatmap")
def event_heatmap():
    """Get event counts by hour-of-day and day-of-week for heatmap."""
    body = {
        "query": {"range": {"timestamp": {"gte": "now-7d"}}},
        "aggs": {
            "by_hour": {
                "date_histogram": {"field": "timestamp", "calendar_interval": "hour"},
            }
        },
        "size": 0,
    }
    try:
        resp = os_client.client.search(index=IDX_EVENTS, body=body)
        buckets = resp.get("aggregations", {}).get("by_hour", {}).get("buckets", [])
        # Build 7x24 heatmap grid
        grid = [[0]*24 for _ in range(7)]
        for b in buckets:
            ts = b.get("key_as_string", "")
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                grid[dt.weekday()][dt.hour] += b["doc_count"]
            except Exception:
                pass
        return jsonify({
            "grid": grid,
            "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            "hours": list(range(24)),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Data Retention ────────────────────────────────────────────────────────

@api_bp.route("/admin/retention", methods=["POST"])
def admin_apply_retention():
    data = request.get_json(force=True)
    days = data.get("days", 30)
    results = {}
    for idx in [IDX_EVENTS, IDX_ANOMALIES, IDX_ALERTS, IDX_HEARTBEATS]:
        deleted = apply_retention(os_client, idx, days)
        results[idx] = deleted
    return jsonify({"status": "ok", "deleted": results, "retention_days": days})


# ── CSV Export ────────────────────────────────────────────────────────────

@api_bp.route("/admin/export/csv")
def admin_export_csv():
    """Export events as CSV."""
    import csv
    import io
    from flask import Response as FlaskResponse

    events = os_client.get_recent_events(limit=5000)
    output = io.StringIO()
    if events:
        fields = ["timestamp", "agent_id", "event_type", "file_path", "file_size",
                   "file_hash", "severity", "is_anomaly", "hostname"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for e in events:
            writer.writerow(e)

    return FlaskResponse(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=securefim_events.csv"},
    )


# ── Restore Request Handling ─────────────────────────────────────────────

@api_bp.route("/agents/<agent_id>/restore-requests", methods=["GET"])
def get_restore_requests(agent_id):
    """Agent polls this to get pending restore requests for itself."""
    body = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"agent_id": agent_id}},
                    {"term": {"status": "pending"}},
                ]
            }
        },
        "size": 20,
        "sort": [{"timestamp": {"order": "asc"}}],
    }
    try:
        resp = os_client.client.search(index="fim-restore-requests", body=body)
        hits = resp.get("hits", {}).get("hits", [])
        requests_list = []
        for h in hits:
            s = h.get("_source", {})
            requests_list.append({
                "_id": h.get("_id"),
                "file_path": s.get("file_path"),
                "backup_path": s.get("backup_path"),
                "event_id": s.get("event_id"),
                "requested_by": s.get("requested_by"),
                "timestamp": s.get("timestamp"),
            })
        if requests_list:
            log.info("Agent %s polled and found %d pending restores", agent_id, len(requests_list))
        return jsonify({"requests": requests_list, "count": len(requests_list)})
    except Exception as exc:
        log.error("Failed to get restore requests for %s: %s", agent_id, exc)
        return jsonify({"requests": [], "error": str(exc)}), 500


@api_bp.route("/agents/<agent_id>/restore-complete", methods=["POST"])
def mark_restore_complete(agent_id):
    """Agent notifies server that a restore request has been processed."""
    data = request.get_json(force=True)
    request_id = data.get("request_id")
    status = data.get("status", "completed")
    error = data.get("error", "")

    if not request_id:
        return jsonify({"error": "request_id required"}), 400

    try:
        # Update the restore request doc
        update_body = {
            "doc": {
                "status": status,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error": error if error else None,
            }
        }
        os_client.client.update(index="fim-restore-requests", id=request_id,
                                 body=update_body, refresh="wait_for")

        # Create a visible alert for admin
        completion_msg = (
            f"Agent {agent_id} restored: {data.get('restored_to')}" if status == "completed"
            else f"Agent {agent_id} restore FAILED: {error}"
        )
        os_client.index_doc(IDX_ALERTS, {
            "alert_type": "restore_completed" if status == "completed" else "restore_failed",
            "severity": "info" if status == "completed" else "warning",
            "title": "✓ File Restore Completed" if status == "completed" else "✗ File Restore Failed",
            "message": completion_msg,
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        log.info("Restore request %s marked as %s for agent %s", request_id, status, agent_id)
        return jsonify({"status": "acknowledged"})
    except Exception as exc:
        log.error("Failed to mark restore complete: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Baseline Verification (v7.6) ─────────────────────────────────────────

@api_bp.route("/agents/<agent_id>/verify-requests", methods=["GET"])
def get_verify_requests(agent_id):
    """
    Agent polls this to fetch pending baseline verification requests.
    Returns the list of pending requests + the list of files to hash
    (agent looks up the baseline file list from its own knowledge, or
    we include the paths here for convenience).
    """
    try:
        body = {
            "query": {"bool": {"must": [
                {"term": {"agent_id": agent_id}},
                {"term": {"status": "pending"}},
            ]}},
            "sort": [{"timestamp": {"order": "asc"}}],
            "size": 10,
        }
        resp = os_client.client.search(index="fim-verify-requests", body=body)
        reqs = []
        for hit in resp.get("hits", {}).get("hits", []):
            src = hit["_source"]
            baseline_name = src.get("baseline_name")
            # Fetch the baseline file list for this agent
            baseline_docs = os_client.search("fim-baselines", {
                "query": {"bool": {"must": [
                    {"term": {"baseline_name": baseline_name}},
                    {"term": {"agent_id": agent_id}},
                ]}}
            }, size=5000)
            files = [{"path": d.get("file_path"),
                      "baseline_hash": d.get("file_hash")} for d in baseline_docs]
            reqs.append({
                "request_id": hit["_id"],
                "baseline_name": baseline_name,
                "scheduled": src.get("scheduled", False),
                "files": files,
            })
        return jsonify({"requests": reqs})
    except Exception as exc:
        log.error("get_verify_requests error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/agents/<agent_id>/verify-complete", methods=["POST"])
def verify_complete(agent_id):
    """
    Agent POSTs verification results here.
    Body: {request_id, baseline_name, files: [{path, hash, size}]}
    """
    try:
        data = request.get_json(force=True) or {}
        request_id = data.get("request_id")
        baseline_name = data.get("baseline_name")
        files = data.get("files", [])
        if not request_id or not baseline_name:
            return jsonify({"error": "request_id and baseline_name required"}), 400

        if not scheduler_ref:
            return jsonify({"error": "scheduler not initialized"}), 500

        # Look up whether this was a scheduled verification (for result metadata)
        scheduled = False
        try:
            req = os_client.get_doc("fim-verify-requests", request_id)
            if req:
                scheduled = bool(req.get("scheduled", False))
        except Exception:
            pass

        result = scheduler_ref.record_verification_result(
            baseline_name=baseline_name,
            agent_id=agent_id,
            request_id=request_id,
            current_files=files,
            scheduled=scheduled,
        )

        # Also update the baseline's last_verified timestamp
        try:
            os_client.client.update_by_query(
                index=IDX_BASELINES,
                body={
                    "query": {"term": {"baseline_name": baseline_name}},
                    "script": {
                        "source": "ctx._source.last_verified = params.ts",
                        "lang": "painless",
                        "params": {"ts": datetime.now(timezone.utc).isoformat()},
                    },
                },
                refresh=True,
            )
        except Exception as exc:
            log.debug("last_verified update failed: %s", exc)

        return jsonify({"status": "recorded",
                        "integrity_score": result.get("integrity_score"),
                        "drift_detected": result.get("drift_detected")})
    except Exception as exc:
        log.error("verify_complete error: %s", exc)
        return jsonify({"error": str(exc)}), 500
