"""
SecureFIM Pro  Admin Server (Port 8444)
Separate Flask app with sidebar navigation, login, OTP, user management.
"""
import hashlib,json,logging,os,random,smtplib,threading,time
from datetime import datetime,timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask,Blueprint,Response,request,jsonify,send_file
from flask_cors import CORS

log=logging.getLogger("securefim.admin")
ADMIN_CREDS_FILE="data/admin_credentials.json"
EMAIL_CONFIG_FILE="data/email_config.json"
from server.auth import (hash_password, authenticate, load_users, save_users,
                         issue_token, revoke_token, require_admin, guard_blueprint)
USERS=load_users()
_otp_store={}
_os_client=None;_ml_detector=None;_rw_detector=None;_discord_alerter=None;_email_alerter=None;_scheduler=None
def init_admin(os_client,ml_detector,rw_detector,discord_alerter,email_alerter=None,scheduler=None):
    global _os_client,_ml_detector,_rw_detector,_discord_alerter,_email_alerter,_scheduler
    _os_client=os_client;_ml_detector=ml_detector;_rw_detector=rw_detector;_discord_alerter=discord_alerter;_email_alerter=email_alerter;_scheduler=scheduler

admin_api=Blueprint("admin_api",__name__,url_prefix="/admin-api")

# Require a valid session token on every /admin-api route EXCEPT these public ones.
admin_api.before_request(guard_blueprint((
    "/login", "/forgot-password", "/verify-otp", "/reset-password",
)))

@admin_api.route("/login",methods=["POST"])
def login():
    d=request.get_json(force=True);u,p=d.get("username","").strip(),d.get("password","")
    if authenticate(USERS,u,p):
        log.info("Admin login: %s",u)
        return jsonify({"status":"ok","username":u,"token":issue_token(u)})
    return jsonify({"error":"Invalid credentials"}),401

@admin_api.route("/forgot-password",methods=["POST"])
def forgot_password():
    d=request.get_json(force=True);u,email=d.get("username","").strip(),d.get("email","").strip()
    if not u or not email:return jsonify({"error":"Required"}),400
    if u not in USERS:return jsonify({"error":"User not found"}),404
    otp=str(random.randint(100000,999999));_otp_store[u]={"otp":otp,"expires":time.time()+180,"email":email,"verified":False}
    try:
        cfg={};
        if os.path.exists(EMAIL_CONFIG_FILE):
            with open(EMAIL_CONFIG_FILE) as f:cfg=json.load(f)
        s_email,s_pw=cfg.get("sender_email",""),cfg.get("sender_password","")
        if s_email and s_pw:
            msg=MIMEMultipart();msg["From"],msg["To"],msg["Subject"]=s_email,email,"SecureFIM Pro OTP"
            msg.attach(MIMEText(f"Your OTP: {otp}\nValid for 3 minutes.\n\n— SecureFIM Pro","plain"))
            with smtplib.SMTP(cfg.get("smtp_server","smtp.gmail.com"),cfg.get("smtp_port",587),timeout=10) as sv:
                sv.starttls();sv.login(s_email,s_pw);sv.sendmail(s_email,email,msg.as_string())
        else:log.warning("No email config. OTP for %s: %s",u,otp)
    except Exception as e:log.error("Email failed: %s. OTP for %s: %s",e,u,otp)
    return jsonify({"status":"ok"})

@admin_api.route("/verify-otp",methods=["POST"])
def verify_otp():
    d=request.get_json(force=True);u,otp=d.get("username","").strip(),d.get("otp","").strip()
    s=_otp_store.get(u)
    if not s:return jsonify({"error":"No OTP requested"}),400
    if time.time()>s["expires"]:del _otp_store[u];return jsonify({"error":"OTP expired"}),400
    if s["otp"]!=otp:return jsonify({"error":"Invalid OTP"}),400
    s["verified"]=True;return jsonify({"status":"ok"})

@admin_api.route("/reset-password",methods=["POST"])
def reset_password():
    d=request.get_json(force=True);u,pw=d.get("username","").strip(),d.get("new_password","")
    if not u or len(pw)<4:return jsonify({"error":"Min 4 chars"}),400
    s=_otp_store.get(u)
    if not s or not s.get("verified"):return jsonify({"error":"OTP not verified"}),400
    USERS[u]=hash_password(pw);save_users(USERS);del _otp_store[u]
    return jsonify({"status":"ok"})

@admin_api.route("/change-password",methods=["POST"])
def change_password():
    d=request.get_json(force=True);u,cur,new=d.get("username","").strip(),d.get("current_password",""),d.get("new_password","")
    if not u or not cur or len(new)<4:return jsonify({"error":"Invalid"}),400
    if not authenticate(USERS,u,cur):return jsonify({"error":"Wrong credentials"}),401
    USERS[u]=hash_password(new);save_users(USERS);return jsonify({"status":"ok","message":f"Password changed for {u}"})

@admin_api.route("/add-user",methods=["POST"])
def add_user():
    d=request.get_json(force=True);au,ap,nu,np_=d.get("auth_username","").strip(),d.get("auth_password",""),d.get("new_username","").strip(),d.get("new_password","")
    if not all([au,ap,nu,np_]):return jsonify({"error":"All fields required"}),400
    if not authenticate(USERS,au,ap):return jsonify({"error":"Auth failed"}),401
    if nu in USERS:return jsonify({"error":"Exists"}),400
    if len(np_)<4:return jsonify({"error":"Min 4 chars"}),400
    USERS[nu]=hash_password(np_);save_users(USERS);return jsonify({"status":"ok","message":f"User '{nu}' created"})

@admin_api.route("/remove-user",methods=["POST"])
def remove_user():
    d=request.get_json(force=True);au,ap,ru=d.get("auth_username","").strip(),d.get("auth_password",""),d.get("remove_username","").strip()
    if not authenticate(USERS,au,ap):return jsonify({"error":"Auth failed"}),401
    if ru==au:return jsonify({"error":"Cannot remove yourself"}),400
    if ru not in USERS:return jsonify({"error":"Not found"}),404
    if len(USERS)<=1:return jsonify({"error":"Last admin"}),400
    del USERS[ru];save_users(USERS);return jsonify({"status":"ok","message":f"Removed '{ru}'"})

@admin_api.route("/list-users")
def list_users():return jsonify({"users":list(USERS.keys())})

@admin_api.route("/system-health")
def system_health():
    import psutil
    idx_stats={}
    for idx in["fim-events","fim-agents","fim-anomalies","fim-alerts","fim-heartbeats"]:
        try:idx_stats[idx]={"doc_count":_os_client.count(idx)}
        except:idx_stats[idx]={"doc_count":0,"error":True}
    proc=psutil.Process();disk=psutil.disk_usage("C:\\" if os.name=="nt" else "/");mem=psutil.virtual_memory()
    os_health={}
    try:os_health=_os_client.client.cluster.health()
    except Exception as e:os_health={"status":"error"}
    return jsonify({"server":{"cpu_percent":psutil.cpu_percent(interval=0),"memory_percent":mem.percent,"memory_used_gb":round(mem.used/1073741824,2),"memory_total_gb":round(mem.total/1073741824,2),"disk_percent":disk.percent,"disk_used_gb":round(disk.used/1073741824,2),"disk_total_gb":round(disk.total/1073741824,2),"server_pid":os.getpid(),"server_memory_mb":round(proc.memory_info().rss/1048576,1),"uptime_seconds":int(time.time()-proc.create_time())},"opensearch":os_health,"indices":idx_stats})

@admin_api.route("/agent-health")
def agent_health():
    agents=_os_client.get_agents()
    for a in agents:
        hbs=_os_client.search("fim-heartbeats",{"query":{"term":{"agent_id":a.get("agent_id","")}},"sort":[{"timestamp":{"order":"desc"}}]},size=1)
        a["latest_heartbeat"]=hbs[0] if hbs else {}
    return jsonify({"agents":agents})

@admin_api.route("/dashboard-summary")
def dashboard_summary():
    from server.config import AGENT_OFFLINE_THRESHOLD
    stats=_os_client.get_event_stats(minutes=60);agents=_os_client.get_agents();anomalies=_os_client.get_recent_anomalies(limit=5);alerts=_os_client.get_recent_alerts(limit=30);events=_os_client.get_recent_events(limit=50)
    now_ts=time.time();online=offline=0
    for a in agents:
        hb=a.get("last_heartbeat")
        if hb:
            try:
                hb_ts=datetime.fromisoformat(hb.replace("Z","+00:00")).timestamp()
                if now_ts-hb_ts<=AGENT_OFFLINE_THRESHOLD:online+=1
                else:offline+=1
            except:offline+=1
        else:offline+=1
    paths=[{"agent_id":a.get("agent_id"),"path":p} for a in agents for p in a.get("monitored_paths",[])]
    return jsonify({"event_stats":stats,"agents_online":online,"agents_offline":offline,"agents_total":len(agents),"agents":agents,"monitored_paths":paths,"recent_anomalies":anomalies,"recent_alerts":alerts,"recent_events":events,"ml_status":_ml_detector.status() if _ml_detector else {},"ransomware_status":_rw_detector.status() if _rw_detector else {},"discord_status":_discord_alerter.status() if _discord_alerter else {}})

@admin_api.route("/agents/<agent_id>/paths",methods=["GET"])
def get_paths(agent_id):
    a=_os_client.get_agent(agent_id)
    if not a:return jsonify({"error":"not found"}),404
    return jsonify({"monitored_paths":a.get("monitored_paths",[])})

@admin_api.route("/agents/<agent_id>/paths",methods=["PUT","POST"])
def update_paths(agent_id):
    d=request.get_json(force=True);_os_client.update_doc("fim-agents",agent_id,{"monitored_paths":d.get("monitored_paths",[])});return jsonify({"status":"updated"})

@admin_api.route("/ml/train",methods=["POST"])
def ml_train():
    if not _ml_detector:return jsonify({"error":"ML not init"}),500
    if not _ml_detector.can_train():return jsonify({"error":"Not enough data","samples":len(_ml_detector.training_data)}),400
    return jsonify({"status":"trained" if _ml_detector.train() else "failed"})

@admin_api.route("/ml/reset",methods=["POST"])
def ml_reset():
    if not _ml_detector:return jsonify({"error":"ML not init"}),500
    _ml_detector.model=None;_ml_detector.scaler=None;_ml_detector.is_trained=False;_ml_detector.training_data.clear()
    for f in["models/ocsvm_model.joblib","models/ocsvm_scaler.joblib"]:
        if os.path.exists(f):os.remove(f)
    return jsonify({"status":"ok"})

@admin_api.route("/discord/test",methods=["POST"])
def discord_test():
    if not _discord_alerter or not _discord_alerter.enabled:return jsonify({"error":"Discord not enabled"}),400
    _discord_alerter.send_alert("🧪 Test Alert","Test from Admin Panel","info");return jsonify({"status":"ok"})

@admin_api.route("/alerts/acknowledge-all",methods=["POST"])
def ack_all():
    try:_os_client.client.update_by_query(index="fim-alerts",body={"query":{"term":{"acknowledged":False}},"script":{"source":"ctx._source.acknowledged = true"}},refresh=True);return jsonify({"status":"ok"})
    except Exception as e:return jsonify({"error":str(e)}),500

@admin_api.route("/clear/<index_name>",methods=["DELETE"])
def clear_index(index_name):
    if index_name not in{"fim-events","fim-anomalies","fim-alerts","fim-heartbeats"}:return jsonify({"error":"Cannot clear"}),400
    deleted=_os_client.delete_by_query(index_name,{"query":{"match_all":{}}});return jsonify({"status":"ok","deleted":deleted})

@admin_api.route("/export/events")
def export_events():
    events=_os_client.get_recent_events(limit=int(request.args.get("limit",1000)));return jsonify({"events":events,"exported":len(events)})

@admin_api.route("/export/csv")
def export_csv():
    """Export events as CSV file."""
    import csv, io
    from flask import Response as FlaskResponse
    events = _os_client.get_recent_events(limit=5000)
    output = io.StringIO()
    if events:
        fields = ["timestamp","agent_id","event_type","file_path","file_size",
                  "file_hash","severity","sensitivity","threat_score","threat_level",
                  "outside_hours","is_anomaly","hostname"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for e in events:
            writer.writerow(e)
    else:
        output.write("No events to export\n")
    return FlaskResponse(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=securefim_events_{int(time.time())}.csv"},
    )

@admin_api.route("/retention", methods=["POST"])
def apply_retention_endpoint():
    """Apply data retention — delete events older than N days."""
    data = request.get_json(force=True)
    days = int(data.get("days", 30))
    results = {}
    for idx in ["fim-events","fim-anomalies","fim-alerts","fim-heartbeats"]:
        try:
            body = {"query": {"range": {"timestamp": {"lt": f"now-{days}d"}}}}
            deleted = _os_client.delete_by_query(idx, body)
            results[idx] = deleted
        except Exception as e:
            results[idx] = f"error: {e}"
    return jsonify({"status":"ok", "deleted":results, "retention_days":days})

@admin_api.route("/watchlist", methods=["GET"])
def get_watchlist():
    items = _os_client.search("fim-watchlist", {"query":{"match_all":{}}, "sort":[{"timestamp":{"order":"desc"}}]}, size=200)
    return jsonify({"items":items})

@admin_api.route("/watchlist", methods=["POST"])
def add_watchlist():
    d = request.get_json(force=True)
    doc = {
        "file_path": d.get("file_path",""),
        "sensitivity": d.get("sensitivity","HIGH"),
        "description": d.get("description",""),
        "added_by": d.get("added_by","admin"),
        "auto_alert": d.get("auto_alert",True),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    doc_id = _os_client.index_doc("fim-watchlist", doc)
    return jsonify({"status":"added","id":doc_id})

@admin_api.route("/watchlist/<item_id>", methods=["DELETE"])
def remove_watchlist(item_id):
    try:
        _os_client.client.delete(index="fim-watchlist", id=item_id, refresh="wait_for")
        return jsonify({"status":"removed"})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@admin_api.route("/baselines", methods=["GET"])
def get_baselines():
    items = _os_client.search("fim-baselines", {"query":{"match_all":{}}, "sort":[{"timestamp":{"order":"desc"}}]}, size=500)
    return jsonify({"items":items})

@admin_api.route("/baselines/create", methods=["POST"])
def create_baseline_ep():
    d = request.get_json(force=True)
    name = d.get("name",f"baseline_{int(time.time())}")
    agent_id = d.get("agent_id","")
    files = d.get("files",[])
    indexed = 0
    for entry in files:
        doc = {
            "agent_id": agent_id, "file_path": entry.get("path",""),
            "file_hash": entry.get("hash",""), "file_size": entry.get("size",0),
            "baseline_name": name, "status": "ok",
            "last_verified": datetime.now(timezone.utc).isoformat(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if _os_client.index_doc("fim-baselines", doc): indexed += 1
    return jsonify({"status":"created","name":name,"files":indexed})

@admin_api.route("/baselines/verify", methods=["POST"])
def verify_baseline_ep():
    d = request.get_json(force=True)
    name = d.get("name","")
    current_files = d.get("files",[])
    baseline_items = _os_client.search("fim-baselines", {"query":{"term":{"baseline_name":name}}}, size=5000)
    baseline_map = {i["file_path"]:i for i in baseline_items}
    current_map = {f["path"]:f for f in current_files}
    results = {"modified":[],"deleted":[],"new":[],"ok":0}
    for path, bl in baseline_map.items():
        if path not in current_map:
            results["deleted"].append({"path":path})
        elif current_map[path].get("hash") != bl.get("file_hash"):
            results["modified"].append({"path":path})
        else:
            results["ok"] += 1
    for path in current_map:
        if path not in baseline_map:
            results["new"].append({"path":path})
    results["total_baseline"] = len(baseline_map)
    results["total_current"] = len(current_map)
    results["integrity_score"] = round(results["ok"]/max(len(baseline_map),1)*100,1)
    return jsonify(results)

@admin_api.route("/backups", methods=["GET"])
def list_backups():
    """List all events that have backups available for restore, grouped by file."""
    body = {
        "query": {"term": {"backed_up": True}},
        "sort": [{"timestamp": {"order": "asc"}}],  # oldest first
        "size": 500,
    }
    try:
        resp = _os_client.client.search(index="fim-events", body=body)
        hits = resp.get("hits", {}).get("hits", [])
        # Group backups per file to number them (v1, v2, ...)
        version_counter = {}
        items = []
        for h in hits:
            s = h.get("_source", {})
            fp = s.get("file_path", "")
            version_counter[fp] = version_counter.get(fp, 0) + 1
            items.append({
                "_id": h.get("_id"),
                "file_path": fp,
                "backup_path": s.get("backup_path"),
                "event_type": s.get("event_type"),
                "username": s.get("username"),
                "agent_id": s.get("agent_id"),
                "hostname": s.get("hostname"),
                "file_hash": s.get("file_hash"),
                "timestamp": s.get("timestamp"),
                "sensitivity": s.get("sensitivity"),
                "version": version_counter[fp],  # 1 = oldest (safest original)
            })
        # Reverse for display: newest first, but version number still shows order
        items.reverse()
        return jsonify({"items": items, "total": len(items)})
    except Exception as exc:
        return jsonify({"error": str(exc), "items": []}), 500

@admin_api.route("/backups/restore", methods=["POST"])
def request_restore():
    """
    Request restoration of a file from its backup.
    This creates a restore request for the agent to pick up.
    """
    data = request.get_json(force=True)
    event_id = data.get("event_id")
    if not event_id:
        return jsonify({"error": "event_id required"}), 400

    try:
        # Get the event
        resp = _os_client.client.get(index="fim-events", id=event_id)
        event = resp.get("_source", {})

        if not event.get("backed_up"):
            return jsonify({"error": "No backup available for this event"}), 400

        # Create a restore request document in the dedicated index
        restore_doc = {
            "event_id": event_id,
            "agent_id": event.get("agent_id"),
            "file_path": event.get("file_path"),
            "backup_path": event.get("backup_path"),
            "requested_by": data.get("requested_by", "admin"),
            "status": "pending",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Ensure restore-requests index exists with correct mapping before writing
        try:
            if not _os_client.client.indices.exists(index="fim-restore-requests"):
                _os_client.client.indices.create(index="fim-restore-requests", body={
                    "mappings": {
                        "properties": {
                            "event_id":      {"type": "keyword"},
                            "agent_id":      {"type": "keyword"},
                            "file_path":     {"type": "keyword"},
                            "backup_path":   {"type": "keyword"},
                            "requested_by":  {"type": "keyword"},
                            "status":        {"type": "keyword"},
                            "error":         {"type": "text"},
                            "completed_at":  {"type": "date"},
                            "timestamp":     {"type": "date"},
                        }
                    },
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                })
                log.info("Created fim-restore-requests index on demand")
        except Exception as exc:
            log.error("Failed to create fim-restore-requests index: %s", exc)

        doc_id = _os_client.index_doc("fim-restore-requests", restore_doc)
        if not doc_id:
            log.error("Failed to index restore-request doc! Payload: %s", restore_doc)
            return jsonify({"error": "Failed to store restore request in OpenSearch"}), 500

        # Force refresh so the agent's next poll can see it immediately
        try:
            _os_client.client.indices.refresh(index="fim-restore-requests")
        except Exception:
            pass

        # Also create an audit alert so admin can see it happened
        _os_client.index_doc("fim-alerts", {
            "alert_type": "restore_request",
            "severity": "info",
            "title": "File Restore Requested",
            "message": f"Restore requested: {event.get('file_path')} (agent: {event.get('agent_id')})",
            "agent_id": event.get("agent_id"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        log.info("Restore request queued: id=%s agent=%s file=%s",
                 doc_id, event.get('agent_id'), event.get('file_path'))

        return jsonify({
            "status": "restore_requested",
            "request_id": doc_id,
            "instructions": f"copy \"{event.get('backup_path')}\" \"{event.get('file_path')}\""
        })
    except Exception as exc:
        log.error("Restore request error: %s", exc)
        return jsonify({"error": str(exc)}), 500

#  Compliance Reports (v7.3) 
@admin_api.route("/reports/generate",methods=["POST"])
def reports_generate():
    """Generate a PDF compliance report. Body: {period, start?, end?, generated_by?}"""
    try:
        from server.features import reports as _reports
    except Exception as exc:
        log.error("reports module import failed: %s", exc)
        return jsonify({"error": f"reports module unavailable: {exc}"}), 500
    d = request.get_json(force=True) or {}
    period = (d.get("period") or "weekly").lower()
    generated_by = d.get("generated_by") or "admin"
    start_iso = d.get("start")
    end_iso = d.get("end")
    start_dt = end_dt = None
    if period == "custom":
        try:
            from datetime import datetime as _dt, timezone as _tz
            start_dt = _dt.fromisoformat(start_iso.replace("Z","+00:00")) if start_iso else None
            end_dt = _dt.fromisoformat(end_iso.replace("Z","+00:00")) if end_iso else None
            if not start_dt or not end_dt:
                return jsonify({"error":"custom period requires start and end ISO timestamps"}),400
        except Exception as exc:
            return jsonify({"error":f"invalid date format: {exc}"}),400
    try:
        result = _reports.generate_report(_os_client, period=period,
                                          start=start_dt, end=end_dt,
                                          generated_by=generated_by)
        return jsonify({"status":"ok", **{k:v for k,v in result.items() if k!="summary"},
                        "summary":result.get("summary",{})})
    except Exception as exc:
        log.error("Report generation failed: %s", exc)
        return jsonify({"error":str(exc)}), 500

@admin_api.route("/reports/list",methods=["GET"])
def reports_list():
    try:
        from server.features import reports as _reports
        return jsonify({"reports":_reports.list_reports()})
    except Exception as exc:
        log.error("reports_list failed: %s", exc)
        return jsonify({"error":str(exc)}), 500

@admin_api.route("/reports/download/<path:filename>",methods=["GET"])
def reports_download(filename):
    try:
        from server.features import reports as _reports
        full = _reports.get_report_path(filename)
        if not full:
            return jsonify({"error":"not found"}), 404
        return send_file(full, as_attachment=True, download_name=filename, mimetype="application/pdf")
    except Exception as exc:
        log.error("reports_download failed: %s", exc)
        return jsonify({"error":str(exc)}), 500

@admin_api.route("/reports/delete/<path:filename>",methods=["DELETE"])
def reports_delete(filename):
    try:
        from server.features import reports as _reports
        ok = _reports.delete_report(filename)
        return jsonify({"status":"deleted" if ok else "failed"})
    except Exception as exc:
        log.error("reports_delete failed: %s", exc)
        return jsonify({"error":str(exc)}), 500

#  Email Alerts (v7.5) 
@admin_api.route("/email-alerts/status",methods=["GET"])
def email_alerts_status():
    if not _email_alerter:
        return jsonify({"error":"email alerter not initialized"}), 500
    return jsonify(_email_alerter.status())

@admin_api.route("/email-alerts/config",methods=["GET","POST"])
def email_alerts_config():
    if not _email_alerter:
        return jsonify({"error":"email alerter not initialized"}), 500
    if request.method == "GET":
        return jsonify({"config":_email_alerter.config,
                        "smtp_ready":_email_alerter._smtp_ready(),
                        "sender_email":_email_alerter.smtp.get("sender_email","")})
    d = request.get_json(force=True) or {}
    cfg = _email_alerter.config
    if "enabled" in d: cfg["enabled"] = bool(d["enabled"])
    if "recipients" in d and isinstance(d["recipients"], list):
        cfg["recipients"] = [r.strip() for r in d["recipients"] if r and "@" in r]
    if "alert_types" in d and isinstance(d["alert_types"], dict):
        for k,v in d["alert_types"].items(): cfg["alert_types"][k] = bool(v)
    if "throttle_per_minute" in d:
        try: cfg["throttle_per_minute"] = max(1, min(100, int(d["throttle_per_minute"])))
        except: pass
    if "min_severity" in d:
        s = str(d["min_severity"]).lower()
        if s in ("info","warning","critical","ransomware"): cfg["min_severity"] = s
    _email_alerter.save_config()
    if cfg.get("enabled") and _email_alerter._smtp_ready() and not _email_alerter._worker:
        import threading as _th
        _email_alerter._worker = _th.Thread(target=_email_alerter._process_queue, daemon=True)
        _email_alerter._worker.start()
        log.info("Email alerter worker started (enabled via admin)")
    return jsonify({"status":"ok","config":cfg})

@admin_api.route("/email-alerts/recipients/add",methods=["POST"])
def email_alerts_add_recipient():
    if not _email_alerter:
        return jsonify({"error":"email alerter not initialized"}), 500
    d = request.get_json(force=True) or {}
    email = (d.get("email") or "").strip()
    if not email or "@" not in email:
        return jsonify({"error":"invalid email"}), 400
    cfg = _email_alerter.config
    if email in cfg.get("recipients", []):
        return jsonify({"status":"already_exists","recipients":cfg["recipients"]})
    cfg.setdefault("recipients", []).append(email)
    _email_alerter.save_config()
    log.info("Email recipient added: %s", email)
    return jsonify({"status":"added","recipients":cfg["recipients"]})

@admin_api.route("/email-alerts/recipients/remove",methods=["POST"])
def email_alerts_remove_recipient():
    if not _email_alerter:
        return jsonify({"error":"email alerter not initialized"}), 500
    d = request.get_json(force=True) or {}
    email = (d.get("email") or "").strip()
    cfg = _email_alerter.config
    if email in cfg.get("recipients", []):
        cfg["recipients"].remove(email)
        _email_alerter.save_config()
        log.info("Email recipient removed: %s", email)
        return jsonify({"status":"removed","recipients":cfg["recipients"]})
    return jsonify({"status":"not_found","recipients":cfg.get("recipients",[])})

@admin_api.route("/email-alerts/test",methods=["POST"])
def email_alerts_test():
    if not _email_alerter:
        return jsonify({"error":"email alerter not initialized"}), 500
    d = request.get_json(silent=True) or {}
    to = (d.get("email") or "").strip() or None
    ok, msg = _email_alerter.send_test_email(to=to)
    return jsonify({"status":"ok" if ok else "failed", "message":msg})

#  Baseline Scheduler (v7.6) 
@admin_api.route("/scheduler/status",methods=["GET"])
def scheduler_status():
    if not _scheduler:
        return jsonify({"error":"scheduler not initialized"}), 500
    return jsonify(_scheduler.status())

@admin_api.route("/scheduler/list",methods=["GET"])
def scheduler_list():
    """List all baselines with their schedule state."""
    if not _scheduler or not _os_client:
        return jsonify({"error":"scheduler not initialized"}), 500
    try:
        # Group baselines by name, pick one rep per name
        body = {
            "size": 0,
            "query": {"match_all": {}},
            "aggs": {
                "by_name": {
                    "terms": {"field": "baseline_name", "size": 200},
                    "aggs": {
                        "rep": {
                            "top_hits": {"size": 1,
                                         "_source": {"includes": [
                                             "baseline_name","agent_id",
                                             "schedule_enabled","schedule_frequency",
                                             "schedule_interval_minutes",
                                             "schedule_next_at","schedule_last_at",
                                             "last_verified"]}}
                        },
                        "file_count": {"value_count": {"field": "file_path.raw"}}
                    }
                }
            }
        }
        resp = _os_client.client.search(index="fim-baselines", body=body)
        items = []
        for b in resp.get("aggregations",{}).get("by_name",{}).get("buckets",[]):
            hits = b.get("rep",{}).get("hits",{}).get("hits",[])
            if not hits: continue
            src = hits[0]["_source"]
            items.append({
                "baseline_name": src.get("baseline_name"),
                "agent_id": src.get("agent_id"),
                "file_count": b.get("file_count",{}).get("value",0) or b.get("doc_count",0),
                "schedule_enabled": bool(src.get("schedule_enabled")),
                "schedule_frequency": src.get("schedule_frequency") or "daily",
                "schedule_interval_minutes": src.get("schedule_interval_minutes") or 0,
                "schedule_next_at": src.get("schedule_next_at"),
                "schedule_last_at": src.get("schedule_last_at"),
                "last_verified": src.get("last_verified"),
            })
        return jsonify({"baselines": items})
    except Exception as exc:
        log.error("scheduler_list error: %s", exc)
        return jsonify({"error": str(exc)}), 500

@admin_api.route("/scheduler/schedule",methods=["POST"])
def scheduler_set_schedule():
    if not _scheduler:
        return jsonify({"error":"scheduler not initialized"}), 500
    d = request.get_json(force=True) or {}
    name = (d.get("baseline_name") or "").strip()
    if not name:
        return jsonify({"error":"baseline_name required"}), 400
    try:
        fields = _scheduler.set_schedule(
            name,
            enabled=bool(d.get("enabled", False)),
            frequency=(d.get("frequency") or "daily").lower(),
            interval_minutes=int(d.get("interval_minutes") or 0),
        )
        return jsonify({"status":"ok","schedule":fields})
    except Exception as exc:
        log.error("scheduler_set_schedule error: %s", exc)
        return jsonify({"error": str(exc)}), 500

@admin_api.route("/scheduler/run-now",methods=["POST"])
def scheduler_run_now():
    if not _scheduler:
        return jsonify({"error":"scheduler not initialized"}), 500
    d = request.get_json(force=True) or {}
    name = (d.get("baseline_name") or "").strip()
    agent_id = (d.get("agent_id") or "").strip()
    if not name or not agent_id:
        return jsonify({"error":"baseline_name and agent_id required"}), 400
    try:
        req_id = _scheduler.run_now(name, agent_id, requested_by="admin")
        if not req_id:
            return jsonify({"error":"failed to enqueue"}), 500
        return jsonify({"status":"queued","request_id":req_id})
    except Exception as exc:
        log.error("scheduler_run_now error: %s", exc)
        return jsonify({"error": str(exc)}), 500

@admin_api.route("/scheduler/history",methods=["GET"])
def scheduler_history():
    if not _scheduler:
        return jsonify({"error":"scheduler not initialized"}), 500
    name = request.args.get("baseline_name")
    limit = int(request.args.get("limit", 20))
    try:
        return jsonify({"history": _scheduler.list_history(baseline_name=name, limit=limit)})
    except Exception as exc:
        log.error("scheduler_history error: %s", exc)
        return jsonify({"error": str(exc)}), 500

admin_page=Blueprint("admin_page",__name__)
@admin_page.route("/")
def index():return Response(ADMIN_HTML,mimetype="text/html",headers={"Cache-Control":"no-cache,no-store,must-revalidate","Pragma":"no-cache","Expires":"0"})

def create_admin_app():
    app=Flask(__name__);app.config["SECRET_KEY"]="securefim-admin";CORS(app)
    app.register_blueprint(admin_api);app.register_blueprint(admin_page);return app


ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureFIM Pro — Admin Panel</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--card:#161b22;--card2:#1c2333;--bdr:#30363d;--tx:#e6edf3;--dim:#8b949e;--acc:#58a6ff;--grn:#3fb950;--red:#f85149;--yel:#d29922;--sbw:220px}
[data-theme="light"]{--bg:#f0f2f5;--card:#fff;--card2:#f8f9fa;--bdr:#d0d7de;--tx:#1f2328;--dim:#656d76;--acc:#0969da;--grn:#1a7f37;--red:#cf222e;--yel:#9a6700}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--tx);display:flex;min-height:100vh;font-size:14px}
a{color:var(--acc);text-decoration:none}
.sidebar{width:var(--sbw);background:var(--card);border-right:1px solid var(--bdr);position:fixed;top:0;left:0;bottom:0;overflow-y:auto;display:flex;flex-direction:column;z-index:50}
.sb-logo{padding:16px;border-bottom:1px solid var(--bdr)}
.sb-logo h1{font-size:14px;color:var(--acc);font-weight:600}
.sb-logo span{font-size:10px;color:var(--dim)}
.nav-i{display:flex;align-items:center;gap:9px;padding:9px 16px;color:var(--dim);cursor:pointer;font-size:13px;border-left:3px solid transparent;transition:all .12s}
.nav-i:hover{background:var(--card2);color:var(--tx)}
.nav-i.active{color:var(--acc);border-left-color:var(--acc);background:rgba(88,166,255,.06)}
.sb-section{padding:10px 0;border-bottom:1px solid var(--bdr)}
.sb-section:last-of-type{border:none}
.sb-user{padding:12px 16px;border-top:1px solid var(--bdr);margin-top:auto}
.sb-user .name{color:var(--grn);font-weight:600;font-size:13px}
.sb-user .role{color:var(--dim);font-size:11px}
.logout-btn{margin-top:8px;width:100%;padding:6px;border-radius:6px;border:1px solid var(--red);background:transparent;color:var(--red);cursor:pointer;font-size:12px}
.logout-btn:hover{background:var(--red);color:#fff}
.theme-btn{margin-top:6px;width:100%;padding:6px;border-radius:6px;border:1px solid var(--bdr);background:transparent;color:var(--dim);cursor:pointer;font-size:12px}
.main{margin-left:var(--sbw);flex:1;padding:20px}
.panel{display:none}.panel.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:14px}
.card .l{font-size:10px;text-transform:uppercase;color:var(--dim);letter-spacing:.5px;margin-bottom:4px}
.card .v{font-size:22px;font-weight:700}
.card .s{font-size:11px;color:var(--dim);margin-top:2px}
.sec{background:var(--card);border:1px solid var(--bdr);border-radius:10px;margin-bottom:14px;overflow:hidden}
.sec-h{padding:12px 16px;border-bottom:1px solid var(--bdr);font-size:13px;font-weight:600}
.sec-b{padding:14px 16px}.sec-b.np{padding:0}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:7px 12px;color:var(--dim);font-weight:600;font-size:10px;text-transform:uppercase;border-bottom:1px solid var(--bdr)}
td{padding:7px 12px;border-bottom:1px solid var(--bdr)}
.mono{font-family:monospace;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}
.badge.ok{background:rgba(63,185,80,.12);color:var(--grn)}.badge.err{background:rgba(248,81,73,.12);color:var(--red)}.badge.warn{background:rgba(210,153,34,.12);color:var(--yel)}.badge.info{background:rgba(88,166,255,.12);color:var(--acc)}
.empty{text-align:center;padding:25px;color:var(--dim);font-style:italic}
.btn{padding:5px 14px;border-radius:6px;border:1px solid var(--bdr);background:var(--card);color:var(--tx);cursor:pointer;font-size:12px;transition:all .12s}
.btn:hover{border-color:var(--acc)}.btn-p{background:var(--acc);border-color:var(--acc);color:#fff}.btn-d{background:var(--red);border-color:var(--red);color:#fff}
.inp{width:100%;padding:7px 10px;border-radius:6px;border:1px solid var(--bdr);background:var(--bg);color:var(--tx);font-size:13px;margin-bottom:8px}.inp:focus{outline:none;border-color:var(--acc)}
.res{font-size:12px;margin-top:6px;min-height:16px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}.dot.ok{background:var(--grn)}.dot.err{background:var(--red)}.dot.warn{background:var(--yel)}
.feed-i{padding:8px 12px;border-bottom:1px solid var(--bdr);font-size:12px}
/* Login */
.overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.75);z-index:100;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.overlay.hidden{display:none}
.lbox{background:var(--card);border:1px solid var(--bdr);border-radius:14px;padding:36px;width:400px;max-width:90vw;text-align:center;position:relative}
.lbox .close-x{position:absolute;top:12px;right:16px;background:none;border:none;color:var(--dim);font-size:20px;cursor:pointer}.lbox .close-x:hover{color:var(--red)}
.lbox h2{font-size:18px;margin:8px 0 4px}.lbox p{color:var(--dim);font-size:12px;margin-bottom:16px}
.lbox .ic{font-size:40px;display:block}
.step{display:none}.step.active{display:block}
.lbtn{width:100%;padding:9px;border-radius:7px;border:none;background:var(--acc);color:#fff;font-size:13px;font-weight:600;cursor:pointer;margin-top:4px}.lbtn:hover{opacity:.9}
.lbtn.sec{background:transparent;border:1px solid var(--bdr);color:var(--dim);margin-top:6px}.lbtn.sec:hover{border-color:var(--acc);color:var(--acc)}
.errmsg{color:var(--red);font-size:12px;margin-top:6px}.okmsg{color:var(--grn);font-size:12px;margin-top:6px}
.otp-i{letter-spacing:8px;font-size:22px;text-align:center;font-weight:700;font-family:monospace}
.tmr{color:var(--yel);font-size:11px;margin-top:3px}
</style>
</head>
<body>
<!-- LOGIN -->
<div id="loginO" class="overlay">
<div class="lbox">
<button class="close-x" onclick="document.getElementById('loginO').classList.add('hidden')">&times;</button>
<div id="s1" class="step active"><span class="ic">🔐</span><h2>Admin Login</h2><p>Port 8444 — Restricted Access</p>
<input id="lU" class="inp" placeholder="Username"><input id="lP" class="inp" type="password" placeholder="Password" onkeydown="if(event.key==='Enter')doLogin()">
<button class="lbtn" onclick="doLogin()">🔓 Login</button><button class="lbtn sec" onclick="ss(2)">Forgot Password?</button><div class="errmsg" id="lE"></div></div>
<div id="s2" class="step"><span class="ic">📧</span><h2>Forgot Password</h2><p>Enter username &amp; email</p>
<input id="fU" class="inp" placeholder="Username"><input id="fE" class="inp" type="email" placeholder="Email">
<button class="lbtn" onclick="sendOTP()">📨 Send OTP</button><button class="lbtn sec" onclick="ss(1)">← Back</button><div class="errmsg" id="fErr"></div></div>
<div id="s3" class="step"><span class="ic">🔢</span><h2>Enter OTP</h2><p>6-digit code • 3 minutes</p>
<input id="oI" class="inp otp-i" maxlength="6" placeholder="000000" onkeydown="if(event.key==='Enter')vOTP()">
<div class="tmr" id="oTmr">3:00</div>
<button class="lbtn" onclick="vOTP()">✅ Verify</button><button class="lbtn sec" onclick="sendOTP()">Resend</button><button class="lbtn sec" onclick="ss(1)">← Back</button><div class="errmsg" id="oE"></div></div>
<div id="s4" class="step"><span class="ic">🔑</span><h2>New Password</h2>
<input id="n1" class="inp" type="password" placeholder="New Password"><input id="n2" class="inp" type="password" placeholder="Confirm" onkeydown="if(event.key==='Enter')doReset()">
<button class="lbtn" onclick="doReset()">Reset Password</button><div class="errmsg" id="rE"></div><div class="okmsg" id="rO"></div></div>
</div></div>

<!-- SIDEBAR -->
<aside class="sidebar" id="sidebarEl" style="display:none">
<div class="sb-logo"><h1>🔒 SecureFIM Pro</h1><span data-i18n="sb.subtitle">Admin Panel — Port 8444</span></div>
<div class="sb-section">
<div class="nav-i active" onclick="sw('sys',this)" data-i18n="nav.sys">🖥️ System Health</div>
<div class="nav-i" onclick="sw('os',this)" data-i18n="nav.os">🗄️ OpenSearch</div>
<div class="nav-i" onclick="sw('agt',this)" data-i18n="nav.agt">💻 Agent Health</div>
<div class="nav-i" onclick="sw('path',this)" data-i18n="nav.path">📂 Path Management</div>
</div><div class="sb-section">
<div class="nav-i" onclick="sw('watch',this)" data-i18n="nav.watch">👁️ Watchlist</div>
<div class="nav-i" onclick="sw('baseline',this)" data-i18n="nav.baseline">📋 Baselines</div>
<div class="nav-i" onclick="sw('backup',this)" data-i18n="nav.backup">💾 Backups & Restore</div>
<div class="nav-i" onclick="sw('ml',this)" data-i18n="nav.ml">🤖 ML Model</div>
<div class="nav-i" onclick="sw('disc',this)" data-i18n="nav.disc">💬 Discord</div>
<div class="nav-i" onclick="sw('email',this)" data-i18n="nav.email">📧 Email Alerts</div>
<div class="nav-i" onclick="sw('alerts',this)" data-i18n="nav.alerts">🔔 Alerts</div>
<div class="nav-i" onclick="sw('reports',this)" data-i18n="nav.reports">📄 Compliance Reports</div>
</div><div class="sb-section">
<div class="nav-i" onclick="sw('data',this)" data-i18n="nav.data">⚙️ Data Management</div>
<div class="nav-i" onclick="sw('users',this)" data-i18n="nav.users">👤 User Management</div>
<div class="nav-i" onclick="sw('log',this)" data-i18n="nav.log">📝 Audit Log</div>
</div>
<div class="sb-user">
<div class="name" id="sUsr">—</div><div class="role" data-i18n="sb.role">Administrator</div>
<button class="logout-btn" onclick="doLogout()" data-i18n="sb.logout">🔓 Logout</button>
<button class="theme-btn" onclick="tglTheme()" id="thBtn">🌙 Dark Mode</button>
<button class="theme-btn" onclick="tglLang()" id="lngBtn" style="margin-top:6px">🇳🇵 नेपाली</button>
</div></aside>

<!-- MAIN -->
<div class="main" id="mainEl" style="display:none">
<div class="panel active" id="t-sys"><h2 style="margin-bottom:16px" data-i18n="panel.sys">System Health</h2>
<div class="grid">
<div class="card"><div class="l">Server</div><div class="v" style="color:var(--grn)" id="xSt">Online</div><div class="s" id="xUp"></div></div>
<div class="card"><div class="l">OpenSearch</div><div class="v" id="xOs">—</div><div class="s" id="xOsS"></div></div>
<div class="card"><div class="l">Agents</div><div class="v" id="xAg">0</div></div>
<div class="card"><div class="l">Events</div><div class="v" id="xEv">0</div></div>
<div class="card"><div class="l">Memory</div><div class="v" id="xMe">—</div><div class="s" id="xMeS"></div></div>
<div class="card"><div class="l">CPU</div><div class="v" id="xCp">—</div></div>
<div class="card"><div class="l">Disk</div><div class="v" id="xDi">—</div><div class="s" id="xDiS"></div></div>
<div class="card"><div class="l">PID</div><div class="v" id="xPi">—</div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
<div class="sec"><div class="sec-h">📈 Event Timeline (1 hour)</div><div class="sec-b" style="height:220px;padding:10px"><canvas id="admChTime"></canvas></div></div>
<div class="sec"><div class="sec-h">📊 Events by Type</div><div class="sec-b" style="height:220px;padding:10px"><canvas id="admChType"></canvas></div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<div class="sec"><div class="sec-h">🔴 Severity Distribution</div><div class="sec-b" style="height:220px;padding:10px"><canvas id="admChSev"></canvas></div></div>
<div class="sec"><div class="sec-h">🗄️ Index Document Counts</div><div class="sec-b" style="height:220px;padding:10px"><canvas id="admChIdx"></canvas></div></div>
</div>
</div>

<div class="panel" id="t-os"><h2 style="margin-bottom:16px" data-i18n="panel.os">OpenSearch Indices</h2>
<div class="sec"><div class="sec-h">📊 Index Size Comparison</div><div class="sec-b" style="height:200px;padding:10px"><canvas id="admChIdxBar"></canvas></div></div>
<div class="sec"><div class="sec-b np"><table><thead><tr><th>Index</th><th>Docs</th><th>Status</th><th>Actions</th></tr></thead><tbody id="tIdx"></tbody></table></div></div></div>

<div class="panel" id="t-agt"><h2 style="margin-bottom:16px" data-i18n="panel.agt">Agent Health</h2>
<div class="sec"><div class="sec-b np"><table><thead><tr><th>Agent</th><th>Host</th><th>Status</th><th>CPU</th><th>Mem</th><th>Disk</th></tr></thead><tbody id="tAg"></tbody></table></div></div></div>

<div class="panel" id="t-path"><h2 style="margin-bottom:16px" data-i18n="panel.path">Path Management</h2>
<div class="sec"><div class="sec-b"><div style="display:flex;gap:8px;margin-bottom:12px"><select id="pS" class="btn"><option value="">Agent</option></select><input id="pI" class="inp" style="flex:1;margin:0" placeholder="Path"><button class="btn btn-p" onclick="addP()">+ Add</button></div>
<table><thead><tr><th>Agent</th><th>Path</th><th></th></tr></thead><tbody id="tPa"></tbody></table></div></div></div>

<div class="panel" id="t-watch"><h2 style="margin-bottom:16px" data-i18n="panel.watch">Watchlist Management</h2>
<div class="sec"><div class="sec-h">👁️ Add to Watchlist</div><div class="sec-b">
<div style="display:grid;grid-template-columns:2fr 1fr 2fr;gap:8px;margin-bottom:12px">
<input id="wPath" class="inp" placeholder="File path to watch" style="margin:0">
<select id="wSens" class="btn"><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select>
<input id="wDesc" class="inp" placeholder="Description (optional)" style="margin:0">
</div>
<button class="btn btn-p" onclick="addWatch()">+ Add to Watchlist</button><span class="res" id="wR"></span>
</div></div>
<div class="sec"><div class="sec-h">📋 Watched Files</div><div class="sec-b np">
<table><thead><tr><th>Path</th><th>Sensitivity</th><th>Description</th><th>Auto Alert</th><th>Added</th><th></th></tr></thead><tbody id="tWa"></tbody></table>
</div></div></div>

<div class="panel" id="t-baseline"><h2 style="margin-bottom:16px" data-i18n="panel.baseline">Baseline Management</h2>
<div class="sec"><div class="sec-h">📋 Create Baseline</div><div class="sec-b">
<p style="color:var(--dim);font-size:12px;margin-bottom:12px">Baselines capture a known-good state of files. The agent sends current file hashes which are stored. Later you can verify integrity by comparing against the baseline.</p>
<div style="display:flex;gap:8px;margin-bottom:12px">
<select id="blAgent" class="btn"><option value="">Agent</option></select>
<input id="blName" class="inp" placeholder="Baseline name" style="margin:0;flex:1">
<button class="btn btn-p" onclick="createBL()">📸 Create Baseline</button>
</div>
<span class="res" id="blR"></span>
</div></div>
<div class="sec"><div class="sec-h">✅ Verify Baseline</div><div class="sec-b">
<div style="display:flex;gap:8px;margin-bottom:12px">
<input id="blVerifyName" class="inp" placeholder="Baseline name to verify" style="margin:0;flex:1">
<button class="btn btn-p" onclick="verifyBL()">🔍 Verify</button>
</div>
<div id="blVerifyResult"></div>
</div></div>
<div class="sec"><div class="sec-h">⏰ Scheduled Verification<button class="btn" onclick="lSchedules()" style="padding:3px 10px;font-size:10px;float:right">↻ Refresh</button></div>
<div class="sec-b">
<p style="color:var(--dim);font-size:12px;margin-bottom:12px">
Configure automatic periodic verification. When enabled, the server asks the agent to re-hash all files in the baseline at the chosen frequency. If any file differs from the baseline, a <strong style="color:var(--red)">CRITICAL drift alert</strong> is raised (dashboard + Discord + email) and stored in verification history.
</p>
<table><thead><tr><th>Baseline</th><th>Agent</th><th>Files</th><th>Enable</th><th>Frequency</th><th>Next Verify</th><th>Last Result</th><th>Action</th></tr></thead><tbody id="tSched"></tbody></table>
</div></div>
<div class="sec"><div class="sec-h">📜 Verification History<button class="btn" onclick="lVerifyHist()" style="padding:3px 10px;font-size:10px;float:right">↻ Refresh</button></div>
<div class="sec-b np">
<table><thead><tr><th>Time</th><th>Baseline</th><th>Agent</th><th>Integrity</th><th>Modified</th><th>Deleted</th><th>New</th><th>Status</th></tr></thead><tbody id="tVerifyHist"></tbody></table>
</div></div>
<div class="sec"><div class="sec-h">📂 Stored Baselines</div><div class="sec-b np">
<table><thead><tr><th>Name</th><th>Agent</th><th>File</th><th>Hash</th><th>Size</th><th>Status</th><th>Created</th></tr></thead><tbody id="tBl"></tbody></table>
</div></div></div>

<div class="panel" id="t-backup"><h2 style="margin-bottom:16px" data-i18n="panel.backup">Backups & File Recovery</h2>
<div class="sec"><div class="sec-h">💾 About Backups</div><div class="sec-b">
<p style="color:var(--dim);font-size:12px;line-height:1.6">
SecureFIM Pro automatically creates backups of <strong>sensitive files</strong> (citizenship records, land records, passwords, database files, exam results, patient records, etc.) every time they are created or modified. If a file is tampered with, deleted, or encrypted by ransomware, you can restore it from the backup.<br><br>
<strong>Backup location on agent machines:</strong> <code>~/.securefim_backup/</code> (per-user home directory)<br>
<strong>Backup format:</strong> <code>filename.YYYYMMDD_HHMMSS.HASH.bak</code><br>
<strong>Retention:</strong> Backups are never auto-deleted by default.<br><br>
<strong style="color:var(--grn)">🟢 Which version to restore?</strong> Each file has multiple backups — one per change (create, modify). <strong>Version 1 (v1 🟢 highlighted in green)</strong> is the <strong>original</strong> — the version created before any tampering. Restoring v1 undoes all changes. Higher versions are snapshots taken after each modification, in case the tampering happened later.
</p>
</div></div>
<div class="sec"><div class="sec-h">🔄 Available Backups<button class="btn" onclick="lBackups()" style="padding:3px 10px;font-size:10px;float:right">↻ Refresh</button></div>
<div class="sec-b np">
<table><thead><tr><th>Time</th><th>Version</th><th>Event</th><th>Agent</th><th>User</th><th>Original File</th><th>Backup Path</th><th>Sensitivity</th><th>Action</th></tr></thead><tbody id="tBackup"></tbody></table>
</div></div></div>

<div class="panel" id="t-ml"><h2 style="margin-bottom:16px" data-i18n="panel.ml">ML Model — One-Class SVM</h2>
<div class="sec"><div class="sec-b"><div style="display:flex;align-items:center;gap:8px;margin-bottom:12px"><span class="dot" id="mD"></span><span id="mT">Loading</span></div>
<p style="color:var(--dim);font-size:13px;margin-bottom:14px">Trains on normal activity. Detects anomalies using 11 features.</p>
<button class="btn btn-p" onclick="mlTr()">🧠 Train</button> <button class="btn btn-d" onclick="mlRs()">🗑 Reset</button><div class="res" id="mR"></div></div></div></div>

<div class="panel" id="t-disc"><h2 style="margin-bottom:16px" data-i18n="panel.disc">Discord Integration</h2>
<div class="sec"><div class="sec-b"><div id="dR" style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px"></div>
<button class="btn btn-p" onclick="dTst()">🧪 Test Alert</button><div class="res" id="dRes"></div></div></div></div>

<div class="panel" id="t-email"><h2 style="margin-bottom:16px" data-i18n="panel.email">Email Alert Configuration</h2>
<div class="sec"><div class="sec-h">📧 About Email Alerts</div><div class="sec-b">
<p style="color:var(--dim);font-size:12px;line-height:1.6">
Send email alerts for critical security events using the same Gmail SMTP configured for OTP password reset. Emails are queued and sent by a background worker with rate limiting to prevent email storms during ransomware bursts.<br><br>
<strong>SMTP config:</strong> <code>data/email_config.json</code> (shared with OTP)<br>
<strong>Alert settings:</strong> <code>data/email_alerts_config.json</code> (managed here)
</p>
</div></div>
<div class="sec"><div class="sec-h">⚙️ Status &amp; Controls</div><div class="sec-b">
<div id="emStatus" style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;font-size:12px"></div>
<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
<label style="display:flex;align-items:center;gap:6px;cursor:pointer">
<input type="checkbox" id="emEnabled" onchange="emSaveCfg()"> <strong>Enable email alerts</strong>
</label>
</div>
<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
<span style="font-size:12px">Minimum severity:</span>
<select id="emMinSev" class="btn" onchange="emSaveCfg()" style="margin:0">
<option value="info">Info and above</option>
<option value="warning">Warning and above</option>
<option value="critical" selected>Critical and above</option>
<option value="ransomware">Ransomware only</option>
</select>
<span style="font-size:12px;margin-left:16px">Throttle (per minute):</span>
<input id="emThrottle" class="inp" type="number" value="10" min="1" max="100" onchange="emSaveCfg()" style="width:70px;margin:0">
</div>
<div class="res" id="emR"></div>
</div></div>
<div class="sec"><div class="sec-h">📨 Recipients</div><div class="sec-b">
<div style="display:flex;gap:8px;margin-bottom:10px">
<input id="emNewEmail" class="inp" placeholder="email@example.com" style="margin:0;flex:1">
<button class="btn btn-p" onclick="emAddRecip()">➕ Add</button>
</div>
<div id="emRecipients" style="display:flex;gap:6px;flex-wrap:wrap"></div>
</div></div>
<div class="sec"><div class="sec-h">🔔 Alert Types</div><div class="sec-b">
<p style="color:var(--dim);font-size:11px;margin-bottom:10px">Which event categories should trigger emails.</p>
<div id="emAlertTypes" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px"></div>
</div></div>
<div class="sec"><div class="sec-h">🧪 Test Email</div><div class="sec-b">
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px">
<input id="emTestTo" class="inp" placeholder="Optional: override recipient (else uses first configured)" style="margin:0;flex:1">
<button class="btn btn-p" onclick="emSendTest()">📤 Send Test Email</button>
</div>
<div class="res" id="emTestR"></div>
</div></div></div>

<div class="panel" id="t-alerts"><h2 style="margin-bottom:16px" data-i18n="panel.alerts">Alert Management</h2>
<div class="sec"><div class="sec-h">📊 Alert Types</div><div class="sec-b" style="height:180px;padding:10px"><canvas id="admChAlert"></canvas></div></div>
<div class="sec"><div class="sec-b"><div style="display:flex;gap:8px;margin-bottom:12px"><button class="btn btn-p" onclick="ackA()">✅ Ack All</button><button class="btn btn-d" onclick="clr('fim-alerts')">🗑 Clear Alerts</button><button class="btn btn-d" onclick="clr('fim-events')">🗑 Clear Events</button><button class="btn btn-d" onclick="clr('fim-anomalies')">🗑 Clear Anomalies</button><span class="res" id="aR"></span></div>
<table><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Message</th><th>Status</th></tr></thead><tbody id="tAl"></tbody></table></div></div></div>

<div class="panel" id="t-reports"><h2 style="margin-bottom:16px" data-i18n="panel.reports">Compliance Reports</h2>
<div class="sec"><div class="sec-h">📄 About Compliance Reports</div><div class="sec-b">
<p style="color:var(--dim);font-size:12px;line-height:1.6">
Generate auditor-ready PDF reports covering file integrity monitoring, threat intelligence, sensitive file activity, ransomware indicators, and baseline status. Reports are aligned with the <strong>Nepal NCSC 102-point advisory (January 2025)</strong> and mapped to <strong>Cyber Kill Chain</strong> phases used in the thesis framework.<br><br>
Generated reports are saved to <code>data/reports/</code> and listed below for re-download.
</p>
</div></div>
<div class="sec"><div class="sec-h">🛠 Generate New Report</div><div class="sec-b">
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
<button class="btn btn-p" onclick="genReport('weekly')">📅 Weekly (last 7 days)</button>
<button class="btn btn-p" onclick="genReport('monthly')">📆 Monthly (last 30 days)</button>
</div>
<div style="border-top:1px solid var(--bdr);padding-top:10px;margin-top:6px">
<div style="font-size:12px;color:var(--dim);margin-bottom:6px">Custom date range:</div>
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
<input id="rptStart" class="inp" type="datetime-local" style="margin:0">
<span style="font-size:12px;color:var(--dim)">to</span>
<input id="rptEnd" class="inp" type="datetime-local" style="margin:0">
<button class="btn btn-p" onclick="genReportCustom()">📄 Generate Custom</button>
</div>
</div>
<div class="res" id="rptR" style="margin-top:10px"></div>
</div></div>
<div class="sec"><div class="sec-h">📚 Generated Reports<button class="btn" onclick="lReports()" style="padding:3px 10px;font-size:10px;float:right">↻ Refresh</button></div>
<div class="sec-b np">
<table><thead><tr><th>Filename</th><th>Generated</th><th>Size</th><th>Action</th></tr></thead><tbody id="tReports"></tbody></table>
</div></div></div>

<div class="panel" id="t-data"><h2 style="margin-bottom:16px" data-i18n="panel.data">Data Management</h2>
<div class="sec"><div class="sec-h">📅 Data Retention</div><div class="sec-b">
<p style="color:var(--dim);font-size:12px;margin-bottom:12px">Delete events older than a specified number of days across all indices.</p>
<div style="display:flex;gap:8px;align-items:center;margin-bottom:12px">
<span style="font-size:12px">Delete events older than</span>
<input id="retDays" class="inp" type="number" value="30" min="1" max="365" style="width:80px;margin:0">
<span style="font-size:12px">days</span>
<button class="btn btn-d" onclick="applyRet()">🗑 Apply Retention</button>
</div>
<div class="res" id="retR"></div>
</div></div>
<div class="sec"><div class="sec-h">📥 Export</div><div class="sec-b">
<div style="display:flex;gap:8px;flex-wrap:wrap">
<button class="btn" onclick="expE()" style="padding:10px">📥 Export JSON</button>
<button class="btn" onclick="expCSV()" style="padding:10px">📊 Export CSV</button>
</div></div></div>
<div class="sec"><div class="sec-h">🗑 Clear Data</div><div class="sec-b">
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px">
<button class="btn btn-d" onclick="clr('fim-events')" style="padding:10px">Events</button>
<button class="btn btn-d" onclick="clr('fim-anomalies')" style="padding:10px">Anomalies</button>
<button class="btn btn-d" onclick="clr('fim-alerts')" style="padding:10px">Alerts</button>
<button class="btn btn-d" onclick="clr('fim-heartbeats')" style="padding:10px">Heartbeats</button>
<button class="btn btn-d" onclick="clrAll()" style="padding:10px;grid-column:span 2">💥 ALL</button>
</div><div class="res" id="daR"></div></div></div></div>

<div class="panel" id="t-users"><h2 style="margin-bottom:16px" data-i18n="panel.users">User Management</h2>
<div class="sec"><div class="sec-b"><div id="uL" style="margin-bottom:14px;display:flex;gap:6px;flex-wrap:wrap"></div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<div style="background:var(--bg);padding:14px;border-radius:8px;border:1px solid var(--bdr)"><strong style="font-size:12px">🔑 Change Password</strong>
<input id="cU" class="inp" placeholder="Username" style="margin-top:8px"><input id="cC" class="inp" type="password" placeholder="Current"><input id="cN" class="inp" type="password" placeholder="New">
<button class="btn btn-p" onclick="chPw()" style="width:100%">Change</button><div class="res" id="cR"></div></div>
<div style="background:var(--bg);padding:14px;border-radius:8px;border:1px solid var(--bdr)"><strong style="font-size:12px">➕ Add Admin</strong>
<input id="aU" class="inp" placeholder="Your Username" style="margin-top:8px"><input id="aP" class="inp" type="password" placeholder="Your Password"><input id="nU" class="inp" placeholder="New Username"><input id="nP" class="inp" type="password" placeholder="New Password">
<button class="btn btn-p" onclick="addU()" style="width:100%">Add</button><div class="res" id="aR2"></div></div>
</div></div></div></div>

<div class="panel" id="t-log"><h2 style="margin-bottom:16px" data-i18n="panel.log">Audit Log</h2>
<div class="sec"><div class="sec-b np" id="auF" style="max-height:500px;overflow-y:auto"><div class="empty">No actions yet</div></div></div></div>
</div>

<script>
const A='/admin-api';let fpU='',oTm=null,ADM_TOKEN='';
(function(){const _f=window.fetch;window.fetch=function(u,o){o=o||{};if(typeof u==='string'&&u.indexOf('/admin-api')!==-1&&ADM_TOKEN){o.headers=Object.assign({},o.headers,{'X-Admin-Token':ADM_TOKEN});}return _f(u,o);};})();
function $(id){return document.getElementById(id)}
function esc(s){const d=document.createElement('div');d.textContent=String(s||'');return d.innerHTML}
function ft(t){if(!t)return'—';try{return new Date(t).toLocaleString()}catch(e){return t}}
function fD(s){if(!s)return'—';const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h?h+'h '+m+'m':m+'m'}
function ss(n){for(let i=1;i<=4;i++)$('s'+i).className='step';$('s'+n).className='step active'}

function logA(m){const f=$('auF');if(f.querySelector('.empty'))f.innerHTML='';const d=document.createElement('div');d.className='feed-i';d.innerHTML=`<span style="color:var(--dim)">${new Date().toLocaleTimeString()}</span> — ${esc(m)}`;f.prepend(d);while(f.children.length>50)f.lastChild.remove()}

async function doLogin(){const u=$('lU').value.trim(),p=$('lP').value;$('lE').textContent='';if(!u||!p){$('lE').textContent='Required';return}
const r=await fetch(A+'/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});const d=await r.json();
if(d.status==='ok'){ADM_TOKEN=d.token||'';$('loginO').classList.add('hidden');$('sidebarEl').style.display='flex';$('mainEl').style.display='block';$('sUsr').textContent=d.username;logA('Login: '+u);loadAll()}
else $('lE').textContent=d.error||'Failed'}
function doLogout(){$('loginO').classList.remove('hidden');$('sidebarEl').style.display='none';$('mainEl').style.display='none';ss(1);logA('Logout');
// Clear all password and input fields
['lU','lP','fU','fE','oI','n1','n2','cU','cC','cN','aU','aP','nU','nP'].forEach(id=>{const e=$(id);if(e)e.value=''});
['lE','fErr','oE','rE','rO','cR','aR2','mR','dRes','aR','daR'].forEach(id=>{const e=$(id);if(e)e.textContent=''})}

async function sendOTP(){fpU=$('fU').value.trim();const em=$('fE').value.trim();$('fErr').textContent='';if(!fpU||!em){$('fErr').textContent='Required';return}
const r=await fetch(A+'/forgot-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:fpU,email:em})});const d=await r.json();
if(d.status==='ok'){ss(3);let s=180;if(oTm)clearInterval(oTm);$('oTmr').style.color='var(--yel)';oTm=setInterval(()=>{s--;$('oTmr').textContent=Math.floor(s/60)+':'+String(s%60).padStart(2,'0');if(s<=30)$('oTmr').style.color='var(--red)';if(s<=0){clearInterval(oTm);$('oTmr').textContent='Expired'}},1000)}else $('fErr').textContent=d.error||'Failed'}

async function vOTP(){const o=$('oI').value.trim();$('oE').textContent='';if(o.length!==6){$('oE').textContent='6 digits';return}
const r=await fetch(A+'/verify-otp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:fpU,otp:o})});const d=await r.json();
if(d.status==='ok'){clearInterval(oTm);ss(4)}else $('oE').textContent=d.error||'Failed'}

async function doReset(){const p1=$('n1').value,p2=$('n2').value;$('rE').textContent='';$('rO').textContent='';if(p1!==p2){$('rE').textContent='Mismatch';return}if(p1.length<4){$('rE').textContent='Min 4';return}
const r=await fetch(A+'/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:fpU,new_password:p1})});const d=await r.json();
if(d.status==='ok'){$('rO').textContent='✅ Reset! Login now.';setTimeout(()=>ss(1),2000)}else $('rE').textContent=d.error||'Failed'}

function sw(id,btn){document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.nav-i').forEach(n=>n.classList.remove('active'));$('t-'+id).classList.add('active');if(btn)btn.classList.add('active');logA('Tab: '+id)}

function tglTheme(){const d=document.documentElement,isL=d.getAttribute('data-theme')==='light';d.setAttribute('data-theme',isL?'':'light');$('thBtn').textContent=isL?'🌙 Dark Mode':'☀️ Light Mode';localStorage.setItem('admTheme',isL?'dark':'light')}
if(localStorage.getItem('admTheme')==='light'){document.documentElement.setAttribute('data-theme','light');$('thBtn').textContent='☀️ Light Mode'}

// ── Internationalization (v7.7) ─────────────────────────────────────────
const I18N = {
  en: {
    "sb.subtitle":   "Admin Panel — Port 8444",
    "sb.role":       "Administrator",
    "sb.logout":     "🔓 Logout",
    "nav.sys":       " System Health",
    "nav.os":        " OpenSearch",
    "nav.agt":       " Agent Health",
    "nav.path":      " Path Management",
    "nav.watch":     " Watchlist",
    "nav.baseline":  " Baselines",
    "nav.backup":    " Backups & Restore",
    "nav.ml":        " ML Model",
    "nav.disc":      " Discord",
    "nav.email":     " Email Alerts",
    "nav.alerts":    " Alerts",
    "nav.reports":   " Compliance Reports",
    "nav.data":      " Data Management",
    "nav.users":     " User Management",
    "nav.log":       " Audit Log",
    "panel.sys":     "System Health",
    "panel.os":      "OpenSearch Indices",
    "panel.agt":     "Agent Health",
    "panel.path":    "Path Management",
    "panel.watch":   "Watchlist Management",
    "panel.baseline":"Baseline Management",
    "panel.backup":  "Backups & File Recovery",
    "panel.ml":      "ML Model — One-Class SVM",
    "panel.disc":    "Discord Integration",
    "panel.email":   "Email Alert Configuration",
    "panel.alerts":  "Alert Management",
    "panel.reports": "Compliance Reports",
    "panel.data":    "Data Management",
    "panel.users":   "User Management",
    "panel.log":     "Audit Log",
    "btn.dark":      "🌙 Dark Mode",
    "btn.light":     "☀️ Light Mode",
    "btn.lang.np":   "🇳🇵 नेपाली",
    "btn.lang.en":   "🇬🇧 English",
  },
  np: {
    "sb.subtitle":   "व्यवस्थापक प्यानल — पोर्ट 8444",
    "sb.role":       "व्यवस्थापक",
    "sb.logout":     " 🔓लगआउट",
    "nav.sys":       " प्रणाली स्वास्थ्य",
    "nav.os":        " ओपनसर्च",
    "nav.agt":       " एजेन्ट स्वास्थ्य",
    "nav.path":      " मार्ग व्यवस्थापन",
    "nav.watch":     " निगरानी सूची",
    "nav.baseline":  " आधारभूत",
    "nav.backup":    " ब्याकअप र पुनर्स्थापना",
    "nav.ml":        " एमएल मोडेल",
    "nav.disc":      " डिस्कोर्ड",
    "nav.email":     " इमेल सूचना",
    "nav.alerts":    " सतर्कता",
    "nav.reports":   " अनुपालन प्रतिवेदन",
    "nav.data":      " डाटा व्यवस्थापन",
    "nav.users":     " प्रयोगकर्ता व्यवस्थापन",
    "nav.log":       " अडिट लग",
    "panel.sys":     "प्रणाली स्वास्थ्य",
    "panel.os":      "ओपनसर्च सूचकांक",
    "panel.agt":     "एजेन्ट स्वास्थ्य",
    "panel.path":    "मार्ग व्यवस्थापन",
    "panel.watch":   "निगरानी सूची व्यवस्थापन",
    "panel.baseline":"आधारभूत व्यवस्थापन",
    "panel.backup":  "ब्याकअप र फाइल पुनःप्राप्ति",
    "panel.ml":      "एमएल मोडेल — One-Class SVM",
    "panel.disc":    "डिस्कोर्ड एकीकरण",
    "panel.email":   "इमेल सूचना कन्फिगरेसन",
    "panel.alerts":  "सतर्कता व्यवस्थापन",
    "panel.reports": "अनुपालन प्रतिवेदन",
    "panel.data":    "डाटा व्यवस्थापन",
    "panel.users":   "प्रयोगकर्ता व्यवस्थापन",
    "panel.log":     "अडिट लग",
    "btn.dark":      "🌙 डार्क मोड",
    "btn.light":     "☀️ लाइट मोड",
    "btn.lang.np":   "🇳🇵 नेपाली",
    "btn.lang.en":   "🇬🇧 English",
  },
};
let CUR_LANG = localStorage.getItem('admLang') || 'en';
function t(key){return (I18N[CUR_LANG] && I18N[CUR_LANG][key]) || (I18N.en[key]) || key}
function applyI18n(){
  document.querySelectorAll('[data-i18n]').forEach(el=>{
    const k=el.getAttribute('data-i18n');
    const v=t(k);
    if(v) el.textContent=v;
  });
  // Keep theme button in sync with current language
  const isLight=document.documentElement.getAttribute('data-theme')==='light';
  $('thBtn').textContent=isLight?t('btn.light'):t('btn.dark');
  // Language button shows the OTHER language (what clicking will switch TO)
  $('lngBtn').textContent=CUR_LANG==='en'?t('btn.lang.np'):t('btn.lang.en');
  // Set lang attribute on root for accessibility
  document.documentElement.setAttribute('lang',CUR_LANG==='np'?'ne':'en');
}
function tglLang(){
  CUR_LANG = (CUR_LANG==='en')?'np':'en';
  localStorage.setItem('admLang',CUR_LANG);
  applyI18n();
}
// Apply on initial load
applyI18n();


async function loadAll(){lH();lAg();lSum();lUs();lWatch();lBaselines();lBackups();lReports();lEmail();lSchedules();lVerifyHist()}
async function lH(){try{const r=await fetch(A+'/system-health');const d=await r.json();const s=d.server||{},o=d.opensearch||{},ix=d.indices||{};
$('xUp').textContent=fD(s.uptime_seconds);$('xOs').textContent=(o.status||'?').toUpperCase();$('xOs').style.color=o.status==='green'?'var(--grn)':'var(--yel)';$('xOsS').textContent=(o.number_of_nodes||0)+' nodes';
$('xMe').textContent=(s.server_memory_mb||0)+'MB';$('xMeS').textContent=s.memory_used_gb+'GB/'+s.memory_total_gb+'GB';$('xCp').textContent=s.cpu_percent+'%';$('xDi').textContent=s.disk_percent+'%';$('xDiS').textContent=s.disk_used_gb+'GB/'+s.disk_total_gb+'GB';$('xPi').textContent=s.server_pid;
$('tIdx').innerHTML=Object.entries(ix).map(([n,i])=>`<tr><td class="mono">${esc(n)}</td><td><strong>${i.doc_count||0}</strong></td><td>${i.error?'<span class="badge err">Error</span>':'<span class="badge ok">OK</span>'}</td><td>${n!=='fim-agents'?`<button class="btn btn-d" onclick="clr('${n}')" style="padding:2px 8px;font-size:11px">Clear</button>`:'—'}</td></tr>`).join('');updateIdxCharts(ix)}catch(e){}}
async function lAg(){try{const r=await fetch(A+'/agent-health');const d=await r.json();
$('tAg').innerHTML=(d.agents||[]).map(a=>{const h=a.latest_heartbeat||{};return`<tr><td class="mono">${esc(a.agent_id)}</td><td>${esc(a.hostname||'')}</td><td><span class="badge ${a.status==='online'?'ok':'err'}">${a.status||'?'}</span></td><td>${h.cpu_percent!=null?h.cpu_percent.toFixed(1)+'%':'—'}</td><td>${h.memory_percent!=null?h.memory_percent.toFixed(1)+'%':'—'}</td><td>${h.disk_percent!=null?h.disk_percent.toFixed(1)+'%':'—'}</td></tr>`}).join('')||'<tr><td colspan="6" class="empty">None</td></tr>'}catch(e){}}
async function lSum(){try{const r=await fetch(A+'/dashboard-summary');const d=await r.json();
$('xAg').textContent=d.agents_total||0;$('xEv').textContent=(d.event_stats||{}).total||0;
const ags=d.agents||[];const sel=$('pS');sel.innerHTML='<option value="">Agent</option>'+ags.map(a=>`<option value="${esc(a.agent_id)}">${esc(a.agent_id)}</option>`).join('');
const blSel=$('blAgent');if(blSel)blSel.innerHTML='<option value="">Agent</option>'+ags.map(a=>`<option value="${esc(a.agent_id)}">${esc(a.agent_id)}</option>`).join('');
const ps=d.monitored_paths||[];$('tPa').innerHTML=ps.length?ps.map(p=>`<tr><td class="mono">${esc(p.agent_id)}</td><td class="mono">${esc(p.path)}</td><td><button class="btn btn-d" onclick="rmP('${esc(p.agent_id)}','${esc(p.path)}')" style="padding:2px 8px;font-size:11px">✕</button></td></tr>`).join(''):'<tr><td colspan="3" class="empty">None</td></tr>';
const ml=d.ml_status||{};$('mD').className='dot '+(ml.is_trained?'ok':'warn');$('mT').textContent=ml.is_trained?'Trained (One-Class SVM)':'Not trained ('+(ml.training_samples||0)+'/'+(ml.min_required||100)+')';
const dc=d.discord_status||{};$('dR').innerHTML=`<span><span class="dot ${dc.enabled?'ok':'err'}"></span> ${dc.enabled?'Enabled':'Disabled'}</span><span><span class="dot ${dc.token_set?'ok':'err'}"></span> Token: ${dc.token_set?'Set':'No'}</span><span>Type: ${dc.token_type||'—'}</span><span>Queue: ${dc.queue_size||0}</span>`;
const als=d.recent_alerts||[];$('tAl').innerHTML=als.length?als.map(a=>`<tr><td class="mono">${ft(a.timestamp)}</td><td><span class="badge ${a.alert_type==='ransomware'?'err':'info'}">${esc(a.alert_type||'')}</span></td><td><span class="badge ${a.severity==='critical'?'err':'warn'}">${a.severity||''}</span></td><td>${esc(a.message||a.title||'')}</td><td>${a.acknowledged?'<span class="badge ok">✓</span>':'<span class="badge warn">⏳</span>'}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">None</td></tr>';updateCharts(d)}catch(e){}}
async function lUs(){try{const r=await fetch(A+'/list-users');const d=await r.json();$('uL').innerHTML=(d.users||[]).map(u=>`<span class="badge info" style="padding:5px 12px;font-size:12px">👤 ${esc(u)} <button onclick="rmU('${esc(u)}')" style="background:none;border:none;color:var(--red);cursor:pointer;margin-left:3px">✕</button></span>`).join('')}catch(e){}}

async function mlTr(){$('mR').textContent='Training...';logA('ML Train');const r=await fetch(A+'/ml/train',{method:'POST'});const d=await r.json();$('mR').textContent=d.status==='trained'?'✅ Done':'❌ '+(d.error||'');lSum()}
async function mlRs(){if(!confirm('Reset ML?'))return;logA('ML Reset');await fetch(A+'/ml/reset',{method:'POST'});$('mR').textContent='✅ Reset';lSum()}
async function dTst(){logA('Discord test');const r=await fetch(A+'/discord/test',{method:'POST'});const d=await r.json();$('dRes').textContent=d.status==='ok'?'✅ Sent':'❌ '+(d.error||'')}
async function ackA(){logA('Ack all');await fetch(A+'/alerts/acknowledge-all',{method:'POST'});$('aR').textContent='✅';lSum()}
async function clr(i){if(!confirm('Clear '+i+'?'))return;logA('Clear '+i);const r=await fetch(A+'/clear/'+i,{method:'DELETE'});const d=await r.json();$('daR').textContent='✅ '+(d.deleted||0)+' cleared';loadAll()}
async function clrAll(){if(!confirm('Clear ALL?'))return;logA('Clear ALL');for(const i of['fim-events','fim-anomalies','fim-alerts','fim-heartbeats'])await fetch(A+'/clear/'+i,{method:'DELETE'});$('daR').textContent='✅ Done';loadAll()}
async function expE(){logA('Export');const r=await fetch(A+'/export/events?limit=5000');const d=await r.json();const b=new Blob([JSON.stringify(d.events,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='events.json';a.click()}
async function addP(){const ag=$('pS').value,p=$('pI').value.trim();if(!ag||!p){alert('Select agent & path');return}logA('Add: '+p);const r=await fetch(A+'/agents/'+ag+'/paths');const d=await r.json();const ps=d.monitored_paths||[];ps.push(p);await fetch(A+'/agents/'+ag+'/paths',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({monitored_paths:ps})});$('pI').value='';lSum()}
async function rmP(ag,p){if(!confirm('Remove?'))return;logA('Remove: '+p);const r=await fetch(A+'/agents/'+ag+'/paths');const d=await r.json();await fetch(A+'/agents/'+ag+'/paths',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({monitored_paths:(d.monitored_paths||[]).filter(x=>x!==p)})});lSum()}
async function chPw(){const u=$('cU').value.trim(),c=$('cC').value,n=$('cN').value;$('cR').textContent='';const r=await fetch(A+'/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,current_password:c,new_password:n})});const d=await r.json();$('cR').textContent=d.status==='ok'?'✅':'❌ '+(d.error||'');$('cR').style.color=d.status==='ok'?'var(--grn)':'var(--red)';logA('PW change: '+u)}
async function addU(){const au=$('aU').value.trim(),ap=$('aP').value,nu=$('nU').value.trim(),np=$('nP').value;$('aR2').textContent='';const r=await fetch(A+'/add-user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({auth_username:au,auth_password:ap,new_username:nu,new_password:np})});const d=await r.json();$('aR2').textContent=d.status==='ok'?'✅ '+d.message:'❌ '+(d.error||'');$('aR2').style.color=d.status==='ok'?'var(--grn)':'var(--red)';lUs();logA('Add user: '+nu)}
async function rmU(u){if(!confirm('Remove "'+u+'"?'))return;const au=prompt('Your username:');if(!au)return;const ap=prompt('Your password:');if(!ap)return;const r=await fetch(A+'/remove-user',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({auth_username:au,auth_password:ap,remove_username:u})});const d=await r.json();alert(d.status==='ok'?'✅ Removed':'❌ '+(d.error||''));lUs();logA('Remove: '+u)}

// Watchlist
async function lWatch(){try{const r=await fetch('/admin-api/watchlist');const d=await r.json();
$('tWa').innerHTML=(d.items||[]).length?(d.items||[]).map(w=>`<tr><td class="mono">${esc(w.file_path||'')}</td><td><span class="badge ${w.sensitivity||'HIGH'}">${w.sensitivity||'HIGH'}</span></td><td>${esc(w.description||'')}</td><td>${w.auto_alert?'✅':'—'}</td><td class="mono">${ft(w.timestamp)}</td><td><button class="btn btn-d" onclick="rmWatch('${w._id}')" style="padding:2px 8px;font-size:10px">✕</button></td></tr>`).join(''):'<tr><td colspan="6" class="empty">No watched files</td></tr>'}catch(e){}}
async function addWatch(){const p=$('wPath').value.trim(),s=$('wSens').value,d=$('wDesc').value.trim();if(!p){alert('Enter path');return}
logA('Add watchlist: '+p);const r=await fetch('/admin-api/watchlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({file_path:p,sensitivity:s,description:d,auto_alert:true})});const res=await r.json();$('wR').textContent=res.status==='added'?'✅ Added':'❌';$('wPath').value='';$('wDesc').value='';lWatch()}
async function rmWatch(id){if(!confirm('Remove?'))return;logA('Remove watchlist');await fetch('/admin-api/watchlist/'+id,{method:'DELETE'});lWatch()}

// Baselines
async function lBaselines(){try{const r=await fetch('/admin-api/baselines');const d=await r.json();
$('tBl').innerHTML=(d.items||[]).length?(d.items||[]).slice(0,50).map(b=>`<tr><td class="mono">${esc(b.baseline_name||'')}</td><td class="mono">${esc(b.agent_id||'')}</td><td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(b.file_path||'')}</td><td class="mono">${(b.file_hash||'').substring(0,12)}</td><td>${b.file_size||0}</td><td><span class="badge ${b.status==='ok'?'ok':'err'}">${b.status||'?'}</span></td><td class="mono">${ft(b.timestamp)}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">No baselines</td></tr>'}catch(e){}}
async function createBL(){const ag=$('blAgent').value,name=$('blName').value.trim();if(!ag){alert('Select agent');return}if(!name){alert('Enter name');return}
logA('Create baseline: '+name);$('blR').textContent='Creating... (agent will send file data)';
// For now create empty baseline - agent needs to send file hashes
const r=await fetch('/admin-api/baselines/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_id:ag,name:name,files:[]})});
const d=await r.json();$('blR').textContent=d.status==='created'?'✅ Baseline "'+name+'" created ('+d.files+' files)':'❌ '+(d.error||'');lBaselines()}
async function verifyBL(){const name=$('blVerifyName').value.trim();if(!name){alert('Enter baseline name');return}
logA('Verify baseline: '+name);$('blVerifyResult').innerHTML='<span style="color:var(--dim)">Verifying...</span>';
const r=await fetch('/admin-api/baselines/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,files:[]})});
const d=await r.json();
$('blVerifyResult').innerHTML=`<div style="margin-top:8px;font-size:12px">
<strong>Integrity Score: <span style="color:${d.integrity_score>=90?'var(--grn)':d.integrity_score>=50?'var(--yel)':'var(--red)'}">${d.integrity_score||0}%</span></strong><br>
Baseline files: ${d.total_baseline||0} | OK: ${d.ok||0} | Modified: ${(d.modified||[]).length} | Deleted: ${(d.deleted||[]).length} | New: ${(d.new||[]).length}
</div>`}

// Retention
async function applyRet(){const days=parseInt($('retDays').value)||30;if(!confirm('Delete events older than '+days+' days?'))return;
logA('Apply retention: '+days+' days');$('retR').textContent='Applying...';
const r=await fetch('/admin-api/retention',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:days})});
const d=await r.json();if(d.status==='ok'){const total=Object.values(d.deleted||{}).reduce((a,b)=>a+b,0);$('retR').textContent='✅ Deleted '+total+' old documents';$('retR').style.color='var(--grn)'}else{$('retR').textContent='❌ Error';$('retR').style.color='var(--red)'}loadAll()}

// CSV Export
async function expCSV(){logA('Export CSV');window.open('/admin-api/export/csv','_blank')}

// Backups
async function lBackups(){try{const r=await fetch('/admin-api/backups');const d=await r.json();
$('tBackup').innerHTML=(d.items||[]).length?(d.items||[]).map(b=>{const isV1=b.version===1;const verBadge=isV1?`<span class="badge online" title="First version — safest to restore">v${b.version} 🟢</span>`:`<span class="badge" style="background:rgba(88,166,255,.12);color:var(--acc)">v${b.version}</span>`;return `<tr${isV1?' style="background:rgba(63,185,80,.04)"':''}><td class="mono">${ft(b.timestamp)}</td><td>${verBadge}</td><td><span class="badge ${b.event_type||''}">${esc(b.event_type||'')}</span></td><td class="mono">${esc(b.agent_id||'')}</td><td class="mono">${esc(b.username||'unknown')}</td><td class="mono" style="max-width:180px;overflow:hidden;text-overflow:ellipsis" title="${esc(b.file_path)}">${esc(b.file_path||'')}</td><td class="mono" style="max-width:180px;overflow:hidden;text-overflow:ellipsis" title="${esc(b.backup_path)}">${esc(b.backup_path||'')}</td><td><span class="badge ${b.sensitivity||'HIGH'}">${b.sensitivity||'HIGH'}</span></td><td><button class="btn btn-p" onclick="restoreBackup('${b._id}')" style="padding:2px 8px;font-size:10px">🔄 Restore</button></td></tr>`}).join(''):'<tr><td colspan="9" class="empty">No backups available yet. Backups are created automatically when sensitive files change.</td></tr>'}catch(e){$('tBackup').innerHTML='<tr><td colspan="9" class="empty">Error loading backups</td></tr>'}}

async function restoreBackup(eventId){
if(!confirm('Request automatic restore of this file from backup?\n\nThe agent on the source machine will restore it within 15 seconds.'))return;
logA('Request file restore: '+eventId);
const r=await fetch('/admin-api/backups/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({event_id:eventId,requested_by:U})});
const d=await r.json();
if(d.status==='restore_requested'){
alert('✅ Restore request queued!\n\nThe agent will automatically restore the file within 15 seconds.\n\nCheck the Alerts tab for confirmation once complete.\n\nFile: '+d.instructions.split('"')[3]);
lBackups();
}else{
alert('❌ Error: '+(d.error||'Unknown error'));
}
}
// Charts
const chOpts={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}}};
const chOptsLeg={responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:11}}}}};
const chSc={x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(128,128,128,.12)'}},y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(128,128,128,.12)'},beginAtZero:true}};
let acTime,acType,acSev,acIdx,acIdxBar,acAlert;
function initCharts(){
acTime=new Chart($('admChTime'),{type:'line',data:{labels:[],datasets:[{label:'Events',data:[],borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.1)',fill:true,tension:.3,pointRadius:2}]},options:{...chOpts,scales:chSc}});
acType=new Chart($('admChType'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#3fb950','#d29922','#f85149','#58a6ff','#bc8cff','#39d2c0']}]},options:chOptsLeg});
acSev=new Chart($('admChSev'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#58a6ff','#d29922','#f85149']}]},options:chOptsLeg});
acIdx=new Chart($('admChIdx'),{type:'bar',data:{labels:[],datasets:[{label:'Docs',data:[],backgroundColor:['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff']}]},options:{...chOpts,scales:chSc}});
acIdxBar=new Chart($('admChIdxBar'),{type:'bar',data:{labels:[],datasets:[{label:'Documents',data:[],backgroundColor:['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff']}]},options:{...chOpts,indexAxis:'y',scales:{x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(128,128,128,.12)'},beginAtZero:true},y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'rgba(128,128,128,.12)'}}}}});
acAlert=new Chart($('admChAlert'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#f85149','#bc8cff','#d29922','#58a6ff']}]},options:chOptsLeg});
}
function updateCharts(d){
const s=d.event_stats||{},bt=s.by_type||{},bs=s.by_severity||{},ot=s.over_time||[];
if(acTime&&ot.length){acTime.data.labels=ot.map(b=>{try{const t=new Date(b.time);return t.getHours()+':'+String(t.getMinutes()).padStart(2,'0')}catch(e){return''}});acTime.data.datasets[0].data=ot.map(b=>b.count);acTime.update('none')}
if(acType&&Object.keys(bt).length){acType.data.labels=Object.keys(bt);acType.data.datasets[0].data=Object.values(bt);acType.update('none')}
if(acSev&&Object.keys(bs).length){acSev.data.labels=Object.keys(bs);acSev.data.datasets[0].data=Object.values(bs);acSev.update('none')}
// Alert type chart
const als=d.recent_alerts||[];const alTypes={};als.forEach(a=>{const t=a.alert_type||'other';alTypes[t]=(alTypes[t]||0)+1});
if(acAlert&&Object.keys(alTypes).length){acAlert.data.labels=Object.keys(alTypes);acAlert.data.datasets[0].data=Object.values(alTypes);acAlert.update('none')}
}
function updateIdxCharts(idx){
if(!idx)return;const names=Object.keys(idx),counts=Object.values(idx).map(v=>v.doc_count||0);
if(acIdx){acIdx.data.labels=names.map(n=>n.replace('fim-',''));acIdx.data.datasets[0].data=counts;acIdx.update('none')}
if(acIdxBar){acIdxBar.data.labels=names;acIdxBar.data.datasets[0].data=counts;acIdxBar.update('none')}
}
// Compliance Reports
async function lReports(){
  try{
    const r=await fetch(A+'/reports/list');const d=await r.json();const rows=(d.reports||[]);
    const tbody=$('tReports');if(!tbody)return;
    if(!rows.length){tbody.innerHTML='<tr><td colspan="4" class="empty">No reports generated yet</td></tr>';return}
    tbody.innerHTML=rows.map(r=>{
      const ts=r.mtime?new Date(r.mtime).toLocaleString():'-';
      const sz=r.size?(r.size/1024).toFixed(1)+' KB':'-';
      const dlUrl=A+'/reports/download/'+encodeURIComponent(r.filename);
      return `<tr><td class="mono" style="font-size:11px">${esc(r.filename)}</td><td>${esc(ts)}</td><td>${sz}</td><td><a class="btn btn-p" href="${dlUrl}" target="_blank" style="padding:3px 10px;font-size:11px">⬇ Download</a> <button class="btn btn-d" onclick="delReport('${esc(r.filename)}')" style="padding:3px 10px;font-size:11px">🗑</button></td></tr>`;
    }).join('');
  }catch(e){}
}
async function genReport(period){
  const btn=event&&event.target;if(btn){btn.disabled=true;btn.textContent='⏳ Generating...'}
  $('rptR').innerHTML='<span style="color:var(--dim)">Generating '+period+' report. This may take a few seconds...</span>';
  try{
    const r=await fetch(A+'/reports/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({period:period,generated_by:$('sUsr').textContent||'admin'})});
    const d=await r.json();
    if(d.status==='ok'){
      const s=d.summary||{};
      $('rptR').innerHTML='<span style="color:var(--grn)">✅ Generated: <strong>'+esc(d.filename)+'</strong></span><br><span style="color:var(--dim);font-size:11px">'+s.total_events+' events · '+s.critical_events+' critical · '+s.high_sens_count+' HIGH-sensitivity · '+(d.bytes/1024).toFixed(1)+' KB</span>';
      logA('Report generated: '+d.report_id);lReports();
    }else{$('rptR').innerHTML='<span style="color:var(--red)">❌ '+esc(d.error||'Failed')+'</span>'}
  }catch(e){$('rptR').innerHTML='<span style="color:var(--red)">❌ '+esc(String(e))+'</span>'}
  if(btn){btn.disabled=false;btn.textContent=period==='weekly'?'📅 Weekly (last 7 days)':'📆 Monthly (last 30 days)'}
}
async function genReportCustom(){
  const s=$('rptStart').value,e=$('rptEnd').value;
  if(!s||!e){$('rptR').innerHTML='<span style="color:var(--red)">❌ Pick both start and end</span>';return}
  const startISO=new Date(s).toISOString(),endISO=new Date(e).toISOString();
  if(new Date(startISO)>=new Date(endISO)){$('rptR').innerHTML='<span style="color:var(--red)">❌ Start must be before end</span>';return}
  $('rptR').innerHTML='<span style="color:var(--dim)">Generating custom report...</span>';
  try{
    const r=await fetch(A+'/reports/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({period:'custom',start:startISO,end:endISO,generated_by:$('sUsr').textContent||'admin'})});
    const d=await r.json();
    if(d.status==='ok'){
      const sm=d.summary||{};
      $('rptR').innerHTML='<span style="color:var(--grn)">✅ '+esc(d.filename)+'</span> <span style="color:var(--dim);font-size:11px">('+sm.total_events+' events, '+(d.bytes/1024).toFixed(1)+' KB)</span>';
      logA('Custom report generated: '+d.report_id);lReports();
    }else{$('rptR').innerHTML='<span style="color:var(--red)">❌ '+esc(d.error||'Failed')+'</span>'}
  }catch(err){$('rptR').innerHTML='<span style="color:var(--red)">❌ '+esc(String(err))+'</span>'}
}
async function delReport(fn){
  if(!confirm('Delete report '+fn+'?'))return;
  try{await fetch(A+'/reports/delete/'+encodeURIComponent(fn),{method:'DELETE'});logA('Report deleted: '+fn);lReports()}catch(e){}
}
// Email Alerts
const EM_TYPE_LABELS={
  ransomware:'🔴 Ransomware detections',
  critical_threat:'⚠️ Critical threat events',
  watchlist_match:'👁️ Watchlist file matches',
  anomaly:'🚨 ML anomalies',
  agent_offline:'💻 Agent offline',
  restore_complete:'🔄 Restore completed',
  test:'🧪 Test emails'
};
async function lEmail(){
  try{
    const r=await fetch(A+'/email-alerts/config');const d=await r.json();if(d.error)return;
    const cfg=d.config||{};
    $('emEnabled').checked=!!cfg.enabled;
    $('emMinSev').value=cfg.min_severity||'critical';
    $('emThrottle').value=cfg.throttle_per_minute||10;
    // Recipients chips
    const recips=cfg.recipients||[];
    $('emRecipients').innerHTML=recips.length?recips.map(e=>`<span class="badge" style="display:inline-flex;align-items:center;gap:6px;padding:4px 10px"><span>${esc(e)}</span><button onclick="emRemoveRecip('${esc(e)}')" style="background:none;border:none;color:var(--red);cursor:pointer;padding:0;font-size:14px;line-height:1">×</button></span>`).join(''):'<span style="color:var(--dim);font-size:12px">No recipients configured</span>';
    // Alert type checkboxes
    const types=cfg.alert_types||{};
    $('emAlertTypes').innerHTML=Object.keys(EM_TYPE_LABELS).map(k=>{const ch=types[k]?'checked':'';return `<label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:6px 8px;border:1px solid var(--bdr);border-radius:4px;font-size:12px"><input type="checkbox" data-em-type="${k}" ${ch} onchange="emSaveCfg()"> ${EM_TYPE_LABELS[k]}</label>`}).join('');
    // Status line
    const sr=await fetch(A+'/email-alerts/status');const s=await sr.json();if(!s.error){
      $('emStatus').innerHTML=[
        '<span class="badge '+(s.enabled?'ok':'err')+'">'+(s.enabled?'Enabled':'Disabled')+'</span>',
        '<span class="badge '+(s.smtp_ready?'ok':'err')+'">SMTP '+(s.smtp_ready?'ready':'not configured')+'</span>',
        '<span>Sender: <code>'+esc(s.sender_email||'(none)')+'</code></span>',
        '<span>Queue: '+(s.queue_size||0)+'</span>',
        '<span>Sent (last min): '+(s.recent_sends_last_minute||0)+'/'+(s.throttle_per_minute||0)+'</span>'
      ].join(' ');
    }
  }catch(e){}
}
async function emSaveCfg(){
  const types={};document.querySelectorAll('[data-em-type]').forEach(cb=>{types[cb.getAttribute('data-em-type')]=cb.checked});
  const payload={enabled:$('emEnabled').checked,min_severity:$('emMinSev').value,throttle_per_minute:parseInt($('emThrottle').value)||10,alert_types:types};
  try{
    const r=await fetch(A+'/email-alerts/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await r.json();
    $('emR').innerHTML=d.status==='ok'?'<span style="color:var(--grn)">✅ Saved</span>':'<span style="color:var(--red)">❌ '+esc(d.error||'Failed')+'</span>';
    logA('Email config saved');setTimeout(()=>{$('emR').innerHTML=''},2000);lEmail();
  }catch(e){$('emR').innerHTML='<span style="color:var(--red)">❌ '+esc(String(e))+'</span>'}
}
async function emAddRecip(){
  const email=$('emNewEmail').value.trim();if(!email||!email.includes('@')){$('emR').innerHTML='<span style="color:var(--red)">❌ Invalid email</span>';return}
  try{
    const r=await fetch(A+'/email-alerts/recipients/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email})});
    const d=await r.json();
    if(d.status==='added'||d.status==='already_exists'){$('emNewEmail').value='';logA('Recipient added: '+email);lEmail()}
    else{$('emR').innerHTML='<span style="color:var(--red)">❌ '+esc(d.error||'Failed')+'</span>'}
  }catch(e){}
}
async function emRemoveRecip(email){
  if(!confirm('Remove '+email+'?'))return;
  try{await fetch(A+'/email-alerts/recipients/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email})});logA('Recipient removed: '+email);lEmail()}catch(e){}
}
async function emSendTest(){
  const to=$('emTestTo').value.trim();
  $('emTestR').innerHTML='<span style="color:var(--dim)">Sending test email...</span>';
  try{
    const r=await fetch(A+'/email-alerts/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:to})});
    const d=await r.json();
    if(d.status==='ok'){$('emTestR').innerHTML='<span style="color:var(--grn)">✅ '+esc(d.message||'Sent')+'</span>';logA('Test email sent')}
    else{$('emTestR').innerHTML='<span style="color:var(--red)">❌ '+esc(d.message||d.error||'Failed')+'</span>'}
  }catch(e){$('emTestR').innerHTML='<span style="color:var(--red)">❌ '+esc(String(e))+'</span>'}
}
// Scheduled Baseline Verification
async function lSchedules(){
  try{
    const r=await fetch(A+'/scheduler/list');const d=await r.json();if(d.error)return;
    const items=d.baselines||[];
    if(!items.length){$('tSched').innerHTML='<tr><td colspan="8" class="empty">No baselines created yet</td></tr>';return}
    $('tSched').innerHTML=items.map(b=>{
      const next=b.schedule_next_at?new Date(b.schedule_next_at).toLocaleString():'-';
      const last=b.last_verified?new Date(b.last_verified).toLocaleString():'-';
      const ch=b.schedule_enabled?'checked':'';
      const freq=b.schedule_frequency||'daily';
      const bn=esc(b.baseline_name),ag=esc(b.agent_id||'');
      return `<tr>
        <td class="mono">${bn}</td>
        <td class="mono">${ag}</td>
        <td>${b.file_count||0}</td>
        <td><label style="cursor:pointer"><input type="checkbox" ${ch} onchange="schSave('${bn}',this.checked,document.getElementById('fq_${bn}').value)"></label></td>
        <td><select id="fq_${bn}" class="btn" onchange="schSave('${bn}',${b.schedule_enabled?'true':'false'},this.value)" style="margin:0;padding:3px 6px;font-size:11px">
          <option value="hourly" ${freq==='hourly'?'selected':''}>Hourly</option>
          <option value="daily" ${freq==='daily'?'selected':''}>Daily</option>
          <option value="weekly" ${freq==='weekly'?'selected':''}>Weekly</option>
        </select></td>
        <td style="font-size:11px">${esc(next)}</td>
        <td style="font-size:11px">${esc(last)}</td>
        <td><button class="btn btn-p" onclick="schRunNow('${bn}','${ag}')" style="padding:3px 10px;font-size:11px">▶ Run Now</button></td>
      </tr>`;
    }).join('');
  }catch(e){}
}
async function schSave(name,enabled,frequency){
  try{
    const r=await fetch(A+'/scheduler/schedule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({baseline_name:name,enabled:enabled,frequency:frequency})});
    const d=await r.json();
    if(d.status==='ok'){logA('Schedule updated: '+name+' ('+frequency+', '+(enabled?'enabled':'disabled')+')');lSchedules()}
    else{alert('Failed: '+(d.error||'unknown'))}
  }catch(e){alert('Error: '+e)}
}
async function schRunNow(name,agent){
  if(!agent){alert('No agent associated with this baseline');return}
  if(!confirm('Queue immediate verification for '+name+' on '+agent+'?'))return;
  try{
    const r=await fetch(A+'/scheduler/run-now',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({baseline_name:name,agent_id:agent})});
    const d=await r.json();
    if(d.status==='queued'){logA('Verification queued: '+name);setTimeout(lVerifyHist,20000)}
    else{alert('Failed: '+(d.error||'unknown'))}
  }catch(e){alert('Error: '+e)}
}
async function lVerifyHist(){
  try{
    const r=await fetch(A+'/scheduler/history?limit=20');const d=await r.json();if(d.error)return;
    const rows=d.history||[];
    if(!rows.length){$('tVerifyHist').innerHTML='<tr><td colspan="8" class="empty">No verification history yet</td></tr>';return}
    $('tVerifyHist').innerHTML=rows.map(h=>{
      const ts=h.timestamp?new Date(h.timestamp).toLocaleString():'-';
      const score=h.integrity_score!=null?h.integrity_score.toFixed(1)+'%':'-';
      const drift=h.drift_detected;
      const sc=drift?'var(--red)':'var(--grn)';
      const status=drift?'<span class="badge err">DRIFT</span>':'<span class="badge ok">CLEAN</span>';
      return `<tr>
        <td style="font-size:11px">${esc(ts)}</td>
        <td class="mono">${esc(h.baseline_name||'')}</td>
        <td class="mono">${esc(h.agent_id||'')}</td>
        <td style="color:${sc};font-weight:600">${score}</td>
        <td>${h.modified_count||0}</td>
        <td>${h.deleted_count||0}</td>
        <td>${h.new_count||0}</td>
        <td>${status}</td>
      </tr>`;
    }).join('');
  }catch(e){}
}
initCharts();
setInterval(loadAll,10000);
</script>
</body>
</html>"""