"""
SecureFIM Pro — Scheduled Baseline Verification
"""

import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

log = logging.getLogger("securefim.scheduler")


FREQUENCY_MINUTES = {
    "hourly":  60,
    "daily":   60 * 24,
    "weekly":  60 * 24 * 7,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(s) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def _frequency_minutes(freq: str, custom_interval: int = 0) -> int:
    freq = (freq or "").lower()
    if freq in FREQUENCY_MINUTES:
        return FREQUENCY_MINUTES[freq]
    if freq == "custom" and custom_interval > 0:
        return int(custom_interval)
    return FREQUENCY_MINUTES["daily"]  # safe default


class BaselineScheduler:
    """
    Runs in a daemon thread. On each tick, iterates stored baselines,
    finds schedules that are due, and enqueues a verification request.
    """

    def __init__(self, os_client,
                 tick_seconds: int = 60,
                 discord_alerter=None,
                 email_alerter=None):
        self.os_client = os_client
        self.tick_seconds = max(10, int(tick_seconds))
        self.discord_alerter = discord_alerter
        self.email_alerter = email_alerter
        self._thread: Optional[threading.Thread] = None
        self._stop = False
        self._lock = threading.Lock()
        # Avoid duplicate enqueues for the same baseline within one tick window
        self._inflight: set[str] = set()

    #  lifecycle 

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="BaselineScheduler")
        self._thread.start()
        log.info("Baseline scheduler started (tick=%ds)", self.tick_seconds)

    def stop(self):
        self._stop = True

    #  main loop 

    def _run(self):
        # Small grace period so OpenSearch indices are fully ready
        time.sleep(3)
        while not self._stop:
            try:
                self._tick()
            except Exception as exc:
                log.error("Scheduler tick error: %s", exc)
            time.sleep(self.tick_seconds)

    def _tick(self):
        now = _now()
        baselines = self._list_scheduled_baselines()
        if not baselines:
            return

        # We need agent_id per baseline to route the verify-request.
        # Each baseline document has an agent_id field stored on every
        # file entry — pick any (they're all the same agent per baseline).
        due_count = 0
        for group in baselines:
            name = group["name"]
            agent_id = group["agent_id"]
            meta = group["meta"]  # the first document's schedule fields

            if not meta.get("schedule_enabled"):
                continue

            next_at = _parse_iso(meta.get("schedule_next_at"))
            if next_at and next_at > now:
                continue  # not due yet

            if name in self._inflight:
                continue  # already enqueued

            self._enqueue_verification(name, agent_id, scheduled=True,
                                       requested_by="scheduler")
            due_count += 1

            # Update next_at on all baseline docs for this baseline_name
            interval = _frequency_minutes(
                meta.get("schedule_frequency", "daily"),
                int(meta.get("schedule_interval_minutes") or 0),
            )
            new_next = now + timedelta(minutes=interval)
            self._update_schedule_fields(name, {
                "schedule_last_at": _iso(now),
                "schedule_next_at": _iso(new_next),
            })

        if due_count:
            log.info("Scheduler enqueued %d verification(s)", due_count)

    # helpers: baseline querying 

    def _list_scheduled_baselines(self) -> list[dict]:
        """
        Return a list of {name, agent_id, meta} for every unique baseline
        that has schedule fields present. Baselines are stored as one doc
        per file, all sharing a baseline_name.
        """
        try:
            # Aggregate unique baseline names; pick one representative doc per name
            body = {
                "size": 0,
                "query": {"exists": {"field": "schedule_enabled"}},
                "aggs": {
                    "by_name": {
                        "terms": {"field": "baseline_name", "size": 200},
                        "aggs": {
                            "first_doc": {
                                "top_hits": {"size": 1,
                                             "_source": {"includes": [
                                                 "baseline_name", "agent_id",
                                                 "schedule_enabled",
                                                 "schedule_frequency",
                                                 "schedule_interval_minutes",
                                                 "schedule_next_at",
                                                 "schedule_last_at",
                                             ]}}
                            }
                        }
                    }
                }
            }
            resp = self.os_client.client.search(index="fim-baselines", body=body)
            buckets = resp.get("aggregations", {}).get("by_name", {}).get("buckets", [])
            out = []
            for b in buckets:
                hits = b.get("first_doc", {}).get("hits", {}).get("hits", [])
                if not hits:
                    continue
                src = hits[0].get("_source", {})
                out.append({
                    "name": src.get("baseline_name"),
                    "agent_id": src.get("agent_id"),
                    "meta": src,
                })
            return out
        except Exception as exc:
            log.debug("_list_scheduled_baselines failed: %s", exc)
            return []

    def _update_schedule_fields(self, baseline_name: str, fields: dict):
        """Update schedule_* fields on every doc of a baseline via update_by_query."""
        try:
            script_lines = []
            for k, v in fields.items():
                script_lines.append(f"ctx._source.{k} = params.{k};")
            self.os_client.client.update_by_query(
                index="fim-baselines",
                body={
                    "query": {"term": {"baseline_name": baseline_name}},
                    "script": {"source": " ".join(script_lines),
                               "lang": "painless",
                               "params": fields},
                },
                refresh=True,
            )
        except Exception as exc:
            log.warning("update_schedule_fields(%s) failed: %s", baseline_name, exc)

    #  public: enqueue + record result 

    def _enqueue_verification(self, baseline_name: str, agent_id: str,
                              scheduled: bool = True,
                              requested_by: str = "scheduler") -> Optional[str]:
        """Write a verify-request doc. Returns the document id."""
        if not baseline_name or not agent_id:
            log.warning("Cannot enqueue verify: missing name=%s agent=%s",
                        baseline_name, agent_id)
            return None
        doc = {
            "baseline_name": baseline_name,
            "agent_id": agent_id,
            "status": "pending",
            "requested_by": requested_by,
            "scheduled": bool(scheduled),
            "timestamp": _iso(_now()),
        }
        try:
            # Ensure index exists with correct mapping before writing (safety net)
            if not self.os_client.client.indices.exists(index="fim-verify-requests"):
                self.os_client.ensure_indices()
            doc_id = self.os_client.index_doc("fim-verify-requests", doc)
            if doc_id:
                self.os_client.client.indices.refresh(index="fim-verify-requests")
                self._inflight.add(baseline_name)
                log.info("Verification enqueued: baseline=%s agent=%s id=%s",
                         baseline_name, agent_id, doc_id)
            return doc_id
        except Exception as exc:
            log.error("_enqueue_verification failed: %s", exc)
            return None

    def record_verification_result(self, baseline_name: str, agent_id: str,
                                   request_id: str,
                                   current_files: list[dict],
                                   scheduled: bool = False) -> dict:
        """
        Called from the /verify-complete API handler after the agent reports.
        Compares current_files (list of {path, hash, size}) against the
        stored baseline and writes a result doc. Fires alerts on drift.
        """
        baseline_items = self.os_client.search("fim-baselines", {
            "query": {"term": {"baseline_name": baseline_name}},
        }, size=5000)
        baseline_map = {item["file_path"]: item for item in baseline_items}
        current_map = {f.get("path"): f for f in current_files if f.get("path")}

        modified, deleted, new = [], [], []
        ok_count = 0
        for path, bl in baseline_map.items():
            cur = current_map.get(path)
            if not cur:
                deleted.append(path)
            elif cur.get("hash") != bl.get("file_hash"):
                modified.append(path)
            else:
                ok_count += 1
        for path in current_map:
            if path not in baseline_map:
                new.append(path)

        total_baseline = len(baseline_map)
        integrity_score = round(ok_count / max(total_baseline, 1) * 100, 1)
        drift = bool(modified or deleted)  # "new" alone isn't necessarily drift

        result_doc = {
            "baseline_name": baseline_name,
            "agent_id": agent_id,
            "request_id": request_id,
            "integrity_score": integrity_score,
            "total_baseline": total_baseline,
            "total_current": len(current_map),
            "ok_count": ok_count,
            "modified_count": len(modified),
            "deleted_count": len(deleted),
            "new_count": len(new),
            "drift_detected": drift,
            "modified_files": modified[:100],  # cap for safety
            "deleted_files": deleted[:100],
            "new_files": new[:100],
            "scheduled": bool(scheduled),
            "timestamp": _iso(_now()),
        }
        try:
            self.os_client.index_doc("fim-verify-results", result_doc)
        except Exception as exc:
            log.error("Failed to store verify-result: %s", exc)

        # Mark request as completed
        try:
            self.os_client.client.update(
                index="fim-verify-requests",
                id=request_id,
                body={"doc": {"status": "completed",
                              "completed_at": _iso(_now())}},
                refresh=True,
            )
        except Exception as exc:
            log.debug("Could not mark verify-request completed: %s", exc)

        # Clear inflight marker
        self._inflight.discard(baseline_name)

        # Alerts on drift
        if drift:
            self._fire_drift_alerts(result_doc)
        else:
            log.info("Verification clean: baseline=%s integrity=%.1f%%",
                     baseline_name, integrity_score)

        return result_doc

    #  alerting 

    def _fire_drift_alerts(self, result: dict):
        baseline = result.get("baseline_name", "?")
        agent = result.get("agent_id", "?")
        score = result.get("integrity_score", 0)
        m = result.get("modified_count", 0)
        d = result.get("deleted_count", 0)
        n = result.get("new_count", 0)

        title = f"⚠️ Baseline drift detected: {baseline}"
        summary = (f"Integrity score: {score}%. "
                   f"Modified: {m}, Deleted: {d}, New: {n}.")

        # Store as an alert so it shows in the dashboard Alerts page too
        try:
            self.os_client.index_doc("fim-alerts", {
                "alert_type": "baseline_drift",
                "severity": "critical",
                "title": title,
                "message": summary,
                "agent_id": agent,
                "acknowledged": False,
                "timestamp": _iso(_now()),
            })
        except Exception as exc:
            log.warning("Could not write drift alert: %s", exc)

        fields = {
            "Baseline": baseline,
            "Agent": agent,
            "Integrity Score": f"{score}%",
            "Modified Files": m,
            "Deleted Files": d,
            "New Files": n,
        }
        # Attach a short sample of affected paths for the alerts
        sample = (result.get("modified_files", [])[:3]
                  + result.get("deleted_files", [])[:3])
        if sample:
            fields["Examples"] = ", ".join(sample)

        if self.discord_alerter:
            try:
                self.discord_alerter.send_alert(
                    title=title, message=summary,
                    severity="critical", fields=fields,
                )
            except Exception as exc:
                log.error("Discord drift alert error: %s", exc)

        if self.email_alerter:
            try:
                self.email_alerter.send_alert(
                    title=title, message=summary,
                    severity="critical",
                    alert_type="critical_threat",
                    fields=fields,
                )
            except Exception as exc:
                log.error("Email drift alert error: %s", exc)

        log.warning("Baseline drift alert fired: %s (integrity=%.1f%%)",
                    baseline, score)

    #  public: schedule config API 

    def set_schedule(self, baseline_name: str, *,
                     enabled: bool,
                     frequency: str = "daily",
                     interval_minutes: int = 0) -> dict:
        """
        Enable/disable a schedule for a baseline and set frequency.
        Returns the updated schedule snapshot.
        """
        freq = (frequency or "daily").lower()
        if freq not in FREQUENCY_MINUTES and freq != "custom":
            freq = "daily"

        interval = _frequency_minutes(freq, interval_minutes)
        now = _now()
        next_at = now + timedelta(minutes=interval) if enabled else None

        fields = {
            "schedule_enabled": bool(enabled),
            "schedule_frequency": freq,
            "schedule_interval_minutes": int(interval_minutes or 0),
            "schedule_next_at": _iso(next_at) if next_at else None,
        }
        self._update_schedule_fields(baseline_name, fields)
        log.info("Schedule set: baseline=%s enabled=%s freq=%s next=%s",
                 baseline_name, enabled, freq,
                 fields.get("schedule_next_at"))
        return fields

    def run_now(self, baseline_name: str, agent_id: str,
                requested_by: str = "admin") -> Optional[str]:
        """Trigger an immediate verification outside the schedule."""
        return self._enqueue_verification(baseline_name, agent_id,
                                          scheduled=False,
                                          requested_by=requested_by)

    def list_history(self, baseline_name: Optional[str] = None,
                     limit: int = 20) -> list[dict]:
        query = {"match_all": {}} if not baseline_name \
            else {"term": {"baseline_name": baseline_name}}
        return self.os_client.search("fim-verify-results", {
            "query": query,
            "sort": [{"timestamp": {"order": "desc"}}],
        }, size=limit)

    def status(self) -> dict:
        return {
            "running": bool(self._thread and self._thread.is_alive()),
            "tick_seconds": self.tick_seconds,
            "inflight": list(self._inflight),
        }
