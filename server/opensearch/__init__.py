"""
SecureFIM Pro — OpenSearch Client
Handles connection, index creation, and all document operations.
"""

import time
import logging
from datetime import datetime, timezone
from opensearchpy import OpenSearch, RequestsHttpConnection, exceptions as os_exc

from server.config import (
    OPENSEARCH_HOST, OPENSEARCH_PORT, OPENSEARCH_SCHEME,
    OPENSEARCH_USER, OPENSEARCH_PASS,
    IDX_EVENTS, IDX_AGENTS, IDX_ANOMALIES, IDX_ALERTS, IDX_HEARTBEATS,
    IDX_BASELINES, IDX_WATCHLIST,
    IDX_VERIFY_REQUESTS, IDX_VERIFY_RESULTS,
)

log = logging.getLogger("securefim.opensearch")

# ── Index mappings ────────────────────────────────────────────────────────

MAPPINGS = {
    IDX_EVENTS: {
        "mappings": {
            "properties": {
                "agent_id":      {"type": "keyword"},
                "event_type":    {"type": "keyword"},
                "file_path":     {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                "dest_path":     {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                "file_size":     {"type": "long"},
                "file_hash":     {"type": "keyword"},
                "old_hash":      {"type": "keyword"},
                "severity":      {"type": "keyword"},
                "hostname":      {"type": "keyword"},
                "os_type":       {"type": "keyword"},
                "is_anomaly":    {"type": "boolean"},
                "anomaly_score": {"type": "float"},
                "username":      {"type": "keyword"},
                "process_info":  {"type": "keyword"},
                "backup_path":   {"type": "keyword"},
                "backed_up":     {"type": "boolean"},
                "sensitivity":   {"type": "keyword"},
                "threat_score":  {"type": "integer"},
                "threat_level":  {"type": "keyword"},
                "outside_hours": {"type": "boolean"},
                "mitre_tags":    {"type": "keyword"},
                "timestamp":     {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
    IDX_AGENTS: {
        "mappings": {
            "properties": {
                "agent_id":        {"type": "keyword"},
                "hostname":        {"type": "keyword"},
                "os_type":         {"type": "keyword"},
                "os_version":      {"type": "keyword"},
                "agent_version":   {"type": "keyword"},
                "ip_address":      {"type": "ip"},
                "monitored_paths": {"type": "keyword"},
                "status":          {"type": "keyword"},
                "registered_at":   {"type": "date"},
                "last_heartbeat":  {"type": "date"},
                "event_count":     {"type": "long"},
                "metadata":        {"type": "object", "enabled": False},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
    IDX_ANOMALIES: {
        "mappings": {
            "properties": {
                "agent_id":         {"type": "keyword"},
                "anomaly_type":     {"type": "keyword"},
                "anomaly_score":    {"type": "float"},
                "severity":         {"type": "keyword"},
                "description":      {"type": "text"},
                "related_events":   {"type": "integer"},
                "feature_vector":   {"type": "float"},
                "timestamp":        {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
    IDX_ALERTS: {
        "mappings": {
            "properties": {
                "agent_id":     {"type": "keyword"},
                "alert_type":   {"type": "keyword"},
                "severity":     {"type": "keyword"},
                "title":        {"type": "text"},
                "message":      {"type": "text"},
                "acknowledged": {"type": "boolean"},
                "timestamp":    {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
    IDX_HEARTBEATS: {
        "mappings": {
            "properties": {
                "agent_id":     {"type": "keyword"},
                "cpu_percent":  {"type": "float"},
                "memory_percent": {"type": "float"},
                "disk_percent": {"type": "float"},
                "event_count":  {"type": "long"},
                "uptime":       {"type": "long"},
                "timestamp":    {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
    IDX_BASELINES: {
        "mappings": {
            "properties": {
                "agent_id":     {"type": "keyword"},
                "file_path":    {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                "file_hash":    {"type": "keyword"},
                "file_size":    {"type": "long"},
                "permissions":  {"type": "keyword"},
                "baseline_name": {"type": "keyword"},
                "status":       {"type": "keyword"},
                "last_verified": {"type": "date"},
                "timestamp":    {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
    IDX_WATCHLIST: {
        "mappings": {
            "properties": {
                "file_path":    {"type": "text", "fields": {"raw": {"type": "keyword"}}},
                "sensitivity":  {"type": "keyword"},
                "description":  {"type": "text"},
                "added_by":     {"type": "keyword"},
                "mitre_tags":   {"type": "keyword"},
                "auto_alert":   {"type": "boolean"},
                "timestamp":    {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
    "fim-restore-requests": {
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
    },
    "fim-verify-requests": {
        "mappings": {
            "properties": {
                "baseline_name": {"type": "keyword"},
                "agent_id":      {"type": "keyword"},
                "status":        {"type": "keyword"},
                "requested_by":  {"type": "keyword"},
                "scheduled":     {"type": "boolean"},
                "completed_at":  {"type": "date"},
                "timestamp":     {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
    "fim-verify-results": {
        "mappings": {
            "properties": {
                "baseline_name":    {"type": "keyword"},
                "agent_id":         {"type": "keyword"},
                "request_id":       {"type": "keyword"},
                "integrity_score":  {"type": "float"},
                "total_baseline":   {"type": "integer"},
                "total_current":    {"type": "integer"},
                "ok_count":         {"type": "integer"},
                "modified_count":   {"type": "integer"},
                "deleted_count":    {"type": "integer"},
                "new_count":        {"type": "integer"},
                "drift_detected":   {"type": "boolean"},
                "modified_files":   {"type": "keyword"},
                "deleted_files":    {"type": "keyword"},
                "new_files":        {"type": "keyword"},
                "scheduled":        {"type": "boolean"},
                "timestamp":        {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    },
}


class OpenSearchClient:
    """Thin wrapper around the opensearch-py client."""

    def __init__(self):
        auth = (OPENSEARCH_USER, OPENSEARCH_PASS) if OPENSEARCH_USER else None
        self.client = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
            http_auth=auth,
            use_ssl=(OPENSEARCH_SCHEME == "https"),
            verify_certs=False,
            connection_class=RequestsHttpConnection,
            timeout=30,
        )
        self._ready = False

    # ── lifecycle ─────────────────────────────────────────────────────────

    def wait_for_cluster(self, retries: int = 30, delay: float = 2.0) -> bool:
        for attempt in range(1, retries + 1):
            try:
                info = self.client.info()
                log.info("OpenSearch cluster ready — version %s", info["version"]["number"])
                self._ready = True
                return True
            except Exception as exc:
                log.warning("Waiting for OpenSearch (%d/%d): %s", attempt, retries, exc)
                time.sleep(delay)
        log.error("OpenSearch not reachable after %d attempts", retries)
        return False

    # Critical keyword fields per index — if any are mistyped as text in the
    # live mapping, terms aggregations silently break (this is the v7.2 bug).
    # On startup we validate these and auto-repair by reindex + swap.
    _CRITICAL_KEYWORDS = {
        IDX_EVENTS: [
            "event_type", "severity", "agent_id", "hostname", "os_type",
            "sensitivity", "threat_level", "username", "mitre_tags",
        ],
        IDX_AGENTS: ["agent_id", "hostname", "os_type", "status"],
        IDX_ANOMALIES: ["agent_id", "anomaly_type", "severity"],
        IDX_ALERTS: ["agent_id", "alert_type", "severity"],
    }

    def _mapping_is_healthy(self, name: str) -> tuple[bool, list[str]]:
        """Check the live mapping for an index. Returns (healthy, broken_fields)."""
        required = self._CRITICAL_KEYWORDS.get(name, [])
        if not required:
            return True, []
        try:
            live = self.client.indices.get_mapping(index=name)
            # live = { "<index>": { "mappings": { "properties": { ... } } } }
            props = (
                live.get(name, {})
                    .get("mappings", {})
                    .get("properties", {})
            )
        except Exception as exc:
            log.warning("get_mapping(%s) failed: %s", name, exc)
            return True, []  # don't block startup on diagnostic failure

        broken = []
        for field in required:
            f = props.get(field)
            if not f:
                continue  # field not present yet — fine, will be added by first doc
            if f.get("type") != "keyword":
                broken.append(field)
        return (len(broken) == 0), broken

    def _repair_index(self, name: str, correct_body: dict):
        """
        Rebuild an index that has a broken dynamic mapping.
        Flow: create <name>_fixed with correct mapping -> reindex -> delete old
        -> alias or rename. We do a rename via reindex-back because OpenSearch
        has no atomic rename, and we want the original name preserved.
        """
        tmp = f"{name}-repair-{int(time.time())}"
        log.warning("Repairing index '%s' — mapping is broken. Data will be reindexed.", name)
        try:
            # 1. Create temp index with correct mapping
            self.client.indices.create(index=tmp, body=correct_body)

            # 2. Reindex old -> temp (OpenSearch coerces values to new types)
            self.client.reindex(
                body={"source": {"index": name}, "dest": {"index": tmp}},
                wait_for_completion=True,
                request_timeout=120,
            )

            # 3. Drop the broken index
            self.client.indices.delete(index=name)

            # 4. Reindex temp -> original name (freshly created with correct mapping)
            self.client.indices.create(index=name, body=correct_body)
            self.client.reindex(
                body={"source": {"index": tmp}, "dest": {"index": name}},
                wait_for_completion=True,
                request_timeout=120,
            )

            # 5. Drop temp
            self.client.indices.delete(index=tmp)
            self.client.indices.refresh(index=name)
            log.info("Repaired index '%s' successfully.", name)
        except Exception as exc:
            log.error("Failed to repair index '%s': %s", name, exc)
            # best-effort cleanup of temp
            try:
                if self.client.indices.exists(index=tmp):
                    self.client.indices.delete(index=tmp)
            except Exception:
                pass

    def ensure_indices(self):
        for name, body in MAPPINGS.items():
            try:
                if not self.client.indices.exists(index=name):
                    self.client.indices.create(index=name, body=body)
                    log.info("Created index: %s", name)
                    continue

                # Index exists — validate critical keyword fields
                healthy, broken = self._mapping_is_healthy(name)
                if healthy:
                    log.info("Index already exists: %s", name)
                else:
                    log.warning(
                        "Index '%s' has broken mapping on fields: %s — auto-repairing",
                        name, broken,
                    )
                    self._repair_index(name, body)
            except os_exc.RequestError as exc:
                if "resource_already_exists_exception" not in str(exc):
                    log.error("Error creating index %s: %s", name, exc)

    # ── generic CRUD ──────────────────────────────────────────────────────

    def index_doc(self, index: str, body: dict, doc_id: str = None) -> str | None:
        try:
            if "timestamp" not in body:
                body["timestamp"] = datetime.now(timezone.utc).isoformat()
            resp = self.client.index(index=index, body=body, id=doc_id, refresh="wait_for")
            return resp.get("_id")
        except Exception as exc:
            log.error("index_doc(%s) failed: %s", index, exc)
            return None

    def get_doc(self, index: str, doc_id: str) -> dict | None:
        try:
            resp = self.client.get(index=index, id=doc_id)
            return resp["_source"]
        except os_exc.NotFoundError:
            return None
        except Exception as exc:
            log.error("get_doc(%s, %s) failed: %s", index, doc_id, exc)
            return None

    def update_doc(self, index: str, doc_id: str, body: dict) -> bool:
        try:
            self.client.update(index=index, id=doc_id, body={"doc": body}, refresh="wait_for")
            return True
        except Exception as exc:
            log.error("update_doc(%s, %s) failed: %s", index, doc_id, exc)
            return False

    def search(self, index: str, body: dict, size: int = 100) -> list[dict]:
        try:
            resp = self.client.search(index=index, body=body, size=size)
            return [
                {**hit["_source"], "_id": hit["_id"]}
                for hit in resp["hits"]["hits"]
            ]
        except Exception as exc:
            log.error("search(%s) failed: %s", index, exc)
            return []

    def count(self, index: str, body: dict = None) -> int:
        try:
            resp = self.client.count(index=index, body=body or {"query": {"match_all": {}}})
            return resp["count"]
        except Exception as exc:
            log.error("count(%s) failed: %s", index, exc)
            return 0

    def delete_by_query(self, index: str, body: dict) -> int:
        try:
            resp = self.client.delete_by_query(index=index, body=body, refresh=True)
            return resp.get("deleted", 0)
        except Exception as exc:
            log.error("delete_by_query(%s) failed: %s", index, exc)
            return 0

    # ── convenience queries ───────────────────────────────────────────────

    def get_recent_events(self, limit: int = 50, agent_id: str = None) -> list[dict]:
        query: dict = {"match_all": {}}
        if agent_id:
            query = {"term": {"agent_id": agent_id}}
        return self.search(IDX_EVENTS, {
            "query": query,
            "sort": [{"timestamp": {"order": "desc"}}],
        }, size=limit)

    def get_agents(self) -> list[dict]:
        return self.search(IDX_AGENTS, {
            "query": {"match_all": {}},
            "sort": [{"last_heartbeat": {"order": "desc"}}],
        }, size=200)

    def get_agent(self, agent_id: str) -> dict | None:
        return self.get_doc(IDX_AGENTS, agent_id)

    def upsert_agent(self, agent_id: str, data: dict) -> bool:
        existing = self.get_agent(agent_id)
        if existing:
            return self.update_doc(IDX_AGENTS, agent_id, data)
        else:
            self.index_doc(IDX_AGENTS, data, doc_id=agent_id)
            return True

    def _resolve_agg_field(self, index: str, field: str) -> str | None:
        """
        Return the correct field name to use for terms aggregation.
        If the field is a keyword, return it as-is.
        If it's text with a .keyword / .raw sub-field, return that instead.
        If it's text with no aggregatable sub-field, return None.
        """
        try:
            live = self.client.indices.get_mapping(index=index)
            props = live.get(index, {}).get("mappings", {}).get("properties", {})
            f = props.get(field)
            if not f:
                return field  # field not yet present — use as-is, agg will be empty
            if f.get("type") == "keyword":
                return field
            # text field — look for a keyword sub-field
            for sub_name, sub_def in (f.get("fields") or {}).items():
                if sub_def.get("type") == "keyword":
                    return f"{field}.{sub_name}"
            return None
        except Exception:
            return field  # on any error, fall back to the plain field name

    def get_event_stats(self, minutes: int = 60) -> dict:
        """Aggregate event counts for the last N minutes."""
        # Resolve aggregatable field names defensively (v7.2 mapping-drift guard)
        type_field = self._resolve_agg_field(IDX_EVENTS, "event_type") or "event_type"
        sev_field = self._resolve_agg_field(IDX_EVENTS, "severity") or "severity"

        body = {
            "query": {
                "range": {"timestamp": {"gte": f"now-{minutes}m"}}
            },
            "aggs": {
                "by_type": {"terms": {"field": type_field, "size": 20}},
                "by_severity": {"terms": {"field": sev_field, "size": 10}},
                "anomalies": {"filter": {"term": {"is_anomaly": True}}},
                "over_time": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": "5m",
                    }
                },
            },
            "size": 0,
        }
        try:
            resp = self.client.search(index=IDX_EVENTS, body=body)
            aggs = resp.get("aggregations", {})
            total = resp["hits"]["total"]["value"]
            by_type = {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])}
            by_severity = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}

            # Diagnostic: events exist but aggregations are empty → mapping still bad
            if total > 0 and not by_type and not by_severity:
                log.warning(
                    "get_event_stats: %d events matched but all terms aggregations are empty. "
                    "Mapping may still be broken. Resolved fields: event_type=%s, severity=%s",
                    total, type_field, sev_field,
                )

            return {
                "total": total,
                "by_type": by_type,
                "by_severity": by_severity,
                "anomaly_count": aggs.get("anomalies", {}).get("doc_count", 0),
                "over_time": [
                    {"time": b["key_as_string"], "count": b["doc_count"]}
                    for b in aggs.get("over_time", {}).get("buckets", [])
                ],
            }
        except Exception as exc:
            log.error("get_event_stats failed: %s", exc)
            return {"total": 0, "by_type": {}, "by_severity": {}, "anomaly_count": 0, "over_time": []}

    def get_recent_anomalies(self, limit: int = 20) -> list[dict]:
        return self.search(IDX_ANOMALIES, {
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }, size=limit)

    def get_recent_alerts(self, limit: int = 30) -> list[dict]:
        return self.search(IDX_ALERTS, {
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }, size=limit)
