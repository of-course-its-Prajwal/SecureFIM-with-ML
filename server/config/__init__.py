"""
SecureFIM Pro  Server Configuration
Reads from environment variables with sensible defaults.
"""

import os

# OpenSearch 
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_SCHEME = os.getenv("OPENSEARCH_SCHEME", "http")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS", "")

# Index names 
IDX_EVENTS = os.getenv("IDX_EVENTS", "fim-events")
IDX_AGENTS = os.getenv("IDX_AGENTS", "fim-agents")
IDX_ANOMALIES = os.getenv("IDX_ANOMALIES", "fim-anomalies")
IDX_ALERTS = os.getenv("IDX_ALERTS", "fim-alerts")
IDX_HEARTBEATS = os.getenv("IDX_HEARTBEATS", "fim-heartbeats")
IDX_BASELINES = os.getenv("IDX_BASELINES", "fim-baselines")
IDX_WATCHLIST = os.getenv("IDX_WATCHLIST", "fim-watchlist")
IDX_VERIFY_REQUESTS = os.getenv("IDX_VERIFY_REQUESTS", "fim-verify-requests")
IDX_VERIFY_RESULTS = os.getenv("IDX_VERIFY_RESULTS", "fim-verify-results")

#  Baseline Scheduler (v7.6) 
# How often the scheduler thread wakes up to check for due verifications
SCHEDULER_TICK_SECONDS = int(os.getenv("SCHEDULER_TICK_SECONDS", "60"))
# Default frequency for newly-enabled schedules (minutes)
SCHEDULER_DEFAULT_FREQUENCY_MINUTES = int(os.getenv("SCHEDULER_DEFAULT_FREQUENCY_MINUTES", "1440"))  # daily

# Working hours (for insider threat detection) 
BUSINESS_HOURS_START = int(os.getenv("BUSINESS_HOURS_START", "9"))   # 9 AM
BUSINESS_HOURS_END = int(os.getenv("BUSINESS_HOURS_END", "18"))      # 6 PM
BUSINESS_DAYS = os.getenv("BUSINESS_DAYS", "0,1,2,3,4")             # Mon-Fri

#  Server 
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8443"))
SECRET_KEY = os.getenv("SECRET_KEY", "securefim-secret-change-me")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

#  ML 
ML_MODEL_DIR = os.getenv("ML_MODEL_DIR", "models")
ML_MIN_TRAINING_SAMPLES = int(os.getenv("ML_MIN_TRAINING_SAMPLES", "100"))
ML_RETRAIN_INTERVAL = int(os.getenv("ML_RETRAIN_INTERVAL", "3600"))  # seconds

#  Agent defaults 
AGENT_HEARTBEAT_INTERVAL = int(os.getenv("AGENT_HEARTBEAT_INTERVAL", "30"))
AGENT_OFFLINE_THRESHOLD = int(os.getenv("AGENT_OFFLINE_THRESHOLD", "90"))

#  Dashboard 
DASHBOARD_REFRESH_MS = int(os.getenv("DASHBOARD_REFRESH_MS", "3000"))

#  Admin 
ADMIN_PORT = int(os.getenv("ADMIN_PORT", "8444"))

#  Corroborative threat scoring 
CORROBORATIVE_SCORING = os.getenv("CORROBORATIVE_SCORING", "true").lower() == "true"
