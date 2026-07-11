# SecureFIM Pro

**A distributed File Integrity Monitoring (FIM) system with machine-learning anomaly detection, ransomware detection, and threat intelligence.**

SecureFIM Pro monitors file systems across multiple endpoints in real time, detects suspicious activity using a One-Class SVM model and behavioural rules, and surfaces everything through a live web dashboard with compliance-grade PDF reporting. It was developed as a thesis project, with a use case focused on protecting sensitive government records.

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/ML-One--Class%20SVM-orange.svg" alt="One-Class SVM">
  <img src="https://img.shields.io/badge/storage-OpenSearch-005EB8.svg" alt="OpenSearch">
</p>

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Machine Learning](#machine-learning)
- [Security](#security)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [License](#license)

---

## Features

- **Real-time file monitoring** — lightweight agents use `watchdog` to capture create / modify / delete / move events and compute SHA-256 hashes.
- **ML anomaly detection** — a One-Class SVM trained on normal activity flags unusual event windows using 11 engineered features, with a rule-based fallback before training.
- **Ransomware detection** — signature and behavioural detection (suspicious extensions, ransom-note patterns, mass rename/delete/encrypt bursts).
- **Threat intelligence** — file sensitivity classification, MITRE ATT&CK mapping, working-hours anomaly detection, and a combined 0–100 threat score.
- **Automatic backup & restore** — sensitive files are backed up before modification and can be restored on demand from the admin panel.
- **Baseline integrity verification** — snapshot a known-good state and verify against it on a schedule.
- **Alerting** — real-time Discord and email alerts, filterable by severity and type.
- **Live dashboard** — real-time web UI (Socket.IO) with English/Nepali localisation and light/dark themes.
- **Compliance reporting** — auditor-ready PDF reports aligned with the Nepal NCSC advisory and the Cyber Kill Chain.
- **Secure admin panel** — salted PBKDF2 password hashing and token-based authentication.

---

## Architecture

```
┌──────────────┐     ┌──────────────┐
│  Agent (PC)  │     │  Agent (VM)  │
│   watchdog   │     │   watchdog   │
└──────┬───────┘     └──────┬───────┘
       │      REST / HTTP   │
       └─────────┬──────────┘
                 ▼
        ┌─────────────────┐
        │   SecureFIM     │
        │  Server (Flask) │
        │  + ML Pipeline  │
        └────────┬────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
 ┌──────────────┐  ┌────────────────────┐
 │  OpenSearch  │  │ OpenSearch          │
 │  (indexing)  │  │ Dashboards (5601)   │
 └──────────────┘  └────────────────────┘
```

| Component | Description |
|-----------|-------------|
| **Agent** | Runs on each endpoint. Monitors paths, hashes files, batches events, sends heartbeats. |
| **Server** | Flask + Socket.IO app. Ingests events, runs ML and ransomware detection, serves the dashboard and admin panel. |
| **OpenSearch** | Stores events, agents, anomalies, alerts, heartbeats, baselines, and watchlist entries. |
| **ML Pipeline** | One-Class SVM trained on normal activity windows; extracts 11 features per event batch. |
| **Dashboard** | Real-time web UI served by the server. |

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for running agents natively)

### 1. Start the stack

```bash
docker compose up -d
```

This launches OpenSearch, OpenSearch Dashboards, and the SecureFIM server.

### 2. Access the interfaces

| Interface | URL |
|-----------|-----|
| Monitoring Dashboard | http://localhost:8443 |
| Admin Panel | http://localhost:8444 |
| OpenSearch Dashboards | http://localhost:5601 |
| API Health | http://localhost:8443/api/health |

### 3. Run an agent

```bash
pip install -r requirements.txt
python -m agent --server http://localhost:8443 --paths /path/to/monitor
```

### 4. Train the ML model

```bash
python scripts/train_model.py --samples 200
```

### 5. Simulate events (for testing)

```bash
python scripts/simulate_events.py --server http://localhost:8443 --mode mixed --duration 120
```

---

## Machine Learning

The anomaly detector uses a **One-Class SVM** (RBF kernel) trained only on normal activity, so it learns a boundary around expected behaviour and flags anything outside it.

**Features extracted per event window (11 total):**

| Feature | Description |
|---------|-------------|
| `event_rate` | Events per minute |
| `modify_ratio` / `delete_ratio` / `create_ratio` | Fraction of each event type |
| `unique_paths` | Count of distinct file paths |
| `path_depth_mean` | Average directory depth |
| `hash_change_rate` | Fraction of events with a changed hash |
| `size_std` | Standard deviation of file sizes |
| `burst_score` | Max events in any 10-second sub-window |
| `hour_sin` / `hour_cos` | Cyclical time-of-day encoding |

Before the model is trained, threshold-based rules catch obvious anomalies (very high event rates, mass deletions, and bursts). Once enough normal windows are collected, the SVM takes over and retrains periodically.

---

## Security

- **Password storage** — admin credentials are hashed with **PBKDF2-HMAC-SHA256** (200,000 iterations, per-user random salt) and compared in constant time.
- **Authentication** — the admin panel issues a session token on login; all sensitive endpoints require a valid token per request.
- **Sensitivity classification** — files are labelled HIGH / MEDIUM / LOW based on configurable path patterns, including credential, database, and government-record indicators.

> **Note:** This is a thesis / research project. For production deployment, enable TLS, run behind a production WSGI server, secure the OpenSearch cluster, and add mutual authentication for agents. See the thesis document for a full discussion of limitations and future work.

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/agents/register` | POST | Register a new agent |
| `/api/agents` | GET | List all agents |
| `/api/agents/<id>/paths` | GET / PUT | Get or update monitored paths |
| `/api/events` | POST | Ingest events (single or batch) |
| `/api/events/recent` | GET | Recent events |
| `/api/events/stats` | GET | Aggregated statistics |
| `/api/anomalies` | GET | Recent anomaly detections |
| `/api/alerts` | GET | Recent alerts |
| `/api/ml/status` | GET | ML model status |
| `/api/ml/train` | POST | Trigger model training |
| `/api/dashboard/summary` | GET | Full dashboard data payload |

---

## Configuration

Key environment variables (all optional, with sensible defaults):

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_HOST` | `localhost` | OpenSearch host |
| `OPENSEARCH_PORT` | `9200` | OpenSearch port |
| `SERVER_PORT` | `8443` | Monitoring dashboard port |
| `ADMIN_PORT` | `8444` | Admin panel port |
| `ML_MIN_TRAINING_SAMPLES` | `100` | Minimum samples before training |
| `LOG_LEVEL` | `INFO` | Logging level |

Alerting is configured via JSON files (`discord_config.json`, `data/email_config.json`). These are excluded from version control — copy the provided examples and add your own credentials locally.

---

## Project Structure

```
securefimpro/
├── server/
│   ├── config/         # Configuration from environment variables
│   ├── opensearch/     # OpenSearch client and index mappings
│   ├── ml/             # One-Class SVM anomaly detector
│   ├── ransomware/     # Ransomware detection
│   ├── features/       # Threat scoring, MITRE mapping, scheduler, reports
│   ├── discord_alert/  # Discord alerting
│   ├── email_alert/    # Email alerting
│   ├── api/            # REST API routes
│   ├── admin/          # Admin panel
│   ├── dashboard/      # Real-time dashboard
│   ├── auth/           # Salted hashing and token authentication
│   └── main.py         # Server entry point
├── agent/              # FIM agent (watchdog + server communication)
├── scripts/            # Training, simulation, and setup utilities
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

Copyright © 2025–2026 Prajwal Vayankar Coder