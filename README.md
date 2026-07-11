# SecureFIM Pro v4.0

**Advanced File Integrity Monitoring System with ML-Based Anomaly Detection**

A distributed FIM tool designed for thesis-level demonstration. Agents on endpoint
devices watch file systems for changes, report events to a central server, which
stores everything in OpenSearch and runs One-Class SVM anomaly detection. A
real-time web dashboard provides full visibility.

---

## Architecture

```
┌─────────────┐     ┌─────────────┐
│  Agent (PC)  │     │ Agent (VM)  │
│  watchdog    │     │  watchdog   │
└──────┬───────┘     └──────┬──────┘
       │  REST/HTTP         │
       └──────────┬─────────┘
                  ▼
         ┌────────────────┐
         │  SecureFIM      │
         │  Server (Flask) │
         │  + ML Pipeline  │
         └───────┬─────────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
 ┌──────────────┐  ┌───────────────────┐
 │  OpenSearch   │  │ OpenSearch         │
 │  (indexing)   │  │ Dashboards (5601)  │
 └──────────────┘  └───────────────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **Agent** (`agent/fim_agent.py`) | Runs on each endpoint. Uses watchdog to monitor paths, computes file hashes, batches events, sends heartbeats. |
| **Server** (`server/`) | Flask + SocketIO app. Receives events, stores in OpenSearch, runs ML anomaly detection, serves dashboard. |
| **OpenSearch** | Stores all events, agent metadata, anomalies, alerts, heartbeats in dedicated indices. |
| **Dashboard** | Real-time HTML dashboard served by the server at `/`. Updates via SocketIO + polling. |
| **ML Pipeline** (`server/ml/`) | One-Class SVM trained on normal activity windows. Extracts 11 features from event batches. |

### OpenSearch Indices

| Index | Purpose |
|-------|---------|
| `fim-events` | All file system events |
| `fim-agents` | Registered agent metadata and status |
| `fim-anomalies` | ML anomaly detection results |
| `fim-alerts` | Generated alerts |
| `fim-heartbeats` | Agent health data |

---

## Quick Start (Docker)

### Prerequisites
- Docker and Docker Compose

### 1. Start the stack

```bash
# Start OpenSearch + Server
docker compose up -d

# Wait for OpenSearch to be healthy (~30s)
docker compose logs -f opensearch | head -20
```

### 2. Access the dashboard

- **SecureFIM Dashboard**: http://localhost:8443
- **OpenSearch Dashboards**: http://localhost:5601
- **API Health**: http://localhost:8443/api/health

### 3. Run an agent

Option A — Run agent natively:
```bash
pip install -r requirements.txt

python -m agent --server http://localhost:8443 --paths /home /var/log /etc
```

Option B — Run agent in Docker:
```bash
mkdir -p monitored  # directory to watch

docker compose -f docker-compose.yml -f docker-compose.agent.yml up -d
```

### 4. Train the ML model

```bash
# Generate synthetic training data and train
python scripts/train_model.py --samples 200

# Or send to server for server-side training
python scripts/train_model.py --server http://localhost:8443 --samples 200 --send-to-server
```

### 5. Test with simulated events

```bash
python scripts/simulate_events.py --server http://localhost:8443 --mode mixed --duration 120
```

---

## Local Development (Without Docker)

### 1. Install OpenSearch

Download from https://opensearch.org/downloads.html and run:
```bash
# Single-node, security disabled for local dev
./opensearch-tar-install.sh
```

Or use Docker just for OpenSearch:
```bash
docker run -d --name opensearch \
  -p 9200:9200 -p 9600:9600 \
  -e discovery.type=single-node \
  -e plugins.security.disabled=true \
  -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" \
  opensearchproject/opensearch:2.17.0
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the server

```bash
python -m server
```

### 4. Start an agent (in another terminal)

```bash
python -m agent --server http://localhost:8443 --paths /home/user/documents /var/log
```

---

## Agent Path Management

### During setup (CLI)
```bash
python -m agent --paths /etc /var/log /home/user
```

### After setup (API)
```bash
# Get current paths
curl http://localhost:8443/api/agents/AGENT_ID/paths

# Update paths
curl -X PUT http://localhost:8443/api/agents/AGENT_ID/paths \
  -H "Content-Type: application/json" \
  -d '{"monitored_paths": ["/etc", "/var/log", "/home/user/new_dir"]}'
```

The agent periodically syncs with the server and will pick up path changes
automatically (within 60 seconds).

### Config file
Paths are also persisted in `agent_config.json` on the agent machine.

---

## ML Anomaly Detection

### Feature Extraction (11 features per window)

| Feature | Description |
|---------|-------------|
| `event_rate` | Events per minute |
| `modify_ratio` | Fraction of MODIFIED events |
| `delete_ratio` | Fraction of DELETED events |
| `create_ratio` | Fraction of CREATED events |
| `unique_paths` | Count of distinct file paths |
| `path_depth_mean` | Average directory depth |
| `hash_change_rate` | Fraction with changed hash |
| `size_std` | Std deviation of file sizes |
| `burst_score` | Max events in any 10s sub-window |
| `hour_sin` | Cyclical hour encoding (sin) |
| `hour_cos` | Cyclical hour encoding (cos) |

### Training
- Normal event windows are automatically collected during operation
- Training triggers when enough samples are gathered (default: 100)
- Can also be triggered via API: `POST /api/ml/train`
- Model is saved to `models/ocsvm_model.joblib`

### Inference
- Every batch of events from agents is evaluated
- Anomalous batches generate entries in `fim-anomalies` and `fim-alerts`
- Results are pushed to the dashboard via SocketIO

### Rule-based fallback
Before the model is trained, simple threshold rules detect obvious anomalies
(high event rate, mass deletions, bursts).

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/agents/register` | POST | Register a new agent |
| `/api/agents` | GET | List all agents |
| `/api/agents/<id>` | GET | Agent detail |
| `/api/agents/<id>/paths` | GET/PUT | Get or update monitored paths |
| `/api/agents/<id>/heartbeat` | POST | Agent heartbeat |
| `/api/events` | POST | Ingest events (single or batch) |
| `/api/events/recent` | GET | Recent events (with `?limit=` and `?agent_id=`) |
| `/api/events/stats` | GET | Aggregated stats (with `?minutes=`) |
| `/api/anomalies` | GET | Recent anomaly detections |
| `/api/alerts` | GET | Recent alerts |
| `/api/alerts/<id>/acknowledge` | POST | Acknowledge an alert |
| `/api/ml/status` | GET | ML model status |
| `/api/ml/train` | POST | Trigger model training |
| `/api/dashboard/summary` | GET | Full dashboard data payload |

---

## Environment Variables

### Server
| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_HOST` | `localhost` | OpenSearch host |
| `OPENSEARCH_PORT` | `9200` | OpenSearch port |
| `SERVER_HOST` | `0.0.0.0` | Server bind address |
| `SERVER_PORT` | `8443` | Server port |
| `ML_MODEL_DIR` | `models` | Directory for ML model files |
| `ML_MIN_TRAINING_SAMPLES` | `100` | Minimum samples before training |
| `LOG_LEVEL` | `INFO` | Logging level |

### Agent
| Variable | Default | Description |
|----------|---------|-------------|
| `SECUREFIM_SERVER` | `http://localhost:8443` | Server URL |
| `AGENT_HEARTBEAT_INTERVAL` | `30` | Heartbeat interval (seconds) |
| `AGENT_BATCH_INTERVAL` | `5` | Event batch interval (seconds) |
| `AGENT_CONFIG_FILE` | `agent_config.json` | Local config file path |

---

## Project Structure

```
securefimpro/
├── docker-compose.yml          # OpenSearch + Server
├── docker-compose.agent.yml    # Optional agent container
├── Dockerfile.server
├── Dockerfile.agent
├── requirements.txt
├── server/
│   ├── __init__.py
│   ├── __main__.py
│   ├── main.py                 # Server entry point
│   ├── config/
│   │   └── __init__.py         # Configuration from env vars
│   ├── opensearch/
│   │   └── __init__.py         # OpenSearch client + index mappings
│   ├── ml/
│   │   └── __init__.py         # One-Class SVM anomaly detector
│   ├── api/
│   │   └── __init__.py         # REST API routes
│   └── dashboard/
│       └── __init__.py         # Dashboard HTML
├── agent/
│   ├── __init__.py
│   ├── __main__.py
│   └── fim_agent.py            # Agent with watchdog + server comm
├── scripts/
│   ├── train_model.py          # ML training helper
│   ├── simulate_events.py      # Event simulator for testing
│   └── setup_opensearch.py     # Index setup utility
├── models/                     # ML model files (generated)
├── data/                       # Runtime data
└── logs/                       # Server logs
```

---

## License

MIT License — Copyright (c) 2025-2026 Prajwal Vayankar
