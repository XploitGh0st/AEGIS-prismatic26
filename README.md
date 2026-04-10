# AEGIS — Automated Event-driven Guardian for Incident Security

> AI-powered cybersecurity incident triage prototype

## Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose (for production — PostgreSQL, Redis, OpenSearch)
- *or* just Python (for local dev — uses SQLite)

### Local Development (No Docker Required)

```bash
cd backend

# Install dependencies
pip install -e ".[dev]"
pip install aiosqlite  # For SQLite dev mode

# Start the server (auto-creates SQLite DB + all tables)
python -m uvicorn app.main:app --reload --port 8000

# API docs at: http://localhost:8000/docs
# Health check: http://localhost:8000/api/v1/health
```

### Production (Docker)

```bash
# Start PostgreSQL + Redis + OpenSearch
docker compose up -d

# Update backend/.env to use PostgreSQL
# DATABASE_URL=postgresql+psycopg://aegis:aegis@localhost:5432/aegis

# Start backend
cd backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Start workers (in separate terminals)
python -m app.workers.normalize_worker
python -m app.workers.correlate_worker
python -m app.workers.summary_worker

# Seed demo data
python scripts/dev_seed.py
```

## Architecture

```
Alert Sources        AEGIS Pipeline              Storage
─────────────     ──────────────────────     ──────────────
Cowrie Honeypot ──→ Ingestion ──→ Normalize ──→ PostgreSQL
Splunk SIEM     ──→   (raw)       (adapters)    Redis Queue
CrowdStrike EDR ──→              ↓              OpenSearch
Suricata IDS    ──→         Correlate          ↓
                         (score+group)    Incident DB
                              ↓
                         Score+Classify
                              ↓
                     RCA Bundle → AI Summary
                         (GPT-4.5)
                              ↓
                     MemPalace Knowledge Graph
                     (persistent attacker memory)
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/alerts/ingest` | Ingest single alert |
| `POST` | `/api/v1/alerts/bulk` | Bulk ingest (max 500) |
| `GET` | `/api/v1/alerts` | List alerts (paginated) |
| `GET` | `/api/v1/alerts/{id}` | Alert detail |
| `GET` | `/api/v1/incidents` | List incidents |
| `GET` | `/api/v1/incidents/{id}` | Incident detail |
| `PATCH` | `/api/v1/incidents/{id}/status` | Update status |
| `POST` | `/api/v1/incidents/{id}/recalculate` | Re-score incident |
| `POST` | `/api/v1/incidents/{id}/generate-summary` | AI summary |
| `GET` | `/api/v1/dashboard/overview` | KPI metrics |
| `GET` | `/api/v1/dashboard/charts` | Chart data |
| `GET` | `/api/v1/scenarios` | List demo scenarios |
| `POST` | `/api/v1/scenarios/run/{name}` | Run scenario |
| `GET` | `/api/v1/health` | Health check |

## Testing

```bash
cd backend
python -m pytest app/tests/ -v

# 16 tests: Cowrie adapter (7) + Scoring engine (9)
```

## Mock Scenarios

| Scenario | Alerts | Classification | Expected Severity |
|----------|--------|---------------|-------------------|
| `cowrie_brute_force_to_shell` | 20 | account_compromise | Critical |
| `account_compromise` | 5 | account_compromise | Critical |
| `malware_execution` | 3 | malware_execution | Critical |
| `reconnaissance_to_login` | 4 | brute_force_attempt | High |
| `exfiltration_chain` | 3 | possible_exfiltration | High |

## Tooling

- **`scripts/splunk_bridge.py`** — Polls Splunk for Cowrie events, forwards to AEGIS
- **`scripts/attack_simulator.py`** — Generates realistic SSH attack traffic against Cowrie
- **`scripts/dev_seed.py`** — Seeds all 5 scenarios via the API

## Team

- **Backend**: Nandha (you)
- **Frontend**: Siva
