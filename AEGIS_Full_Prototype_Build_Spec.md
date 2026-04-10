# AEGIS Full Prototype Build Spec

## Executive summary

**AEGIS** is a hackathon-ready cybersecurity incident triage prototype for the problem statement **CYB-05 – Automated Incident Detection & Initial Investigation Tool**.

Its job is simple and demo-friendly:

1. ingest alerts from **mock SIEM, EDR, and IDS sources**
2. normalize them into one canonical schema
3. correlate related alerts into **incidents**
4. calculate **incident type, confidence, and severity** using deterministic rules
5. generate a **structured RCA summary** using the OpenAI API (GPT-4.5) from a bounded incident bundle
6. present everything in a clean React dashboard

This spec is intentionally implementation-first. It is written so an AI coding model or engineer can build the full prototype with minimal ambiguity.

The prototype must optimize for the following hackathon outcomes:

- visibly transforms **many raw alerts into a few clear incidents**
- is **explainable**, not black-box
- has a strong demo flow: **Alerts -> Incidents -> RCA -> Report**
- is realistic to implement in **24 hours** using mock data and deterministic logic

---

## Final product vision and exact hackathon scope

### Product vision

AEGIS should feel like a lightweight SOC triage console that helps analysts answer these questions quickly:

- Which alerts belong together?
- Is this incident worth immediate attention?
- What likely happened?
- What assets and users are affected?
- What should the analyst do next?

### Exact 24-hour hackathon scope

Build a prototype with these capabilities only:

- **Mock multi-source ingestion**
  - Accept JSON alerts from 3 source families: SIEM, EDR, IDS
  - Support single ingest and bulk scenario ingest
- **Normalization layer**
  - Convert raw source-specific alerts into one canonical normalized alert schema
- **Correlation engine**
  - Deterministically group alerts into incidents using:
    - time window
    - same user
    - same host
    - same IP
    - MITRE technique overlap
    - predefined attack-chain rules
- **Classification and severity**
  - Assign incident type using rule mappings
  - Assign severity score 0-100 and label Low/Medium/High/Critical
- **RCA summary generation**
  - Use OpenAI API only after incident creation
  - Feed it structured incident bundles only
  - Return strict JSON summary
- **UI dashboard**
  - Alert volume cards
  - Incident list
  - Incident detail page
  - Timeline of correlated alerts
  - Severity charts
  - RCA summary panel
- **Demo-ready seeded scenarios**
  - Brute force -> valid login -> privilege escalation
  - Malware execution on host
  - Port scan -> suspicious login chain
  - Optional exfiltration scenario

### Single-sentence judging pitch

> AEGIS turns fragmented SIEM, EDR, and IDS alerts into one explainable incident with severity, root-cause hypothesis, and analyst-ready summary in seconds.

---

## Non-goals / what NOT to build in 24h

Do **not** build the following in the hackathon version:

- real vendor integrations with Splunk, Sentinel, CrowdStrike, Suricata, etc.
- autonomous response, containment, or remediation actions
- SOAR playbooks
- long-term case management or collaboration workflows
- user authentication beyond a trivial demo mode
- multi-tenancy
- advanced ML correlation models
- vector databases / RAG pipelines
- streaming infrastructure like Kafka/Flink unless the team already has it ready
- live threat intel feeds
- PDF export if core workflow is incomplete
- analyst comment threads, notifications, email integration, Slack integration

### Anti-scope rule

If a feature does not directly improve the demo flow **Alerts -> Incidents -> RCA -> Report**, deprioritize it.

---

## User personas and user journeys

### Persona 1: SOC Analyst (primary)

**Role:** Tier-1 / Tier-2 analyst  
**Goal:** Quickly understand whether a cluster of alerts is a real incident and what to do next.

**Pain points:**

- alerts scattered across tools
- duplicate signals from different products
- time lost stitching context together
- difficulty prioritizing what matters first

### Persona 2: SOC Lead / Judge / Demo Viewer (secondary)

**Role:** Supervisor, evaluator, or judge  
**Goal:** Understand value instantly and see evidence that the system is explainable.

**Pain points:**

- black-box AI tools are hard to trust
- raw alert dumps are visually unimpressive
- hard to judge business relevance from low-level logs

### Persona 3: Security Engineering Student / Builder (tertiary)

**Role:** Team member or recruiter evaluating the project  
**Goal:** See clean architecture, realistic implementation, and strong future product potential.

### User journey 1: Triage a likely account compromise

1. Analyst opens dashboard
2. Live alert stream shows multiple new alerts across SIEM, EDR, IDS
3. AEGIS collapses 5 related alerts into 1 incident
4. Analyst clicks incident
5. Incident page shows:
   - title
   - severity badge
   - evidence timeline
   - affected user and hosts
   - MITRE mapping
   - RCA summary
6. Analyst reads recommended next steps
7. Analyst marks it as `in_progress`

### User journey 2: Demo judge walkthrough

1. Presenter loads seeded scenario
2. Alert count rapidly increases
3. Incident counter increments from 0 to 1
4. Presenter opens incident detail page
5. Presenter explains why correlation happened
6. Presenter shows deterministic severity scoring and LLM-generated summary
7. Presenter ends with future scope and real-world applicability

---

## Core features (must-have, should-have, nice-to-have)

### Must-have

- mock alert ingestion endpoint
- bulk scenario loader
- canonical normalization pipeline
- PostgreSQL persistence
- Redis-backed worker pipeline
- deterministic incident correlation engine
- deterministic severity scoring
- incident classification logic
- RCA bundle generation
- OpenAI GPT-4.5-backed structured summary endpoint
- incident list UI
- incident detail UI
- timeline UI
- severity distribution chart
- explanation panel showing why alerts were grouped

### Should-have

- OpenSearch indexing for fast filter/search
- charts for alerts by source and incidents by severity
- scenario seed button from UI
- re-run summary button
- re-run correlation button
- downloadable JSON report

### Nice-to-have

- entity relationship graph
- mini MITRE matrix visualization
- incident merge/split controls
- export report to markdown/PDF
- analyst notes field

---

## End-to-end system workflow

### Workflow overview

```text
Mock JSON alert source
    -> FastAPI ingest endpoint
    -> raw_alerts table
    -> Redis queue
    -> normalization worker
    -> normalized_alerts table
    -> OpenSearch index
    -> correlation worker
    -> incidents + incident_alert_links
    -> severity + classification
    -> RCA bundle creation
    -> OpenAI GPT-4.5 summary generation
    -> incident_summaries table
    -> React dashboard
```

### Detailed processing steps

1. **Alert ingestion**
   - API receives raw alert JSON
   - assigns `raw_alert_id`
   - stores raw payload in PostgreSQL
   - publishes job to Redis queue `normalize_alert`

2. **Normalization**
   - worker identifies adapter by `source_type`
   - adapter transforms raw payload to canonical normalized alert schema
   - normalized alert persisted to `normalized_alerts`
   - normalized alert indexed into OpenSearch `alerts-v1`
   - publishes job to Redis queue `correlate_alert`

3. **Correlation**
   - worker checks open incidents within configured time windows
   - computes correlation score against eligible incidents
   - either attaches alert to existing incident or creates new incident
   - writes reason codes to `correlation_matches`

4. **Classification and severity**
   - worker recalculates incident type and severity every time an alert is added
   - incident title updated using classification template

5. **RCA bundle generation**
   - backend builds a bounded incident bundle from structured data only
   - includes entities, timeline, MITRE tags, risk factors, matched rules

6. **AI summary generation**
   - OpenAI API called only for incidents meeting minimum summary trigger criteria
   - output validated against strict schema
   - summary stored as versioned incident summary

7. **Presentation**
   - frontend polls or fetches incidents and charts
   - analyst opens incident detail page
   - UI shows raw evidence, explanation, and AI-generated summary separately

### Summary trigger criteria

Generate an AI summary when **all** are true:

- incident has at least 2 alerts
- incident severity score >= 40
- incident has at least 1 of: host, user, source IP
- incident status is not `false_positive`

---

## High-level architecture

### Practical architecture choice

Use a **modular monolith** with worker processes, not microservices.

This keeps the build realistic for 24 hours while still looking production-minded.

### Architecture diagram

```text
┌──────────────────────┐
│ Mock Alert Generator │
│ JSON Scenarios       │
└──────────┬───────────┘
           │ POST /api/v1/alerts/ingest or /bulk
           ▼
┌─────────────────────────────────────────────┐
│ FastAPI Backend                             │
│ - ingestion routes                          │
│ - incidents routes                          │
│ - dashboards routes                         │
│ - summary routes                            │
└──────────┬───────────────────────┬──────────┘
           │                       │
           ▼                       ▼
┌──────────────────┐     ┌────────────────────┐
│ PostgreSQL       │     │ Redis              │
│ raw + normalized │     │ queue + cache      │
│ incidents + RCA  │     └─────────┬──────────┘
└─────────┬────────┘               │
          │                        ▼
          │              ┌────────────────────┐
          │              │ Python Workers     │
          │              │ normalize          │
          │              │ correlate          │
          │              │ summarize          │
          │              └─────────┬──────────┘
          │                        │
          ▼                        ▼
┌──────────────────┐     ┌────────────────────┐
│ OpenSearch       │     │ OpenAI GPT-4.5 API │
│ alert search     │     │ bounded summaries  │
└─────────┬────────┘     └────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────┐
│ React + Tailwind Frontend                   │
│ Dashboard / Incidents / Detail / Timeline   │
└─────────────────────────────────────────────┘
```

### Technology choices

- **Backend API:** FastAPI
- **Workers:** Python RQ workers or simple Redis queue consumers
- **Primary DB:** PostgreSQL
- **Queue/cache:** Redis
- **Search:** OpenSearch or Elasticsearch
- **Frontend:** React + Vite + Tailwind
- **Charts:** Recharts
- **HTTP client for LLM:** `httpx`
- **ORM / DB:** SQLAlchemy + Alembic
- **Validation:** Pydantic v2

### Fallback architecture if OpenSearch breaks

If OpenSearch causes setup issues, keep the code abstraction but temporarily serve search/filter from PostgreSQL using indexed columns and JSONB. Do **not** block the entire prototype on OpenSearch.

---

## Monorepo / folder structure

```text
aegis/
├── README.md
├── docker-compose.yml
├── .env.example
├── docs/
│   ├── api_examples.md
│   ├── demo_script.md
│   └── threat_mapping.md
├── mock-data/
│   ├── scenarios/
│   │   ├── account_compromise.json
│   │   ├── malware_execution.json
│   │   ├── reconnaissance_to_login.json
│   │   └── exfiltration_chain.json
│   └── reference/
│       ├── asset_inventory.json
│       ├── mitre_mappings.json
│       └── severity_weights.json
├── backend/
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── alembic/
│   │   ├── env.py
│   │   └── versions/
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
│   │   ├── models/
│   │   │   ├── raw_alert.py
│   │   │   ├── normalized_alert.py
│   │   │   ├── incident.py
│   │   │   ├── incident_alert_link.py
│   │   │   ├── correlation_match.py
│   │   │   ├── incident_summary.py
│   │   │   └── audit_log.py
│   │   ├── schemas/
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
│   │   │   │   └── ids_adapter.py
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
│   │       └── test_summary_validation.py
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/
│   │   │   ├── client.ts
│   │   │   ├── alerts.ts
│   │   │   ├── incidents.ts
│   │   │   └── dashboard.ts
│   │   ├── pages/
│   │   │   ├── DashboardPage.tsx
│   │   │   ├── IncidentsPage.tsx
│   │   │   ├── IncidentDetailPage.tsx
│   │   │   └── ScenarioRunnerPage.tsx
│   │   ├── components/
│   │   │   ├── layout/
│   │   │   │   ├── AppShell.tsx
│   │   │   │   └── TopBar.tsx
│   │   │   ├── dashboard/
│   │   │   │   ├── KPIGrid.tsx
│   │   │   │   ├── AlertsBySourceChart.tsx
│   │   │   │   ├── SeverityDistributionChart.tsx
│   │   │   │   └── LiveAlertFeed.tsx
│   │   │   ├── incidents/
│   │   │   │   ├── IncidentTable.tsx
│   │   │   │   ├── IncidentCard.tsx
│   │   │   │   ├── IncidentHeader.tsx
│   │   │   │   ├── EvidenceList.tsx
│   │   │   │   ├── CorrelationReasonPanel.tsx
│   │   │   │   ├── RCASummaryPanel.tsx
│   │   │   │   ├── Timeline.tsx
│   │   │   │   ├── EntityChips.tsx
│   │   │   │   └── MitreBadgeList.tsx
│   │   ├── store/
│   │   │   ├── useDashboardStore.ts
│   │   │   └── useIncidentsStore.ts
│   │   ├── types/
│   │   │   ├── alert.ts
│   │   │   ├── incident.ts
│   │   │   └── dashboard.ts
│   │   └── lib/
│   │       ├── severity.ts
│   │       ├── datetime.ts
│   │       └── charts.ts
└── scripts/
    ├── dev_seed.py
    ├── wait_for_services.sh
    └── reset_demo.sh
```

---

## Backend architecture (services/modules/files)

### Backend design principle

Keep the backend as a modular monolith with explicit service boundaries. Do not create multiple deployable services.

### API modules

#### `app/api/v1/alerts.py`

Responsibilities:

- `POST /api/v1/alerts/ingest`
- `POST /api/v1/alerts/bulk`
- `GET /api/v1/alerts`
- `GET /api/v1/alerts/{alert_id}`

#### `app/api/v1/incidents.py`

Responsibilities:

- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `POST /api/v1/incidents/{incident_id}/recalculate`
- `POST /api/v1/incidents/{incident_id}/generate-summary`
- `PATCH /api/v1/incidents/{incident_id}/status`

#### `app/api/v1/dashboard.py`

Responsibilities:

- `GET /api/v1/dashboard/overview`
- `GET /api/v1/dashboard/charts`
- `GET /api/v1/dashboard/live-feed`

#### `app/api/v1/scenarios.py`

Responsibilities:

- `GET /api/v1/scenarios`
- `POST /api/v1/scenarios/run/{scenario_name}`

### Core service modules

#### `ingestion_service.py`

Responsibilities:

- validate raw ingest payload shape
- persist raw payload to DB
- dispatch normalization job

Primary function signatures:

```python
def ingest_one(payload: AlertIngestRequest) -> RawAlert: ...
def ingest_bulk(payloads: list[AlertIngestRequest]) -> list[RawAlert]: ...
```

#### `normalization_service.py`

Responsibilities:

- choose adapter
- normalize raw alerts
- compute entity fingerprints
- persist canonical alert
- index alert into OpenSearch

Primary functions:

```python
def normalize_raw_alert(raw_alert_id: UUID) -> NormalizedAlert: ...
def build_entity_fingerprint(alert: CanonicalAlert) -> str: ...
```

#### `correlation_service.py`

Responsibilities:

- load candidate incidents in active time window
- compute match signals and total correlation score
- create or update incident
- store exact reason codes

Primary functions:

```python
def correlate_alert(normalized_alert_id: UUID) -> UUID: ...
def find_candidate_incidents(alert: CanonicalAlert) -> list[Incident]: ...
def compute_correlation_score(alert: CanonicalAlert, incident: Incident) -> CorrelationResult: ...
```

#### `scoring_service.py`

Responsibilities:

- compute severity score 0-100
- compute confidence score 0-1
- assign severity label

Primary functions:

```python
def calculate_incident_severity(incident_id: UUID) -> SeverityResult: ...
def severity_label(score: int) -> str: ...
```

#### `classification_service.py`

Responsibilities:

- map alerts and techniques into incident types
- generate default title

Primary functions:

```python
def classify_incident(incident_id: UUID) -> ClassificationResult: ...
def generate_incident_title(classification: ClassificationResult) -> str: ...
```

#### `rca_service.py`

Responsibilities:

- produce deterministic structured RCA bundle
- build evidence timeline
- compute impacted entities
- generate recommended actions seeds

Primary functions:

```python
def build_rca_bundle(incident_id: UUID) -> RCABundle: ...
def build_timeline(alerts: list[CanonicalAlert]) -> list[TimelineEvent]: ...
```

#### `summary_service.py`

Responsibilities:

- construct bounded LLM prompt
- call OpenAI API
- validate strict JSON response
- persist summary versions

Primary functions:

```python
def generate_summary(incident_id: UUID, force: bool = False) -> IncidentSummary: ...
def validate_summary_json(payload: dict, bundle: RCABundle) -> ValidationResult: ...
```

#### `scenario_service.py`

Responsibilities:

- list packaged demo scenarios
- load JSON from `mock-data/scenarios`
- ingest scenario events with optional delays

### Worker processes

Use 3 worker types:

- `normalize_worker`
- `correlate_worker`
- `summary_worker`

Queue names:

- `queue:normalize`
- `queue:correlate`
- `queue:summary`

### Processing order

1. ingest request stores raw alert
2. enqueue normalize job
3. normalize job stores normalized alert and enqueues correlate job
4. correlate job creates/updates incident and enqueues summary job if summary criteria met
5. summary job calls OpenAI GPT-4.5 and stores summary

---

## Frontend architecture (pages/components/state/API integration)

### Frontend stack

- React
- Vite
- TypeScript
- Tailwind CSS
- Zustand for state management
- React Router
- Recharts for charts

### Pages

#### `DashboardPage.tsx`

Purpose:

- high-level SOC overview
- KPI cards
- live alert feed
- alerts by source chart
- incidents by severity chart
- latest incidents list

Required sections:

- Total alerts ingested today
- Total open incidents
- Critical incidents count
- Average alerts per incident
- Live alert feed
- Severity distribution
- Top affected entities

#### `IncidentsPage.tsx`

Purpose:

- list/search/filter incidents

Required filters:

- severity
- source family present in incident
- status
- incident type
- affected user
- affected host
- time range

Required table columns:

- Incident ID
- Title
- Type
- Severity
- Score
- Alert Count
- First Seen
- Last Seen
- Status

#### `IncidentDetailPage.tsx`

Purpose:

- show one incident end-to-end

Required sections:

1. Header
   - title
   - incident ID
   - severity badge
   - status badge
   - first seen / last seen
2. Summary panel
   - AI executive summary
   - analyst confidence
   - likely root cause
3. Evidence panel
   - normalized alerts list
   - source labels
   - evidence snippets
4. Timeline panel
   - chronological event sequence
5. Entities panel
   - users, hosts, IPs, processes, domains
6. Correlation reason panel
   - exact rules matched
   - score contributions
7. MITRE panel
   - technique badges
8. Action panel
   - recommended next steps
   - regenerate summary button
   - mark status button

#### `ScenarioRunnerPage.tsx`

Purpose:

- trigger seed scenarios in demo

Required UI:

- list scenario cards
- scenario description
- run scenario button
- reset demo button

### Shared components

- `IncidentCard` for latest incidents
- `IncidentTable` for list page
- `Timeline` with timestamped cards
- `CorrelationReasonPanel` with rule name + points + evidence
- `RCASummaryPanel` with tabs:
  - executive summary
  - observed facts
  - next steps
  - open questions

### State management

Use two stores only to keep it simple:

#### `useDashboardStore`

State:

- overview metrics
- charts data
- live feed entries
- loading/error flags

#### `useIncidentsStore`

State:

- incidents list
- active filters
- selected incident
- summary regeneration state

### API integration rules

- one centralized Axios client in `api/client.ts`
- all responses typed with TS interfaces
- use polling every 5-10 seconds; do not implement websockets unless already ready
- keep frontend tolerant of missing summary/OpenSearch data

---

## Data model / DB schema (tables, fields, relations)

Use PostgreSQL with SQLAlchemy models and Alembic migrations.

### Table: `raw_alerts`

Purpose: immutable store of raw inbound data.

| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | uuid | PK | raw alert ID |
| source_family | varchar(20) | not null | `siem`, `edr`, `ids`, `mock` |
| source_type | varchar(50) | not null | `splunk_mock`, `crowdstrike_mock`, etc. |
| external_alert_id | varchar(120) | nullable | source-side identifier |
| ingest_batch_id | uuid | nullable | bulk import trace |
| received_at | timestamptz | not null | API receive time |
| event_time | timestamptz | nullable | original source time if present |
| payload | jsonb | not null | original payload |
| ingest_status | varchar(20) | not null default `received` | `received`, `normalized`, `failed` |
| error_message | text | nullable | normalization failure reason |

Indexes:

- `(received_at desc)`
- `(source_family, source_type)`
- gin on `payload`

### Table: `normalized_alerts`

Purpose: canonical alerts used everywhere else.

| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | uuid | PK | normalized alert ID |
| raw_alert_id | uuid | FK raw_alerts(id), unique | one raw -> one normalized |
| canonical_alert_id | varchar(120) | unique | human-friendly ID like `ALT-20260408-0001` |
| alert_time | timestamptz | not null | normalized event time |
| source_family | varchar(20) | not null | same as raw |
| source_type | varchar(50) | not null | same as raw |
| vendor_severity | varchar(20) | nullable | raw vendor severity |
| normalized_severity | varchar(20) | not null | `low`, `medium`, `high`, `critical` |
| title | varchar(255) | not null | short normalized title |
| description | text | not null | normalized description |
| category | varchar(50) | not null | `auth`, `process`, `network`, etc. |
| mitre_techniques | text[] | not null default `{}` | technique IDs |
| user_name | varchar(120) | nullable | normalized primary user |
| host_name | varchar(120) | nullable | normalized primary host |
| source_ip | inet | nullable | normalized source IP |
| destination_ip | inet | nullable | normalized destination IP |
| process_name | varchar(255) | nullable | normalized process |
| domain_name | varchar(255) | nullable | optional |
| file_hash | varchar(128) | nullable | optional |
| entity_fingerprint | varchar(255) | not null | stable hash of primary entities |
| correlation_key | varchar(255) | not null | grouping helper |
| raw_payload | jsonb | not null | copied raw payload for convenience |
| canonical_payload | jsonb | not null | full canonical schema |
| indexed_at | timestamptz | nullable | OpenSearch success time |
| created_at | timestamptz | not null | row creation time |

Indexes:

- `(alert_time desc)`
- `(user_name)`
- `(host_name)`
- `(source_ip)`
- `(destination_ip)`
- gin on `mitre_techniques`
- gin on `canonical_payload`
- `(correlation_key)`

### Table: `incidents`

Purpose: primary incident record.

| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | uuid | PK | internal UUID |
| incident_id | varchar(120) | unique | display ID like `INC-20260408-0001` |
| title | varchar(255) | not null | generated title |
| incident_type | varchar(80) | not null | classification label |
| severity_score | int | not null | 0-100 |
| severity_label | varchar(20) | not null | `low`, `medium`, `high`, `critical` |
| confidence_score | numeric(4,3) | not null | 0.000-1.000 |
| status | varchar(20) | not null default `new` | `new`, `in_progress`, `resolved`, `false_positive` |
| first_seen_at | timestamptz | not null | first alert time |
| last_seen_at | timestamptz | not null | latest alert time |
| alert_count | int | not null default 1 | denormalized count |
| affected_users | text[] | not null default `{}` | distinct users |
| affected_hosts | text[] | not null default `{}` | distinct hosts |
| affected_ips | text[] | not null default `{}` | distinct IPs |
| mitre_techniques | text[] | not null default `{}` | aggregated techniques |
| summary_status | varchar(20) | not null default `pending` | `pending`, `ready`, `failed`, `not_applicable` |
| latest_summary_id | uuid | nullable | FK incident_summaries(id) |
| explanation_payload | jsonb | not null default '{}' | correlation + severity explanation |
| created_at | timestamptz | not null | row creation time |
| updated_at | timestamptz | not null | row update time |

Indexes:

- `(severity_score desc)`
- `(severity_label, status)`
- `(first_seen_at desc)`
- `(incident_type)`
- gin on arrays for users/hosts/ips/mitre

### Table: `incident_alert_links`

Purpose: many-to-many mapping between incidents and normalized alerts.

| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | uuid | PK | row ID |
| incident_id | uuid | FK incidents(id) | |
| normalized_alert_id | uuid | FK normalized_alerts(id) | |
| added_at | timestamptz | not null | link time |
| link_reason_summary | varchar(255) | not null | short reason |

Unique constraint:

- `(incident_id, normalized_alert_id)`

### Table: `correlation_matches`

Purpose: preserve explainability of correlation decisions.

| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | uuid | PK | row ID |
| incident_id | uuid | FK incidents(id) | matched incident |
| normalized_alert_id | uuid | FK normalized_alerts(id) | incoming alert |
| matched_rules | text[] | not null | e.g. `same_user`, `same_host` |
| score_total | int | not null | correlation score |
| score_breakdown | jsonb | not null | per-rule points |
| created_new_incident | boolean | not null default false | decision flag |
| created_at | timestamptz | not null | audit time |

### Table: `incident_summaries`

Purpose: versioned AI and deterministic summaries.

| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | uuid | PK | summary version ID |
| incident_id | uuid | FK incidents(id) | parent incident |
| summary_version | int | not null | starts at 1 |
| model_name | varchar(100) | nullable | e.g. `gpt-5.4` |
| prompt_hash | varchar(64) | not null | dedupe + trace |
| input_bundle | jsonb | not null | exact structured input |
| summary_json | jsonb | not null | validated output |
| validation_status | varchar(20) | not null | `passed`, `failed` |
| validation_errors | jsonb | nullable | output validation failures |
| created_at | timestamptz | not null | created time |

Unique constraint:

- `(incident_id, summary_version)`

### Table: `audit_logs`

Purpose: minimal audit trail for demo credibility.

| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | uuid | PK | |
| object_type | varchar(50) | not null | `alert`, `incident`, `summary` |
| object_id | uuid | not null | target UUID |
| action | varchar(80) | not null | `ingested`, `normalized`, `correlated`, `summary_generated` |
| actor | varchar(50) | not null | `system`, `api`, `worker`, `analyst` |
| details | jsonb | nullable | additional context |
| created_at | timestamptz | not null | audit time |

### Relations summary

- `raw_alerts 1 -> 1 normalized_alerts`
- `incidents 1 -> many incident_alert_links`
- `normalized_alerts 1 -> many incident_alert_links`
- `incidents 1 -> many correlation_matches`
- `incidents 1 -> many incident_summaries`

---

## Search/index model for Elasticsearch/OpenSearch

### Why use OpenSearch

Use OpenSearch only for fast filtering, live feed, and timeline queries. PostgreSQL remains source of truth.

### Index names

- `alerts-v1`
- `incidents-v1` (optional; can be skipped if time is short)

### `alerts-v1` mapping

```json
{
  "mappings": {
    "properties": {
      "alert_id": { "type": "keyword" },
      "alert_time": { "type": "date" },
      "source_family": { "type": "keyword" },
      "source_type": { "type": "keyword" },
      "normalized_severity": { "type": "keyword" },
      "title": { "type": "text", "fields": { "raw": { "type": "keyword" } } },
      "description": { "type": "text" },
      "category": { "type": "keyword" },
      "mitre_techniques": { "type": "keyword" },
      "user_name": { "type": "keyword" },
      "host_name": { "type": "keyword" },
      "source_ip": { "type": "ip" },
      "destination_ip": { "type": "ip" },
      "process_name": { "type": "keyword" },
      "domain_name": { "type": "keyword" },
      "entity_fingerprint": { "type": "keyword" },
      "correlation_key": { "type": "keyword" },
      "canonical_payload": { "type": "object", "enabled": false }
    }
  }
}
```

### Search behavior to implement

- filter alerts by source family
- filter by severity
- search by user, host, IP, technique
- sort by latest time desc
- return latest 20 alerts for live feed

### Optional `incidents-v1` mapping

Only implement if time permits.

Use for:

- search incidents by ID/title/type
- filter by severity/status
- aggregate counts by type

### Indexing rule

On normalization success:

- write to PostgreSQL first
- then index in OpenSearch
- if OpenSearch fails, log warning and continue

Do not block incident creation on search indexing.

---

## Canonical normalized alert schema

This schema is the source of truth for the entire prototype.

```json
{
  "alert_id": "ALT-20260408-0001",
  "raw_alert_id": "6f8462fa-0dd4-4ef4-8b79-2c91f7f6d477",
  "source_family": "siem",
  "source_type": "splunk_mock",
  "event_name": "multiple_failed_logins",
  "category": "authentication",
  "title": "Multiple failed logins for privileged account",
  "description": "22 failed login attempts for admin from external IP 185.77.10.4 against vpn-gateway-01",
  "alert_time": "2026-04-08T02:40:00Z",
  "vendor_severity": "high",
  "normalized_severity": "high",
  "status": "new",
  "entities": {
    "users": ["admin"],
    "hosts": ["vpn-gateway-01"],
    "source_ips": ["185.77.10.4"],
    "destination_ips": ["10.0.10.5"],
    "processes": [],
    "domains": [],
    "hashes": []
  },
  "principal_entity": {
    "type": "user",
    "value": "admin"
  },
  "mitre_techniques": ["T1110"],
  "evidence": [
    "failed_login_count=22",
    "account=admin",
    "source_ip=185.77.10.4"
  ],
  "risk_flags": [
    "external_source_ip",
    "privileged_account_targeted",
    "burst_auth_failures"
  ],
  "asset_context": {
    "host_criticality": "high",
    "user_privilege": "admin",
    "environment": "production"
  },
  "correlation_key": "user:admin|host:vpn-gateway-01|src:185.77.10.4",
  "raw_payload": {
    "event_type": "failed_login",
    "count": 22
  }
}
```

### Required schema rules

- `alert_id` must be generated internally
- `source_family` must be one of `siem`, `edr`, `ids`, `mock`
- `normalized_severity` must be one of `low`, `medium`, `high`, `critical`
- `entities` keys must always exist, even if arrays are empty
- `mitre_techniques` must be array of strings, possibly empty
- `risk_flags` must be array of enum-like strings
- `asset_context` must exist, even if values are partial or `unknown`

### Normalization adapter responsibilities

#### SIEM adapter

Typical raw fields:

- user
- src_ip
- dest_host
- auth_count
- event type

Maps mostly to:

- authentication alerts
- account compromise signals
- login success/failure chains

#### EDR adapter

Typical raw fields:

- host
- user
- process tree
- command line
- privilege escalation markers

Maps mostly to:

- execution
- persistence
- privilege escalation
- malware behavior

#### IDS adapter

Typical raw fields:

- src_ip
- dst_ip
- dst_port
- protocol
- byte count
- signature

Maps mostly to:

- reconnaissance
- network anomaly
- exfiltration indicators

---

## Incident schema

```json
{
  "incident_id": "INC-20260408-0001",
  "title": "Potential account compromise on vpn-gateway-01",
  "incident_type": "account_compromise",
  "severity_score": 82,
  "severity_label": "critical",
  "confidence_score": 0.86,
  "status": "new",
  "first_seen_at": "2026-04-08T02:40:00Z",
  "last_seen_at": "2026-04-08T02:47:00Z",
  "alert_count": 5,
  "affected_entities": {
    "users": ["admin"],
    "hosts": ["vpn-gateway-01", "app-server-03"],
    "ips": ["185.77.10.4", "10.0.10.5"]
  },
  "mitre_techniques": ["T1110", "T1078", "T1068", "T1059", "T1041"],
  "matched_rules": [
    "same_user",
    "same_source_ip",
    "same_host_chain",
    "mitre_attack_chain_auth_to_execution"
  ],
  "explanation": {
    "correlation_score": 78,
    "score_breakdown": {
      "same_user": 20,
      "same_source_ip": 15,
      "same_host": 15,
      "time_window": 10,
      "mitre_overlap_or_chain": 18
    },
    "severity_breakdown": {
      "base": 25,
      "multi_source_bonus": 10,
      "privilege_escalation_bonus": 20,
      "exfil_signal_bonus": 15,
      "critical_asset_bonus": 10,
      "alert_volume_bonus": 2
    }
  },
  "summary_status": "ready",
  "latest_summary_id": "d1585d93-9073-4dd8-a1f6-d1c6208f0d42"
}
```

### Incident lifecycle states

- `new`
- `in_progress`
- `resolved`
- `false_positive`

No other workflow states in the hackathon version.

---

## RCA summary schema

This is the deterministic RCA bundle before the LLM summary.

```json
{
  "incident_id": "INC-20260408-0001",
  "incident_type": "account_compromise",
  "severity_label": "critical",
  "severity_score": 82,
  "confidence_score": 0.86,
  "time_window": {
    "start": "2026-04-08T02:40:00Z",
    "end": "2026-04-08T02:47:00Z"
  },
  "alert_count": 5,
  "source_families": ["siem", "edr", "ids"],
  "entities": {
    "users": ["admin"],
    "hosts": ["vpn-gateway-01", "app-server-03"],
    "source_ips": ["185.77.10.4"],
    "destination_ips": ["10.0.10.5"],
    "processes": ["powershell.exe", "cmd.exe"]
  },
  "mitre_techniques": ["T1110", "T1078", "T1068", "T1059", "T1041"],
  "timeline": [
    {
      "time": "2026-04-08T02:40:00Z",
      "source_family": "siem",
      "title": "22 failed logins for admin from 185.77.10.4"
    },
    {
      "time": "2026-04-08T02:42:00Z",
      "source_family": "siem",
      "title": "Successful login for admin from same IP"
    },
    {
      "time": "2026-04-08T02:44:00Z",
      "source_family": "edr",
      "title": "Privilege escalation or admin context change on app-server-03"
    },
    {
      "time": "2026-04-08T02:46:00Z",
      "source_family": "edr",
      "title": "Suspicious PowerShell spawning cmd.exe"
    },
    {
      "time": "2026-04-08T02:47:00Z",
      "source_family": "ids",
      "title": "Outbound traffic spike from app-server-03"
    }
  ],
  "observed_facts": [
    "failed login burst followed by successful login from same IP",
    "privileged user involved",
    "execution activity on affected host",
    "possible outbound data movement"
  ],
  "root_cause_hypothesis": "Likely account compromise followed by post-authentication activity on a production host.",
  "impact_summary": [
    "potential unauthorized access to privileged account",
    "possible command execution on impacted endpoint",
    "possible data staging or exfiltration"
  ],
  "recommended_actions_seed": [
    "disable or reset the affected account",
    "invalidate active sessions",
    "isolate impacted host if feasible",
    "review outbound connections",
    "collect process tree and authentication logs"
  ],
  "unsupported_assumptions": []
}
```

---

## API contract: endpoints, request/response examples, validation rules

Use `/api/v1` prefix for all routes.

### 1) Health endpoints

#### `GET /api/v1/health/live`

Response:

```json
{ "status": "ok" }
```

#### `GET /api/v1/health/ready`

Response:

```json
{
  "status": "ok",
  "services": {
    "postgres": true,
    "redis": true,
    "opensearch": true,
    "openai": true
  }
}
```

### 2) Ingest one alert

#### `POST /api/v1/alerts/ingest`

Request:

```json
{
  "source_family": "siem",
  "source_type": "splunk_mock",
  "external_alert_id": "splunk-evt-1001",
  "event_time": "2026-04-08T02:40:00Z",
  "payload": {
    "event_type": "failed_login",
    "user": "admin",
    "src_ip": "185.77.10.4",
    "dest_host": "vpn-gateway-01",
    "count": 22,
    "severity": "high"
  }
}
```

Success response `202 Accepted`:

```json
{
  "raw_alert_id": "6f8462fa-0dd4-4ef4-8b79-2c91f7f6d477",
  "status": "received",
  "queued_jobs": ["normalize_alert"]
}
```

Validation rules:

- `source_family` required; enum `siem|edr|ids|mock`
- `source_type` required
- `payload` required object
- `event_time` if provided must be valid ISO 8601 UTC timestamp
- payload must not exceed 100 KB in hackathon version

### 3) Ingest bulk alerts

#### `POST /api/v1/alerts/bulk`

Request:

```json
{
  "scenario_name": "account_compromise",
  "alerts": [
    {
      "source_family": "siem",
      "source_type": "splunk_mock",
      "event_time": "2026-04-08T02:40:00Z",
      "payload": {
        "event_type": "failed_login",
        "user": "admin",
        "src_ip": "185.77.10.4",
        "dest_host": "vpn-gateway-01",
        "count": 22,
        "severity": "high"
      }
    }
  ]
}
```

Success response `202 Accepted`:

```json
{
  "ingest_batch_id": "eb4c7324-e173-4794-b8a5-db49c1cf5d7f",
  "received_count": 5,
  "status": "queued"
}
```

Validation rules:

- 1 to 500 alerts per bulk request
- reject empty array
- if `scenario_name` provided, must be simple slug

### 4) List alerts

#### `GET /api/v1/alerts?source_family=siem&severity=high&limit=20`

Response:

```json
{
  "items": [
    {
      "alert_id": "ALT-20260408-0001",
      "alert_time": "2026-04-08T02:40:00Z",
      "source_family": "siem",
      "title": "Multiple failed logins for privileged account",
      "normalized_severity": "high",
      "user_name": "admin",
      "host_name": "vpn-gateway-01",
      "source_ip": "185.77.10.4"
    }
  ],
  "total": 1
}
```

### 5) List incidents

#### `GET /api/v1/incidents?severity=critical&status=new&page=1&page_size=20`

Response:

```json
{
  "items": [
    {
      "incident_id": "INC-20260408-0001",
      "title": "Potential account compromise on vpn-gateway-01",
      "incident_type": "account_compromise",
      "severity_label": "critical",
      "severity_score": 82,
      "confidence_score": 0.86,
      "alert_count": 5,
      "status": "new",
      "first_seen_at": "2026-04-08T02:40:00Z",
      "last_seen_at": "2026-04-08T02:47:00Z"
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 1
}
```

Validation rules:

- `severity` enum `low|medium|high|critical`
- `status` enum `new|in_progress|resolved|false_positive`
- `page_size` max 100

### 6) Get incident detail

#### `GET /api/v1/incidents/{incident_id}`

Response:

```json
{
  "incident": {
    "incident_id": "INC-20260408-0001",
    "title": "Potential account compromise on vpn-gateway-01",
    "incident_type": "account_compromise",
    "severity_label": "critical",
    "severity_score": 82,
    "confidence_score": 0.86,
    "status": "new",
    "first_seen_at": "2026-04-08T02:40:00Z",
    "last_seen_at": "2026-04-08T02:47:00Z",
    "alert_count": 5,
    "affected_entities": {
      "users": ["admin"],
      "hosts": ["vpn-gateway-01", "app-server-03"],
      "ips": ["185.77.10.4", "10.0.10.5"]
    },
    "mitre_techniques": ["T1110", "T1078", "T1068", "T1059", "T1041"],
    "explanation": {
      "matched_rules": ["same_user", "same_source_ip", "time_window", "attack_chain_login_to_execution"],
      "correlation_score": 78,
      "score_breakdown": {
        "same_user": 20,
        "same_source_ip": 15,
        "time_window": 10,
        "attack_chain_login_to_execution": 18,
        "same_host": 15
      },
      "severity_breakdown": {
        "base": 25,
        "critical_asset_bonus": 10,
        "privilege_escalation_bonus": 20,
        "execution_bonus": 10,
        "exfiltration_bonus": 15,
        "multi_source_bonus": 10,
        "alert_volume_bonus": 2
      }
    }
  },
  "alerts": [],
  "summary": {}
}
```

### 7) Update incident status

#### `PATCH /api/v1/incidents/{incident_id}/status`

Request:

```json
{ "status": "in_progress" }
```

Response:

```json
{
  "incident_id": "INC-20260408-0001",
  "status": "in_progress"
}
```

Validation rules:

- only allow the 4 status enum values

### 8) Recalculate incident

#### `POST /api/v1/incidents/{incident_id}/recalculate`

Purpose:

- re-run correlation-dependent aggregation, severity, and classification on current linked alerts

Response:

```json
{
  "incident_id": "INC-20260408-0001",
  "recalculated": true,
  "severity_score": 82,
  "severity_label": "critical",
  "incident_type": "account_compromise"
}
```

### 9) Generate or regenerate summary

#### `POST /api/v1/incidents/{incident_id}/generate-summary`

Request:

```json
{ "force": true }
```

Response:

```json
{
  "incident_id": "INC-20260408-0001",
  "summary_status": "ready",
  "summary_version": 2,
  "model_name": "gpt-5.4"
}
```

### 10) Dashboard overview

#### `GET /api/v1/dashboard/overview`

Response:

```json
{
  "alerts_ingested_today": 54,
  "normalized_alerts_today": 54,
  "open_incidents": 3,
  "critical_incidents": 1,
  "avg_alerts_per_incident": 4.2,
  "top_entities": [
    { "label": "admin", "type": "user", "count": 3 },
    { "label": "app-server-03", "type": "host", "count": 2 }
  ]
}
```

### 11) Dashboard charts

#### `GET /api/v1/dashboard/charts`

Response:

```json
{
  "alerts_by_source": [
    { "source_family": "siem", "count": 20 },
    { "source_family": "edr", "count": 18 },
    { "source_family": "ids", "count": 16 }
  ],
  "incidents_by_severity": [
    { "severity_label": "medium", "count": 1 },
    { "severity_label": "high", "count": 1 },
    { "severity_label": "critical", "count": 1 }
  ]
}
```

### 12) Scenario endpoints

#### `GET /api/v1/scenarios`

Response:

```json
{
  "items": [
    {
      "name": "account_compromise",
      "title": "Brute force to valid login to privilege escalation",
      "alert_count": 5,
      "expected_incident_count": 1
    }
  ]
}
```

#### `POST /api/v1/scenarios/run/{scenario_name}`

Response:

```json
{
  "scenario_name": "account_compromise",
  "ingest_batch_id": "7bf38860-b3f0-4f75-8855-c3f0ae4d6ef2",
  "alert_count": 5,
  "status": "queued"
}
```

---

## Correlation engine design: exact heuristics/rules for time, user, host, IP, MITRE, alert grouping, edge cases

### Design goal

Correlation must be deterministic, explainable, and conservative enough to avoid obviously bad merges during the demo.

### Core rule

For each new normalized alert, compare against **open incidents** where:

- incident status in `new`, `in_progress`
- incident `last_seen_at` within last **30 minutes** of incoming alert time

### Correlation scoring model

Create or update incident based on a **correlation score**.

#### Rule weights

| Rule | Points | Condition |
|---|---:|---|
| same_user | 20 | incoming alert user matches any incident user |
| same_host | 15 | incoming alert host matches any incident host |
| same_source_ip | 15 | incoming alert source IP matches any incident IP |
| same_destination_ip | 10 | destination IP overlaps |
| same_process | 8 | process name overlaps |
| same_domain | 8 | domain overlaps |
| time_within_5m | 10 | alert within 5 mins of incident last_seen |
| time_within_15m | 5 | alert within 15 mins of incident last_seen |
| mitre_overlap | 12 | at least one MITRE technique overlaps |
| attack_chain_match | 18 | technique progression matches predefined chain |
| same_source_family_only | 0 | no points alone; avoids over-correlation |
| high_value_asset_match | 5 | same high-criticality host/user |
| duplicate_fingerprint_penalty | -30 | same fingerprint and same minute; likely duplicate |
| contradictory_context_penalty | -20 | impossible or clearly different context |

### Correlation threshold

- **Attach to existing incident** if total score >= **30**
- **Create new incident** if no candidate incident reaches 30
- If multiple candidate incidents score >= 30, attach to the **highest score**
- If tie, choose incident with most recent `last_seen_at`

### Mandatory anti-merge guardrails

Never merge if **all** are true:

- no overlapping user
- no overlapping host
- no overlapping IP
- no MITRE overlap or chain match
- only similarity is same source family or same severity

Never merge if:

- incoming alert is more than 30 minutes after candidate incident `last_seen_at`
- candidate incident is `resolved` or `false_positive`
- entity sets are completely disjoint and attack categories differ strongly
  - example: unrelated malware alert on `host-a` and login failure on `host-b`

### Exact attack-chain rules

Give `attack_chain_match` points when these ordered chains occur inside 15 minutes and share at least one key entity:

#### Chain A: Account compromise

- `T1110` Brute Force / repeated failed login
- then `T1078` Valid Accounts / successful suspicious login
- then one of:
  - `T1068` Privilege Escalation
  - `T1098` Account manipulation
  - `T1059` Command execution
  - `T1041` Exfiltration

#### Chain B: Reconnaissance to exploitation

- `T1046` Network Service Scanning
- then suspicious login or exploit-like process execution
- then host execution alert

#### Chain C: Malware execution

- suspicious file/dropper or execution precursor
- then `T1059` or suspicious process tree
- then outbound beacon-like traffic or persistence signal

### Matching precedence

Order of evaluation:

1. duplicate suppression
2. hard anti-merge rules
3. score same-user/same-host/same-IP
4. add time-based points
5. add MITRE overlap or chain points
6. add asset-criticality bonus
7. choose decision

### Duplicate detection

Treat alert as duplicate if:

- same source type
- same event name/category
- same primary entities
- same normalized title
- event time within 60 seconds

Duplicate behavior:

- still store alert in `normalized_alerts`
- mark `risk_flags` with `possible_duplicate`
- do not add full correlation points twice
- add to incident only if not already linked by exact alert ID

### Edge cases

#### Edge case 1: Same user on multiple unrelated hosts

Example:

- user `admin` failed login on `vpn-gateway-01`
- user `admin` suspicious process on `db-server-09`

Rule:

- merge only if time proximity <= 15 minutes **and** either same source IP or attack-chain match exists
- same user alone is not enough for multi-host correlation in high-noise situations

#### Edge case 2: Shared service account

If user begins with `svc_`, `service_`, or ends with `_svc`, reduce `same_user` from 20 to **8** because shared service accounts cause noisy false merges.

#### Edge case 3: High-volume port scans

Port scans from same source IP against many unrelated hosts can explode into one bad mega-incident.

Rule:

- correlate scans together by source IP + 10 minute window
- but do **not** automatically merge scan cluster into post-authentication incidents unless a later login/host alert includes same source IP and same target host

#### Edge case 4: Missing user or host

If incoming alert has missing user and host, correlation can still occur via:

- same source IP + time window + MITRE overlap
- same destination IP + time window + attack chain

But require total score >= 35 instead of 30.

#### Edge case 5: Outbound spike alone

An outbound traffic anomaly alone should usually create its own medium incident unless it shares host and time proximity with execution/login alerts.

#### Edge case 6: Resolved incidents reopening

Do not reopen resolved incidents. Create a new incident, even if same entities match, unless explicit reopen logic is implemented later.

### Pseudocode

```python
def compute_correlation_score(alert, incident):
    score = 0
    reasons = {}

    if is_duplicate(alert, incident):
        score -= 30
        reasons["duplicate_fingerprint_penalty"] = -30

    if has_contradictory_context(alert, incident):
        score -= 20
        reasons["contradictory_context_penalty"] = -20

    if same_user(alert, incident):
        points = 8 if is_shared_service_account(alert.user_name) else 20
        score += points
        reasons["same_user"] = points

    if same_host(alert, incident):
        score += 15
        reasons["same_host"] = 15

    if same_source_ip(alert, incident):
        score += 15
        reasons["same_source_ip"] = 15

    if same_destination_ip(alert, incident):
        score += 10
        reasons["same_destination_ip"] = 10

    if minutes_between(alert.alert_time, incident.last_seen_at) <= 5:
        score += 10
        reasons["time_within_5m"] = 10
    elif minutes_between(alert.alert_time, incident.last_seen_at) <= 15:
        score += 5
        reasons["time_within_15m"] = 5

    if mitre_overlap(alert, incident):
        score += 12
        reasons["mitre_overlap"] = 12
    elif attack_chain_match(alert, incident):
        score += 18
        reasons["attack_chain_match"] = 18

    if high_value_asset_match(alert, incident):
        score += 5
        reasons["high_value_asset_match"] = 5

    return score, reasons
```

---

## Severity scoring model: explain formula and weights

### Design goal

Severity must be easy to explain live. Use a weighted additive model, capped at 100.

### Score formula

```text
severity_score =
  base_signal_score
+ asset_criticality_bonus
+ privileged_identity_bonus
+ multi_source_bonus
+ execution_bonus
+ privilege_escalation_bonus
+ exfiltration_bonus
+ attack_chain_bonus
+ alert_volume_bonus
- duplicate_noise_penalty
- benign_context_penalty

Clamp final result to 0..100.
```

### Component weights

#### Base signal score by incident type seed

| Condition | Points |
|---|---:|
| authentication anomaly only | 20 |
| reconnaissance only | 15 |
| suspicious process execution | 30 |
| malware-like execution | 35 |
| privilege escalation evidence | 35 |
| outbound exfiltration signal only | 25 |

Take the **highest** applicable base score, not the sum.

#### Additive bonuses

| Factor | Points |
|---|---:|
| critical asset involved | +15 |
| high asset involved | +10 |
| privileged account targeted or used | +10 |
| multi-source correlation across 2 source families | +8 |
| multi-source correlation across 3 source families | +12 |
| privilege escalation observed | +20 |
| suspicious command/process execution observed | +10 |
| exfiltration/outbound spike observed | +15 |
| attack chain matched | +10 |
| more than 3 alerts in incident | +5 |
| more than 6 alerts in incident | +8 |

#### Reductions

| Factor | Points |
|---|---:|
| >50% alerts marked possible duplicate | -10 |
| known benign allowlisted source IP/host in mock data | -15 |
| only low-severity single-source alerts with no chain | -10 |

### Severity label mapping

| Score range | Label |
|---|---|
| 0-24 | low |
| 25-49 | medium |
| 50-74 | high |
| 75-100 | critical |

### Confidence score model

Confidence is separate from severity.

```text
confidence_score =
  0.20 base
+ 0.15 if same_user present
+ 0.15 if same_host present
+ 0.15 if same_source_ip present
+ 0.15 if MITRE overlap or attack chain present
+ 0.10 if 2+ source families present
+ 0.10 if timeline progression is coherent

Clamp final result to 0.0..1.0
```

### Worked example

Scenario: failed logins -> success -> privilege escalation -> suspicious PowerShell -> outbound spike on high-value host.

- base signal score: 35
- high asset bonus: 10
- privileged identity: 10
- multi-source across 3 sources: 12
- privilege escalation: 20
- execution: 10
- exfiltration: 15
- attack chain: 10
- alert volume >3: 5
- total = 127 -> clamp to 100

That is too inflated for demos, so apply **cap logic by max bundle weight**:

```text
If 2 or more major bonuses from {privilege escalation, execution, exfiltration} are present,
reduce total by 15 after summation to avoid every serious incident hitting 100.
```

Adjusted total:

- 127 - 15 = 112 -> clamp to 100

To keep examples varied in demo data, tune base conditions so the seeded account compromise scenario lands around **82-90** instead of always 100. The simplest implementation is to treat high asset as +10, not +15, and only apply one of execution/exfiltration full value if evidence is weaker.

### Practical implementation note

For demo reliability, store weights in `mock-data/reference/severity_weights.json` so they are easy to tweak without code changes.

---

## Classification model: incident types and mapping logic

### Supported incident types

Implement only these 6 types:

1. `account_compromise`
2. `brute_force_attempt`
3. `malware_execution`
4. `privilege_escalation`
5. `reconnaissance`
6. `possible_exfiltration`

### Classification rules

#### 1) `account_compromise`

Assign if:

- failed login burst + successful login on same user or source IP within 15 minutes, OR
- `T1110` + `T1078`, OR
- suspicious login followed by execution/priv-esc on same user/host

Title template:

- `Potential account compromise on {primary_host}`
- fallback: `Potential account compromise involving {primary_user}`

#### 2) `brute_force_attempt`

Assign if:

- repeated failed logins exceed threshold
- no successful login or post-authentication evidence found

Threshold:

- `count >= 8` failed logins within 5 minutes for same user+source IP

#### 3) `malware_execution`

Assign if:

- suspicious process tree, encoded PowerShell, shell spawn, or malicious hash indicator
- optionally reinforced by network anomaly

Example indicators:

- `powershell.exe -> cmd.exe`
- `wscript.exe -> powershell.exe`
- encoded or obfuscated command flags

#### 4) `privilege_escalation`

Assign if:

- EDR or SIEM indicates admin group membership change, token elevation, sudo abuse, or privileged command success
- and there is no stronger account-compromise chain already matched

#### 5) `reconnaissance`

Assign if:

- port scan, service probing, or repeated connection attempts
- no stronger follow-on exploitation/authentication chain exists

#### 6) `possible_exfiltration`

Assign if:

- outbound spike or suspicious external transfer on impacted host
- and not enough evidence exists for a stronger malware/account-compromise root label

### Priority ordering for classification

If multiple conditions match, apply this precedence:

1. `account_compromise`
2. `malware_execution`
3. `privilege_escalation`
4. `possible_exfiltration`
5. `brute_force_attempt`
6. `reconnaissance`

This ensures multi-stage incidents get the most meaningful label.

### MITRE technique mapping table

| Technique | Supports types |
|---|---|
| T1110 | brute_force_attempt, account_compromise |
| T1078 | account_compromise |
| T1068 | privilege_escalation, account_compromise |
| T1098 | privilege_escalation, account_compromise |
| T1059 | malware_execution, account_compromise |
| T1046 | reconnaissance |
| T1041 | possible_exfiltration, malware_execution, account_compromise |

---

## AI summary layer: prompt design, input schema, output schema, validation rules, hallucination guardrails

### Role of AI in AEGIS

AI does **not** detect incidents. AI summarizes structured incidents after deterministic processing.

### Input schema to OpenAI GPT-4.5

Use the deterministic RCA summary schema as the only model input. Do not send raw database rows or arbitrary logs.

### Prompt design

#### System prompt

```text
You are a SOC investigation summarization assistant.
You will receive a structured incident bundle produced by a deterministic detection pipeline.
Your job is to summarize the incident for a human analyst.

Hard rules:
- Do not invent evidence.
- Use only facts present in the input.
- Clearly separate observed facts from hypotheses.
- If evidence is insufficient, say so.
- Do not recommend autonomous remediation; recommend analyst actions only.
- Return strict JSON only.
```

#### User prompt template

```text
Generate an initial incident investigation summary from the incident bundle below.

Return JSON with exactly these keys:
incident_title,
executive_summary,
observed_facts,
likely_root_cause,
incident_hypothesis,
analyst_confidence,
recommended_next_steps,
open_questions,
priority_justification,
unsupported_assumptions

Incident bundle:
{{ bundle_json }}
```

### Expected output schema

```json
{
  "incident_title": "Potential account compromise on vpn-gateway-01",
  "executive_summary": "AEGIS correlated authentication, endpoint, and network alerts into a likely account compromise incident involving the admin account.",
  "observed_facts": [
    "22 failed login attempts were followed by a successful login from the same source IP.",
    "Privilege escalation activity was observed on app-server-03.",
    "Suspicious process execution and outbound traffic spike were recorded shortly after."
  ],
  "likely_root_cause": "Likely compromise of a privileged account followed by post-authentication activity on a production host.",
  "incident_hypothesis": "An external actor may have obtained valid access to the admin account and then executed commands on the affected environment.",
  "analyst_confidence": "High",
  "recommended_next_steps": [
    "Disable or reset the affected account.",
    "Invalidate active sessions.",
    "Review authentication and process execution logs for the impacted time window.",
    "Inspect outbound network connections from app-server-03."
  ],
  "open_questions": [
    "Was MFA enabled on the login path used by the account?",
    "Did the outbound traffic represent data transfer or command-and-control communication?"
  ],
  "priority_justification": "The incident includes authentication abuse, privilege escalation, and possible post-compromise activity across multiple telemetry sources.",
  "unsupported_assumptions": []
}
```

### Validation rules

After receiving LLM output, validate all of the following:

1. response must parse as JSON
2. required keys must all exist
3. array fields must be arrays of strings
4. `analyst_confidence` must be one of `Low`, `Medium`, `High`
5. `unsupported_assumptions` must exist even if empty
6. no new user/host/IP/process/technique may appear if absent from the input bundle
7. if output mentions evidence not in bundle, reject summary

### Hallucination guardrails

Implement 4 guardrails:

#### Guardrail 1: strict structured input only

Never prompt with free-form raw logs.

#### Guardrail 2: post-response entity validation

Extract known entities from bundle and reject summaries that introduce unknown:

- users
- hosts
- IPs
- process names
- techniques

#### Guardrail 3: required unsupported assumptions field

If the model speculates, it must place speculation into `unsupported_assumptions`.

#### Guardrail 4: fallback deterministic summary

If LLM validation fails, store fallback summary built from templates.

### Fallback deterministic summary template

```json
{
  "incident_title": "Potential account compromise on vpn-gateway-01",
  "executive_summary": "AEGIS correlated 5 alerts across siem, edr, ids into one incident.",
  "observed_facts": [
    "A failed-login burst preceded a successful login.",
    "Privilege escalation or execution activity was observed.",
    "Network anomaly was detected on the impacted host."
  ],
  "likely_root_cause": "Likely unauthorized use of valid credentials followed by host activity.",
  "incident_hypothesis": "Possible account compromise with post-authentication activity.",
  "analyst_confidence": "Medium",
  "recommended_next_steps": [
    "Reset the affected account.",
    "Review host and authentication logs.",
    "Inspect outbound connections."
  ],
  "open_questions": [
    "Was MFA present?"
  ],
  "priority_justification": "Multiple telemetry sources support the incident.",
  "unsupported_assumptions": []
}
```

---

## Mock data design: alert types, sample scenarios, volumes, fields, expected incident outcomes

### Design goals

Mock data must be:

- realistic enough to feel like SOC telemetry
- small enough to debug quickly
- deterministic enough to give repeatable demo outcomes

### Supported mock alert types

#### SIEM-style alerts

- failed login burst
- successful login after failures
- impossible travel style suspicious login
- account lockout
- group membership change

#### EDR-style alerts

- suspicious process tree
- PowerShell execution
- encoded command execution
- privilege escalation token event
- suspicious child process spawn

#### IDS-style alerts

- port scan
- outbound traffic spike
- unusual external destination
- repeated connection attempts to multiple ports

### Required scenario files

#### 1) `account_compromise.json`

Goal: main demo scenario  
Expected result: **1 critical incident** of type `account_compromise`

Alert sequence:

1. failed logins for `admin` from `185.77.10.4`
2. successful login for `admin` from same IP
3. EDR privilege escalation on `app-server-03`
4. EDR suspicious PowerShell on `app-server-03`
5. IDS outbound spike from `app-server-03`

Expected outcome:

- incident count: 1
- type: `account_compromise`
- severity: `critical`
- score range: 80-95
- summary generated: yes

#### 2) `malware_execution.json`

Goal: demonstrate host-centric correlation  
Expected result: **1 high incident** of type `malware_execution`

Alert sequence:

1. suspicious file dropped on `finance-laptop-02`
2. PowerShell spawning cmd on same host
3. outbound suspicious destination from same host

Expected outcome:

- incident count: 1
- type: `malware_execution`
- severity: `high`
- score range: 60-80

#### 3) `reconnaissance_to_login.json`

Goal: show pre-attack plus auth chain  
Expected result: **2 incidents** or **1 high incident** depending on tuning

Safer hackathon choice:

- port scan stays separate as `reconnaissance`
- later brute force becomes `brute_force_attempt`

This avoids over-correlation confusion.

#### 4) `exfiltration_chain.json`

Goal: optional advanced scenario  
Expected result: **1 high incident** of type `possible_exfiltration`

### Mock alert field conventions

All scenario raw alerts should include:

```json
{
  "event_type": "failed_login",
  "timestamp": "2026-04-08T02:40:00Z",
  "severity": "high",
  "user": "admin",
  "src_ip": "185.77.10.4",
  "dest_host": "vpn-gateway-01",
  "count": 22
}
```

### Demo data volume

Recommended demo dataset:

- 15-20 alerts total
- 3-4 scenarios
- 3-5 incidents visible in UI
- only 1 critical incident during live walkthrough

### Background noise design

Add a few unrelated low-value alerts to make correlation more impressive:

- low severity failed logins for another user
- single benign port scan
- one medium IDS network anomaly on another host

Keep noise limited. Too much noise hurts the demo.

---

## UI/UX spec: dashboard, incidents list, incident detail, timeline, filters, charts, RCA panel

### Visual design direction

Use a clean dark theme with strong severity colors:

- low = slate/gray
- medium = amber
- high = orange
- critical = red

### Dashboard layout

#### Top row KPI cards

- Alerts Ingested Today
- Open Incidents
- Critical Incidents
- Average Alerts per Incident

#### Main grid

Left column:

- Live Alert Feed
- Alerts by Source chart

Right column:

- Incidents by Severity chart
- Latest Incidents list

#### UI requirements

- cards should update when scenarios run
- show source badges `SIEM`, `EDR`, `IDS`
- show severity chips
- latest incidents list should link to detail page

### Incidents list page

#### Filters bar

- search box for incident ID/title
- severity dropdown
- status dropdown
- type dropdown
- user filter input
- host filter input

#### Table requirements

- sortable by severity score and last seen time
- severity should be color coded
- clicking a row opens detail page

### Incident detail page layout

#### Section 1: Incident header

Display:

- title
- incident ID
- severity score + label
- confidence score
- status selector
- first seen / last seen
- alert count

#### Section 2: RCA summary panel

Display:

- executive summary
- likely root cause
- incident hypothesis
- priority justification
- regenerate summary button

#### Section 3: Observed facts and next steps

Display as two columns:

- observed facts
- recommended next steps

#### Section 4: Timeline

Display chronological cards with:

- timestamp
- source family badge
- short title
- key entity chips

#### Section 5: Evidence list

Per alert card show:

- normalized title
- severity
- source family
- user/host/IP highlights
- MITRE badges
- raw payload collapse toggle

#### Section 6: Correlation explanation panel

Must show:

- why alerts were grouped
- rule breakdown with point values
- exact score total
- duplicate suppressions or penalties if any

Example display:

```text
Correlation score: 78
+20 same_user (admin)
+15 same_source_ip (185.77.10.4)
+15 same_host chain (app-server-03)
+10 time_within_5m
+18 attack_chain_match
```

#### Section 7: MITRE technique panel

Display technique badges with small label text.

Example:

- T1110 Brute Force
- T1078 Valid Accounts
- T1059 Command and Scripting Interpreter

### Charts

Use only 3 charts for speed:

1. bar chart: alerts by source
2. donut or bar chart: incidents by severity
3. small line/bar chart: alerts over time bucketed by minute

Do not overbuild charts.

---

## Demo script for judges

### Demo length

Target **4-6 minutes**.

### Script

#### 1. Problem statement (30-45 seconds)

"SOC teams get flooded with fragmented alerts from SIEM, EDR, and IDS tools. Analysts waste time stitching them together before investigation even starts. AEGIS solves that by turning noisy alerts into one explainable incident with an RCA summary."

#### 2. Show dashboard before scenario (20 seconds)

- point to KPI cards
- explain multi-source ingestion
- show live alert feed area

#### 3. Run main scenario (45-60 seconds)

- click `Run account_compromise`
- show live alerts appear from SIEM, EDR, IDS
- point out alert count increasing

#### 4. Show incident creation (45 seconds)

- incident list updates
- open new critical incident
- say: "Five raw alerts were collapsed into one incident."

#### 5. Explain correlation (60 seconds)

Show correlation panel:

- same user
- same source IP
- time window
- attack chain progression

Explain that correlation is deterministic and auditable.

#### 6. Explain severity and RCA (60 seconds)

- show severity score and breakdown
- show observed facts
- show likely root cause
- show next steps

#### 7. Explain role of AI (30 seconds)

"The AI layer does not detect incidents. It only summarizes a structured incident bundle after deterministic scoring and correlation."

#### 8. Close with impact and future scope (20-30 seconds)

"AEGIS reduces first-pass triage effort, improves analyst speed, and provides a realistic path to production with future integrations to tools like Splunk and CrowdStrike."

### Demo success conditions

Before presenting, verify:

- scenario loads cleanly
- at least one critical incident appears
- incident detail page loads in under 2 seconds
- summary is already generated or regenerates reliably

---

## Implementation roadmap for a 24-hour hackathon (hour-by-hour or phase-by-phase)

### Phase 0: 0-1 hour — lock architecture and contracts

- finalize this spec
- freeze normalized alert schema
- freeze incident schema
- freeze API contract for must-have endpoints
- create repo and folder scaffolding

### Phase 1: 1-4 hours — backend skeleton + DB

- FastAPI app bootstrapped
- PostgreSQL models created
- Alembic migration created
- Docker Compose spins up postgres, redis, opensearch
- health endpoints working
- basic ingest endpoint storing raw alerts

### Phase 2: 4-8 hours — normalization + scenarios

- adapters for SIEM, EDR, IDS mock payloads
- normalization worker implemented
- canonical alert schema persisted
- bulk scenario runner endpoint added
- first scenario JSON files ready

### Phase 3: 8-12 hours — correlation + severity + classification

- correlation service implemented
- incident creation flow working
- severity scoring working
- classification working
- explanation payload stored
- integration test for `account_compromise` passing

### Phase 4: 12-16 hours — frontend MVP

- dashboard page wired
- incidents list page wired
- incident detail page wired
- charts added
- live feed added via polling

### Phase 5: 16-19 hours — RCA + AI summary

- RCA bundle builder done
- OpenAI GPT-4.5 integration done
- strict JSON validation done
- fallback deterministic summary done
- summary panel appears on detail page

### Phase 6: 19-22 hours — polish and seed data tuning

- tune scenario timings and weights
- improve titles and labels
- verify one-click demo reliability
- make severity ranges visually convincing

### Phase 7: 22-24 hours — testing and presentation

- rehearse demo end-to-end 3 times
- fix crashes and layout issues
- prepare screenshots/slides
- write final talking points

### Hard prioritization if behind schedule

If time slips, ship in this order:

1. ingest
2. normalize
3. correlate
4. incident list/detail
5. severity/classification
6. AI summary
7. OpenSearch
8. extra charts/animations

---

## Task split for a 4-person team

### Member 1 — Backend/API owner

Responsibilities:

- FastAPI setup
- DB models and migrations
- alert ingest routes
- incidents routes
- dashboard routes
- status update route

Deliverables:

- backend app boots cleanly
- API docs available at `/docs`
- core DB persistence works

### Member 2 — Detection logic owner

Responsibilities:

- normalization adapters
- correlation engine
- severity scoring
- incident classification
- RCA bundle builder

Deliverables:

- main scenario generates correct incident
- explanation payload complete
- tests for scoring/correlation

### Member 3 — Frontend/UI owner

Responsibilities:

- React app scaffold
- dashboard page
- incidents list page
- incident detail page
- charts and severity visuals

Deliverables:

- polished demo flow
- all must-have pages usable

### Member 4 — AI/demo/data owner

Responsibilities:

- scenario JSON creation
- OpenAI GPT-4.5 summary integration
- summary validation
- fallback templates
- demo script and slide alignment

Deliverables:

- summary generation reliable
- seeded scenarios produce expected results
- pitch/demo narrative ready

### Collaboration rule

Freeze API response contracts early. Frontend should work against mocked responses if backend is incomplete.

---

## Testing strategy

### Testing philosophy

Only test what can break the demo.

### Backend tests

#### Unit tests

- normalization adapter outputs canonical schema
- correlation score calculations
- severity score calculations
- classification mapping
- summary validator rejects hallucinated entities

#### Integration tests

- bulk ingest of `account_compromise.json` creates 1 incident
- incident has expected type `account_compromise`
- incident severity score in expected range
- summary endpoint stores valid summary JSON

### Frontend tests

Minimum useful coverage:

- incident list renders rows from API
- incident detail page renders summary/timeline
- severity chip mapping works

### Manual test checklist

- run each scenario from UI
- confirm dashboard cards update
- confirm incident detail page loads
- confirm regenerate summary works
- confirm filters on incidents page work
- confirm app still works if OpenSearch or OpenAI is unavailable

### Demo smoke test command sequence

1. `docker compose up -d`
2. run migrations
3. seed/reset demo data
4. run `account_compromise`
5. verify 1 critical incident exists
6. open UI and rehearse full click path

---

## Deployment/dev run instructions

### Local dev approach

Use Docker Compose for infrastructure and local dev servers for frontend/backend.

### `docker-compose.yml` services

Required services:

- `postgres`
- `redis`
- `opensearch`
- optional `opensearch-dashboards` if already convenient

### Backend run steps

```bash
cd backend
cp ../.env.example .env
uv sync   # or pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Worker run steps

```bash
cd backend
python -m app.workers.normalize_worker
python -m app.workers.correlate_worker
python -m app.workers.summary_worker
```

### Frontend run steps

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

### Full reset script behavior

`scripts/reset_demo.sh` should:

- delete rows from incident tables
- delete normalized/raw alert rows
- flush Redis queues
- optionally delete OpenSearch indices and recreate them

### Minimum URLs

- backend docs: `http://localhost:8000/docs`
- frontend: `http://localhost:5173`
- OpenSearch: `http://localhost:9200`

---

## Environment variables and secrets layout

### Root `.env.example`

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
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=admin
OPENSEARCH_ALERT_INDEX=alerts-v1
OPENSEARCH_INCIDENT_INDEX=incidents-v1

# OpenAI
OPENAI_API_KEY=replace_me
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-5.4
SUMMARY_GENERATION_ENABLED=true

# Correlation
CORRELATION_LOOKBACK_MINUTES=30
CORRELATION_ATTACH_THRESHOLD=30
CORRELATION_STRICT_THRESHOLD_WITHOUT_USER_OR_HOST=35

# Summary
SUMMARY_MIN_ALERT_COUNT=2
SUMMARY_MIN_SEVERITY_SCORE=40
```

### Secret handling rules

- commit `.env.example`, never `.env`
- OpenAI API key only needed for summary generation
- if no API key, app should still run using deterministic fallback summaries

---

## Risks, shortcuts, and fallback plans

### Risk 1: OpenSearch setup issues

**Shortcut:** skip incident index and only index alerts  
**Fallback:** serve filters from PostgreSQL

### Risk 2: Worker pipeline bugs

**Shortcut:** execute normalization/correlation synchronously inside ingest endpoint  
**Fallback:** keep worker abstraction in code but use direct function call until stable

### Risk 3: OpenAI API instability or missing key

**Shortcut:** generate deterministic template summary  
**Fallback:** hide model name in UI and label summary as `Structured RCA Summary`

### Risk 4: Correlation too aggressive

**Shortcut:** raise attach threshold from 30 to 35  
**Fallback:** make port scans stand alone and only correlate strongest main scenario

### Risk 5: Frontend time overrun

**Shortcut:** prioritize 3 pages only  
**Fallback:** skip ScenarioRunner page and run scenarios from backend/docs or script

### Risk 6: Docker complexity

**Shortcut:** run backend/frontend locally, infra via Docker only  
**Fallback:** temporarily disable OpenSearch and keep PostgreSQL + Redis only

### Shortcut policy

If forced to choose between **more features** and **a stable demo**, always choose stability.

---

## Acceptance criteria / definition of done

The hackathon prototype is done when all of the following are true:

### Core pipeline

- [ ] Raw alerts can be ingested via API
- [ ] Alerts are normalized into canonical schema
- [ ] Normalized alerts are persisted in PostgreSQL
- [ ] At least one scenario creates a correlated incident automatically
- [ ] Incident stores explanation payload with matched rules

### Detection logic

- [ ] Severity score is computed 0-100
- [ ] Severity label is assigned correctly
- [ ] Incident type is assigned from supported taxonomy
- [ ] Main scenario produces expected incident type and severity range

### RCA / summary

- [ ] RCA bundle is generated for incident detail page
- [ ] Summary endpoint returns strict JSON
- [ ] Invalid/hallucinated summaries are rejected
- [ ] Fallback deterministic summary works when LLM fails

### UI

- [ ] Dashboard page shows KPI cards and charts
- [ ] Incidents page lists incidents with filters
- [ ] Incident detail page shows summary, timeline, evidence, and explanation
- [ ] Severity is visually color coded

### Demo readiness

- [ ] `account_compromise` scenario can be run on demand
- [ ] full demo flow works without manual DB fixes
- [ ] app can be started from clean environment using written instructions

---

## Future scope after hackathon

After the hackathon, AEGIS can evolve in credible directions:

### Near-term

- real adapters for Splunk, Microsoft Sentinel, CrowdStrike, Suricata
- analyst notes and incident comments
- merge/split incident controls
- report export to markdown/PDF
- entity graph visualization

### Mid-term

- historical case search
- analyst feedback loop for tuning correlation weights
- richer asset inventory and allowlists
- ATT&CK tactic mapping and attack path visualization
- webhook output to ticketing systems

### Long-term

- SOC copilot experience
- multi-tenant MSSP support
- retrieval from past incidents for better summaries
- semi-automated playbook suggestions
- production-grade RBAC and audit controls

---

## Final implementation notes for the coding agent

1. Build this as a **modular monolith**, not microservices.
2. Keep PostgreSQL as source of truth.
3. Use OpenSearch opportunistically, not as a hard dependency.
4. Prefer deterministic rules everywhere except the final summary layer.
5. Optimize for one excellent demo path: `account_compromise`.
6. If something breaks, simplify rather than expand.
7. The UI should always show **why** the incident exists, not just that it exists.

---

## Suggested first build order for an AI coding model

1. scaffold backend FastAPI app and DB models
2. implement raw ingest endpoint
3. implement normalization adapters and normalized alert model
4. implement correlation service and incident tables
5. implement severity/classification
6. implement incident detail API
7. implement dashboard APIs
8. scaffold frontend pages against mock API data
9. wire frontend to live API
10. add OpenAI GPT-4.5 summary integration with strict validation
11. add scenario seed files and runner endpoint
12. polish UI and demo script

This order minimizes dead ends and produces visible progress quickly.