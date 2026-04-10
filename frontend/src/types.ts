export type DashboardKPI = {
  label: string;
  value: number;
  change?: number | null;
  trend?: "up" | "down" | "flat" | null;
};

export type DashboardOverview = {
  total_alerts_ingested: DashboardKPI;
  open_incidents: DashboardKPI;
  critical_incidents: DashboardKPI;
  avg_alerts_per_incident: DashboardKPI;
  mean_time_to_detect_seconds?: DashboardKPI | null;
};

export type SeverityDistribution = {
  low: number;
  medium: number;
  high: number;
  critical: number;
};

export type SourceDistribution = {
  source: string;
  count: number;
};

export type RecentAlert = {
  id: string;
  event_name: string;
  severity: string;
  source_ip?: string | null;
  user_name?: string | null;
  event_time: string;
  source_family: string;
};

export type DashboardCharts = {
  severity_distribution: SeverityDistribution;
  alerts_by_source: SourceDistribution[];
  recent_alerts: RecentAlert[];
  recent_incidents: Incident[];
};

export type Incident = {
  id: string;
  incident_number: string;
  title: string;
  classification: string;
  severity: string;
  severity_score: number;
  confidence: number;
  status: string;
  primary_user?: string | null;
  primary_host?: string | null;
  primary_src_ip?: string | null;
  alert_count: number;
  mitre_techniques?: string[] | null;
  source_families?: string[] | null;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
};

export type IncidentListResponse = {
  total: number;
  page: number;
  page_size: number;
  incidents: Incident[];
};

export type IncidentSummary = {
  id: string;
  version: number;
  generation_type: string;
  executive_summary: string;
  root_cause?: string | null;
  observed_facts?: string[] | null;
  recommended_actions?: string[] | null;
  confidence_notes?: string | null;
  model_used?: string | null;
  generated_at: string;
};

export type IncidentDetail = Incident & {
  primary_dst_ip?: string | null;
  mitre_tactics?: string[] | null;
  scoring_breakdown?: Record<string, unknown> | null;
  alerts: Array<{
    id: string;
    event_name: string;
    event_time?: string;
    severity: string;
    source_ip?: string | null;
    source_family?: string;
    description?: string | null;
  }>;
  summaries: IncidentSummary[];
  correlation_matches: Array<{
    total_score: number;
    reason_codes: Record<string, unknown>;
    match_type: string;
    matched_entity?: string | null;
  }>;
};

// ── PCAP Types ──────────────────────────────────────────

export type PcapUploadResponse = {
  pcap_id: string;
  filename: string;
  file_size_bytes: number;
  status: string;
  alerts_generated: number;
  incidents_created: string[];
  message: string;
};

// ── MemPalace Types ─────────────────────────────────────

export type AttackerTriple = {
  predicate: string;
  object: string;
  valid_from: string;
};

export type AttackerIntel = {
  ip: string;
  triples: AttackerTriple[];
  total: number;
};

export type AttackerTimelineEntry = {
  time: string;
  action: string;
  detail: string;
};

export type AttackerTimeline = {
  ip: string;
  timeline: AttackerTimelineEntry[];
  total_events: number;
};

export type MemPalaceStatus = {
  available: boolean;
  stats: {
    enabled: boolean;
    total_triples: number;
    total_entities: number;
    palace_path: string;
    wing_attackers_count: number;
    wing_incidents_count: number;
    wing_soc_analyst_count: number;
    [key: string]: unknown;
  };
};

export type MemorySearchResult = {
  text: string;
  score: number;
  metadata: Record<string, unknown>;
  created_at: string;
  room: string;
  matching_keywords: string[];
};