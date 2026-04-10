import type {
  DashboardCharts,
  DashboardOverview,
  Incident,
  IncidentDetail,
  IncidentListResponse,
} from "../types";

const now = Date.now();

export const mockDashboardOverview: DashboardOverview = {
  total_alerts_ingested: { label: "Alerts Ingested", value: 12847, change: 7.2, trend: "up" },
  open_incidents: { label: "Open Incidents", value: 24, change: -4.1, trend: "down" },
  critical_incidents: { label: "Critical Incidents", value: 5, change: 12.5, trend: "up" },
  avg_alerts_per_incident: { label: "Avg Alerts/Incident", value: 14.3, change: 1.8, trend: "up" },
};

const mockIncidents: Incident[] = [
  {
    id: "inc-001",
    incident_number: "AEGIS-2026-0042",
    title: "Credential stuffing from rotating VPS cluster",
    classification: "Account Compromise Attempt",
    severity: "critical",
    severity_score: 92,
    confidence: 0.94,
    status: "in_progress",
    primary_user: "admin",
    primary_host: "auth-gateway-1",
    primary_src_ip: "185.220.101.45",
    alert_count: 34,
    mitre_techniques: ["T1110", "T1078"],
    source_families: ["cowrie", "auth"],
    first_seen_at: new Date(now - 1000 * 60 * 85).toISOString(),
    last_seen_at: new Date(now - 1000 * 60 * 4).toISOString(),
    created_at: new Date(now - 1000 * 60 * 84).toISOString(),
  },
  {
    id: "inc-002",
    incident_number: "AEGIS-2026-0043",
    title: "Suspicious PowerShell download cradle",
    classification: "Execution",
    severity: "high",
    severity_score: 78,
    confidence: 0.87,
    status: "new",
    primary_user: "svc-backup",
    primary_host: "win-core-02",
    primary_src_ip: "10.42.0.18",
    alert_count: 19,
    mitre_techniques: ["T1059.001", "T1105"],
    source_families: ["edr", "proxy"],
    first_seen_at: new Date(now - 1000 * 60 * 62).toISOString(),
    last_seen_at: new Date(now - 1000 * 60 * 7).toISOString(),
    created_at: new Date(now - 1000 * 60 * 61).toISOString(),
  },
  {
    id: "inc-003",
    incident_number: "AEGIS-2026-0044",
    title: "DNS tunneling beacon behavior",
    classification: "Command and Control",
    severity: "medium",
    severity_score: 61,
    confidence: 0.79,
    status: "new",
    primary_user: "jane.doe",
    primary_host: "workstation-17",
    primary_src_ip: "10.42.12.77",
    alert_count: 11,
    mitre_techniques: ["T1071.004"],
    source_families: ["dns", "nids"],
    first_seen_at: new Date(now - 1000 * 60 * 48).toISOString(),
    last_seen_at: new Date(now - 1000 * 60 * 11).toISOString(),
    created_at: new Date(now - 1000 * 60 * 47).toISOString(),
  },
];

export const mockDashboardCharts: DashboardCharts = {
  severity_distribution: {
    low: 8,
    medium: 14,
    high: 9,
    critical: 5,
  },
  alerts_by_source: [
    { source: "cowrie", count: 2240 },
    { source: "edr", count: 1830 },
    { source: "proxy", count: 1174 },
    { source: "dns", count: 963 },
  ],
  recent_alerts: [
    {
      id: "a-1",
      event_name: "SSH login failed (root/admin123)",
      severity: "high",
      source_ip: "185.220.101.45",
      user_name: "root",
      event_time: new Date(now - 1000 * 45).toISOString(),
      source_family: "cowrie",
    },
    {
      id: "a-2",
      event_name: "PowerShell encoded command observed",
      severity: "critical",
      source_ip: "10.42.0.18",
      user_name: "svc-backup",
      event_time: new Date(now - 1000 * 95).toISOString(),
      source_family: "edr",
    },
    {
      id: "a-3",
      event_name: "DNS TXT query burst anomaly",
      severity: "medium",
      source_ip: "10.42.12.77",
      user_name: "jane.doe",
      event_time: new Date(now - 1000 * 160).toISOString(),
      source_family: "dns",
    },
  ],
  recent_incidents: mockIncidents,
};

export const mockIncidentsList: IncidentListResponse = {
  total: mockIncidents.length,
  page: 1,
  page_size: 50,
  incidents: mockIncidents,
};

const mockDetailMap: Record<string, IncidentDetail> = {
  "inc-001": {
    ...mockIncidents[0],
    primary_dst_ip: "10.42.8.10",
    mitre_tactics: ["Credential Access", "Initial Access"],
    scoring_breakdown: {
      entity_match: 35,
      temporal_proximity: 25,
      technique_overlap: 20,
      anomaly_bonus: 12,
      total: 92,
    },
    alerts: [
      { id: "aa-1", event_name: "Brute-force burst", event_time: new Date(now - 1000 * 60 * 8).toISOString(), severity: "critical" },
      { id: "aa-2", event_name: "Credential reuse pattern", event_time: new Date(now - 1000 * 60 * 6).toISOString(), severity: "high" },
    ],
    summaries: [
      {
        id: "sum-1",
        version: 1,
        generation_type: "deterministic",
        executive_summary:
          "A coordinated credential-stuffing campaign is targeting privileged accounts from rotating VPS infrastructure. Blocking source ranges and enforcing MFA challenge escalation is recommended.",
        root_cause: "Weak password policy on legacy admin accounts",
        confidence_notes: "High confidence from repeated auth failure sequence and IP velocity signals.",
        model_used: "mock-local",
        generated_at: new Date(now - 1000 * 60 * 2).toISOString(),
      },
    ],
    correlation_matches: [
      {
        total_score: 92,
        reason_codes: { same_user: true, same_src_ip_cluster: true, short_time_window: true },
        match_type: "entity+time",
      },
    ],
  },
};

export function getMockIncidentDetail(incidentId: string): IncidentDetail {
  return mockDetailMap[incidentId] ?? {
    ...mockIncidents[1],
    id: incidentId,
    alerts: [
      { id: "fallback-1", event_name: "Suspicious event", severity: "medium", event_time: new Date(now - 1000 * 60).toISOString() },
    ],
    summaries: [
      {
        id: "sum-fallback",
        version: 1,
        generation_type: "deterministic",
        executive_summary: "This is fallback mock data so the UI can be reviewed without backend connectivity.",
        generated_at: new Date(now - 1000 * 30).toISOString(),
      },
    ],
    correlation_matches: [
      { total_score: 60, reason_codes: { fallback: true }, match_type: "fallback" },
    ],
  };
}