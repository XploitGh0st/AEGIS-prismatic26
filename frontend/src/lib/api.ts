import axios from "axios";
import type {
  AttackerIntel,
  AttackerTimeline,
  DashboardCharts,
  DashboardOverview,
  IncidentDetail,
  IncidentListResponse,
  MemPalaceStatus,
  MemorySearchResult,
  PcapUploadResponse,
} from "../types";
import {
  getMockIncidentDetail,
  mockDashboardCharts,
  mockDashboardOverview,
  mockIncidentsList,
} from "../mocks/sampleData";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
  timeout: 30000,
});

const useMockData = import.meta.env.VITE_USE_MOCK_DATA === "true";

function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withMockFallback<T>(
  apiCall: () => Promise<T>,
  mockFactory: () => T,
): Promise<T> {
  if (useMockData) {
    await wait(250);
    return mockFactory();
  }

  try {
    return await apiCall();
  } catch {
    await wait(150);
    return mockFactory();
  }
}

// ── Dashboard ───────────────────────────────────────────

export async function getDashboardOverview() {
  return withMockFallback(
    async () => {
      const { data } = await api.get<DashboardOverview>("/api/v1/dashboard/overview");
      return data;
    },
    () => mockDashboardOverview,
  );
}

export async function getDashboardCharts() {
  return withMockFallback(
    async () => {
      const { data } = await api.get<DashboardCharts>("/api/v1/dashboard/charts");
      return data;
    },
    () => mockDashboardCharts,
  );
}

// ── Incidents ───────────────────────────────────────────

export async function getIncidents(page = 1, pageSize = 20) {
  return withMockFallback(
    async () => {
      const { data } = await api.get<IncidentListResponse>("/api/v1/incidents", {
        params: { page, page_size: pageSize },
      });
      return data;
    },
    () => ({ ...mockIncidentsList, page, page_size: pageSize }),
  );
}

export async function getIncidentDetail(incidentId: string) {
  return withMockFallback(
    async () => {
      const { data } = await api.get<IncidentDetail>(`/api/v1/incidents/${incidentId}`);
      return data;
    },
    () => getMockIncidentDetail(incidentId),
  );
}

export async function generateSummary(incidentId: string, force = false) {
  const { data } = await api.post(`/api/v1/incidents/${incidentId}/generate-summary`, null, {
    params: { force, sync_processing: true, generation_type: "deterministic" },
  });
  return data;
}

// ── PCAP Upload ─────────────────────────────────────────

export async function uploadPcap(file: File): Promise<PcapUploadResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const { data } = await api.post<PcapUploadResponse>("/api/v1/pcap/upload", formData, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 120000, // 2 minutes for large files
  });
  return data;
}

// ── PDF Report ──────────────────────────────────────────

export async function downloadIncidentReport(incidentId: string) {
  const response = await api.get(`/api/v1/reports/incidents/${incidentId}/pdf`, {
    responseType: "blob",
    timeout: 60000,
  });

  // Create download link
  const blob = new Blob([response.data], { type: "application/pdf" });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;

  // Get filename from Content-Disposition header or default
  const disposition = response.headers["content-disposition"];
  let filename = `AEGIS_Report.pdf`;
  if (disposition) {
    const match = disposition.match(/filename="?(.+?)"?$/);
    if (match) filename = match[1];
  }

  link.setAttribute("download", filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

// ── MemPalace ───────────────────────────────────────────

export async function getMemPalaceStatus(): Promise<MemPalaceStatus> {
  const { data } = await api.get<MemPalaceStatus>("/api/v1/memory/status");
  return data;
}

export async function getAttackerIntel(ip: string): Promise<AttackerIntel> {
  const { data } = await api.get<AttackerIntel>(`/api/v1/memory/attackers/${ip}`);
  return data;
}

export async function getAttackerTimeline(ip: string): Promise<AttackerTimeline> {
  const { data } = await api.get<AttackerTimeline>(`/api/v1/memory/attackers/${ip}/timeline`);
  return data;
}

export async function searchMemory(query: string, wing = "wing_incidents"): Promise<MemorySearchResult[]> {
  const { data } = await api.get<{ results: MemorySearchResult[] }>("/api/v1/memory/search", {
    params: { q: query, wing },
  });
  return data.results;
}