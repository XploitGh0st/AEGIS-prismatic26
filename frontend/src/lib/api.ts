import axios from "axios";
import type { DashboardCharts, DashboardOverview, IncidentDetail, IncidentListResponse } from "../types";
import {
  getMockIncidentDetail,
  mockDashboardCharts,
  mockDashboardOverview,
  mockIncidentsList,
} from "../mocks/sampleData";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8000",
  timeout: 10000,
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