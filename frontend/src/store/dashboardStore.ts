import { create } from "zustand";
import { getDashboardCharts, getDashboardOverview } from "../lib/api";
import type { DashboardCharts, DashboardOverview } from "../types";

type DashboardState = {
  overview: DashboardOverview | null;
  charts: DashboardCharts | null;
  loading: boolean;
  error: string | null;
  lastUpdated: number | null;
  fetchDashboard: () => Promise<void>;
};

export const useDashboardStore = create<DashboardState>((set) => ({
  overview: null,
  charts: null,
  loading: true,
  error: null,
  lastUpdated: null,
  fetchDashboard: async () => {
    set({ loading: true, error: null });
    try {
      const [overview, charts] = await Promise.all([getDashboardOverview(), getDashboardCharts()]);
      set({ overview, charts, loading: false, lastUpdated: Date.now() });
    } catch (error) {
      set({
        loading: false,
        error: error instanceof Error ? error.message : "Failed to load dashboard data",
      });
    }
  },
}));