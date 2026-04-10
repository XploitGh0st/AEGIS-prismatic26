import { useEffect } from "react";
import { Link } from "react-router-dom";
import { animate, createScope, stagger } from "animejs";
import { useDashboardStore } from "../store/dashboardStore";
import KpiCard from "../components/KpiCard";
import { SeverityChart, SourceChart } from "../components/charts";

export default function DashboardPage() {
  const { overview, charts, loading, error, lastUpdated, fetchDashboard } = useDashboardStore();

  useEffect(() => {
    void fetchDashboard();
    const interval = window.setInterval(() => {
      void fetchDashboard();
    }, 8000);
    return () => window.clearInterval(interval);
  }, [fetchDashboard]);

  useEffect(() => {
    const scope = createScope({ root: document.body }).add(() => {
      animate(".dash-reveal", {
        translateY: [18, 0],
        opacity: [0, 1],
        easing: "outExpo",
        duration: 700,
        delay: stagger(70),
      });
    });

    return () => scope.revert();
  }, [overview, charts]);

  if (loading && !overview) {
    return <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-6 text-aegis-cyan">Syncing tactical telemetry...</div>;
  }

  if (error) {
    return <div className="surface-card rounded-2xl border border-aegis-danger/60 bg-white/[0.04] p-6 text-aegis-danger">Connection fault: {error}</div>;
  }

  return (
    <section className="space-y-5">
      <div className="dash-reveal rounded-3xl border border-white/10 bg-white/[0.04] p-6 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Command Center</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Security Overview</h1>
            <p className="mt-2 text-sm text-slate-300">Operational visibility for alert flow, incident pressure, and response pacing</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3 text-right">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Last refresh</p>
            <p className="mt-1 text-base font-semibold text-white">
              {lastUpdated ? new Date(lastUpdated).toLocaleTimeString() : "-"}
            </p>
          </div>
        </div>
      </div>

      {overview && (
        <div className="dash-reveal grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <KpiCard label={overview.total_alerts_ingested.label} value={overview.total_alerts_ingested.value} />
          <KpiCard label={overview.open_incidents.label} value={overview.open_incidents.value} />
          <KpiCard label={overview.critical_incidents.label} value={overview.critical_incidents.value} />
          <KpiCard label={overview.avg_alerts_per_incident.label} value={overview.avg_alerts_per_incident.value} />
        </div>
      )}

      {charts && (
        <div className="dash-reveal grid gap-4 xl:grid-cols-2">
          <SeverityChart data={charts.severity_distribution} />
          <SourceChart data={charts.alerts_by_source} />
        </div>
      )}

      {charts && (
        <div className="dash-reveal grid gap-4 xl:grid-cols-2">
          <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
            <h3 className="panel-title">Live Alert Feed</h3>
            <div className="mt-4 space-y-2">
              {charts.recent_alerts.slice(0, 8).map((alert) => (
                <div key={alert.id} className="alert-row rounded-xl border border-white/10 bg-black/20 p-3">
                  <p className="text-sm font-medium text-white">{alert.event_name}</p>
                  <p className="text-xs text-slate-400">
                    {alert.source_family} • {alert.source_ip ?? "-"} • {new Date(alert.event_time).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          </div>

          <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
            <h3 className="panel-title">Latest Incidents</h3>
            <div className="mt-4 space-y-2">
              {charts.recent_incidents.slice(0, 8).map((inc) => (
                <Link
                  key={inc.id}
                  to={`/incidents/${inc.id}`}
                  className="incident-row block rounded-xl border border-white/10 bg-black/20 p-3"
                >
                  <p className="text-sm font-medium text-white">{inc.incident_number} — {inc.title}</p>
                  <p className="text-xs text-slate-400">
                    {inc.severity.toUpperCase()} • score {inc.severity_score} • {inc.status}
                  </p>
                </Link>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
