import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { animate, createScope, stagger } from "animejs";
import { getIncidents } from "../lib/api";
import type { Incident } from "../types";

function severityClass(severity: string) {
  if (severity === "critical") return "severity-chip severity-critical";
  if (severity === "high") return "severity-chip severity-high";
  if (severity === "medium") return "severity-chip severity-medium";
  return "severity-chip severity-low";
}

function statusClass(status: string) {
  if (status === "in_progress") return "status-chip status-progress";
  if (status === "resolved" || status === "closed") return "status-chip status-resolved";
  if (status === "false_positive") return "status-chip status-muted";
  return "status-chip status-new";
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const data = await getIncidents(1, 50);
        setIncidents(data.incidents);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load incidents");
      } finally {
        setLoading(false);
      }
    }
    void load();
  }, []);

  useEffect(() => {
    const scope = createScope({ root: document.body }).add(() => {
      animate(".inc-reveal", {
        translateY: [18, 0],
        opacity: [0, 1],
        duration: 700,
        easing: "outExpo",
        delay: stagger(75),
      });
    });

    return () => scope.revert();
  }, [incidents, loading]);

  return (
    <section className="space-y-5">
      <div className="inc-reveal rounded-3xl border border-white/10 bg-white/[0.04] p-6 backdrop-blur-xl">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Incident Management</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Queue & Prioritization</h1>
            <p className="mt-2 text-sm text-slate-300">Analyst-oriented list with severity, confidence, and status markers</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3 text-right">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Total incidents</p>
            <p className="mt-1 text-base font-semibold text-white">{incidents.length}</p>
          </div>
        </div>
      </div>

      {loading && <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-6">Loading incidents...</div>}
      {error && <div className="surface-card rounded-2xl border border-aegis-danger/60 bg-white/[0.04] p-6 text-aegis-danger">{error}</div>}

      {!loading && !error && (
        <div className="inc-reveal surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4 overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-left text-xs uppercase tracking-[0.16em] text-slate-400">
                <th className="px-3 py-3">Incident</th>
                <th className="px-3 py-3">Severity</th>
                <th className="px-3 py-3">Score</th>
                <th className="px-3 py-3">Status</th>
                <th className="px-3 py-3">Alerts</th>
                <th className="px-3 py-3">Action</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr key={incident.id} className="table-row-neo border-b border-white/5">
                  <td className="px-3 py-3">
                    <div className="font-medium text-white">{incident.incident_number}</div>
                    <div className="text-xs text-slate-400">{incident.title}</div>
                  </td>
                  <td className="px-3 py-3"><span className={severityClass(incident.severity)}>{incident.severity}</span></td>
                  <td className="px-3 py-3 text-white">{incident.severity_score}</td>
                  <td className="px-3 py-3"><span className={statusClass(incident.status)}>{incident.status.replace("_", " ")}</span></td>
                  <td className="px-3 py-3 text-slate-200">{incident.alert_count}</td>
                  <td className="px-3 py-3">
                    <Link to={`/incidents/${incident.id}`} className="inline-flex rounded-lg border border-white/20 bg-white/5 px-3 py-1.5 text-slate-200 transition hover:border-white/35 hover:bg-white/10">
                      View details
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
