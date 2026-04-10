import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { animate, createScope, stagger } from "animejs";
import { getIncidentDetail } from "../lib/api";
import type { IncidentDetail } from "../types";

function severityClass(severity: string) {
  if (severity === "critical") return "severity-chip severity-critical";
  if (severity === "high") return "severity-chip severity-high";
  if (severity === "medium") return "severity-chip severity-medium";
  return "severity-chip severity-low";
}

export default function IncidentDetailPage() {
  const { incidentId } = useParams();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!incidentId) return;
    const id = incidentId;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const data = await getIncidentDetail(id);
        setIncident(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load incident detail");
      } finally {
        setLoading(false);
      }
    }
    void load();
  }, [incidentId]);

  useEffect(() => {
    const scope = createScope({ root: document.body }).add(() => {
      animate(".detail-reveal", {
        translateY: [18, 0],
        opacity: [0, 1],
        duration: 700,
        easing: "outExpo",
        delay: stagger(80),
      });
    });

    return () => scope.revert();
  }, [incident, loading]);

  if (loading) return <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-6">Loading incident details...</div>;
  if (error) return <div className="surface-card rounded-2xl border border-aegis-danger/60 bg-white/[0.04] p-6 text-aegis-danger">{error}</div>;
  if (!incident) return <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-6">Incident not found.</div>;

  return (
    <section className="space-y-5">
      <div className="detail-reveal rounded-3xl border border-white/10 bg-white/[0.04] p-6 backdrop-blur-xl">
        <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Incident Dossier</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">{incident.incident_number}</h1>
        <p className="mt-2 text-base text-slate-200">{incident.title}</p>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <span className="rounded-md border border-white/20 bg-white/5 px-2 py-1 text-xs text-slate-300">{incident.classification}</span>
          <span className={severityClass(incident.severity)}>{incident.severity}</span>
          <span className="rounded-md border border-white/20 bg-white/5 px-2 py-1 text-xs text-slate-300">score {incident.severity_score}</span>
          <span className="rounded-md border border-white/20 bg-white/5 px-2 py-1 text-xs text-slate-300">{incident.status.replace("_", " ")}</span>
        </div>
      </div>

      <div className="detail-reveal grid gap-4 xl:grid-cols-2">
        <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
          <h3 className="panel-title">Correlation & Scoring</h3>
          <pre className="mt-3 max-h-72 overflow-auto rounded-xl border border-white/10 bg-black/20 p-3 text-xs text-slate-200">
            {JSON.stringify(incident.scoring_breakdown ?? {}, null, 2)}
          </pre>
        </div>
        <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
          <h3 className="panel-title">MITRE Mapping</h3>
          <div className="mt-3 flex flex-wrap gap-2">
            {(incident.mitre_techniques ?? []).map((tech) => (
              <span key={tech} className="rounded-lg border border-white/20 bg-white/5 px-2 py-1 text-xs text-slate-200">
                {tech}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="detail-reveal surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
        <h3 className="panel-title">AI Summary</h3>
        {incident.summaries.length === 0 ? (
          <p className="mt-3 text-sm text-slate-400">No summary generated yet.</p>
        ) : (
          <article className="mt-3 rounded-xl border border-white/10 bg-black/20 p-4">
            <p className="text-sm leading-6 text-slate-200">{incident.summaries[0].executive_summary}</p>
            {incident.summaries[0].root_cause && (
              <p className="mt-3 rounded-lg border border-aegis-pink/35 bg-aegis-pink/10 px-3 py-2 text-sm text-aegis-pink">Root cause: {incident.summaries[0].root_cause}</p>
            )}
          </article>
        )}
      </div>

      <div className="detail-reveal surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
        <h3 className="panel-title">Timeline Alerts</h3>
        <div className="mt-3 space-y-2">
          {incident.alerts.map((alert) => (
            <div key={alert.id} className="alert-row rounded-xl border border-white/10 bg-black/20 p-3 text-sm text-slate-200">
              <p className="text-white">{alert.event_name}</p>
              <p className="mt-1 text-xs text-slate-400">
                <span className={severityClass(alert.severity)}>{alert.severity}</span>
                <span className="ml-2">{alert.event_time ? new Date(alert.event_time).toLocaleString() : "-"}</span>
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
