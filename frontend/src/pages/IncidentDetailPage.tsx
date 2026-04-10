import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { animate, createScope, stagger } from "animejs";
import { downloadIncidentReport, generateSummary, getAttackerIntel, getIncidentDetail } from "../lib/api";
import type { AttackerIntel, IncidentDetail } from "../types";

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
  const [downloading, setDownloading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [attackerIntel, setAttackerIntel] = useState<AttackerIntel | null>(null);

  useEffect(() => {
    if (!incidentId) return;
    const id = incidentId;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const data = await getIncidentDetail(id);
        setIncident(data);

        // Load attacker intel if we have a source IP
        if (data.primary_src_ip) {
          try {
            const intel = await getAttackerIntel(data.primary_src_ip);
            if (intel.total > 0) setAttackerIntel(intel);
          } catch {
            // MemPalace may not be available
          }
        }
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

  const handleDownloadPdf = async () => {
    if (!incidentId) return;
    setDownloading(true);
    try {
      await downloadIncidentReport(incidentId);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to download report");
    } finally {
      setDownloading(false);
    }
  };

  const handleGenerateSummary = async () => {
    if (!incidentId) return;
    setGenerating(true);
    try {
      await generateSummary(incidentId, true);
      // Reload incident to get new summary
      const data = await getIncidentDetail(incidentId);
      setIncident(data);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to generate summary");
    } finally {
      setGenerating(false);
    }
  };

  if (loading) return <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-6 text-aegis-cyan">Loading incident details...</div>;
  if (error) return <div className="surface-card rounded-2xl border border-aegis-danger/60 bg-white/[0.04] p-6 text-aegis-danger">{error}</div>;
  if (!incident) return <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-6">Incident not found.</div>;

  return (
    <section className="space-y-5">
      {/* Header */}
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

        {/* Action Buttons */}
        <div className="mt-5 flex flex-wrap gap-3">
          <button
            onClick={handleDownloadPdf}
            disabled={downloading}
            className="flex items-center gap-2 rounded-xl border border-aegis-cyan/35 bg-aegis-cyan/10 px-4 py-2.5 text-sm font-medium text-aegis-cyan transition hover:bg-aegis-cyan/20 disabled:opacity-50"
          >
            {downloading ? (
              <>
                <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Generating PDF...
              </>
            ) : (
              <>
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
                </svg>
                Download Investigation Report
              </>
            )}
          </button>

          <button
            onClick={handleGenerateSummary}
            disabled={generating}
            className="flex items-center gap-2 rounded-xl border border-white/20 bg-white/5 px-4 py-2.5 text-sm font-medium text-white transition hover:border-white/35 hover:bg-white/10 disabled:opacity-50"
          >
            {generating ? (
              <>
                <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Generating...
              </>
            ) : (
              <>
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
                </svg>
                Regenerate Summary
              </>
            )}
          </button>
        </div>
      </div>

      {/* Entities: Quick Facts */}
      <div className="detail-reveal grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "Primary User", value: incident.primary_user || "—" },
          { label: "Primary Host", value: incident.primary_host || "—" },
          { label: "Source IP", value: incident.primary_src_ip || "—" },
          { label: "Alert Count", value: String(incident.alert_count) },
        ].map((item) => (
          <div key={item.label} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
            <p className="text-xs uppercase tracking-[0.2em] text-slate-400">{item.label}</p>
            <p className="mt-2 text-lg font-semibold text-white">{item.value}</p>
          </div>
        ))}
      </div>

      {/* AI Summary */}
      <div className="detail-reveal surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
        <h3 className="panel-title">AI Investigation Summary</h3>
        {incident.summaries.length === 0 ? (
          <p className="mt-3 text-sm text-slate-400">No summary generated yet. Click "Regenerate Summary" above.</p>
        ) : (
          <article className="mt-3 space-y-3">
            <div className="rounded-xl border border-white/10 bg-black/20 p-4">
              <p className="text-sm leading-6 text-slate-200">{incident.summaries[0].executive_summary}</p>
            </div>
            {incident.summaries[0].root_cause && (
              <div className="rounded-xl border border-aegis-pink/35 bg-aegis-pink/10 p-3">
                <p className="text-xs uppercase tracking-[0.15em] text-aegis-pink/70">Root Cause</p>
                <p className="mt-1 text-sm text-aegis-pink">{incident.summaries[0].root_cause}</p>
              </div>
            )}
            {incident.summaries[0].observed_facts && incident.summaries[0].observed_facts.length > 0 && (
              <div className="rounded-xl border border-white/10 bg-black/20 p-4">
                <p className="text-xs uppercase tracking-[0.15em] text-slate-400 mb-2">Observed Facts</p>
                <ul className="space-y-1">
                  {incident.summaries[0].observed_facts.map((fact, i) => (
                    <li key={i} className="text-sm text-slate-200">• {fact}</li>
                  ))}
                </ul>
              </div>
            )}
            {incident.summaries[0].recommended_actions && incident.summaries[0].recommended_actions.length > 0 && (
              <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-4">
                <p className="text-xs uppercase tracking-[0.15em] text-emerald-400/70 mb-2">Recommended Actions</p>
                <ol className="space-y-1 list-decimal list-inside">
                  {incident.summaries[0].recommended_actions.map((action, i) => (
                    <li key={i} className="text-sm text-slate-200">{action}</li>
                  ))}
                </ol>
              </div>
            )}
            <p className="text-xs text-slate-500">
              Generated via {incident.summaries[0].generation_type} • {incident.summaries[0].model_used || "deterministic engine"}
            </p>
          </article>
        )}
      </div>

      {/* Correlation & MITRE Grid */}
      <div className="detail-reveal grid gap-4 xl:grid-cols-2">
        <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
          <h3 className="panel-title">Correlation Matches</h3>
          {incident.correlation_matches.length > 0 ? (
            <div className="mt-3 space-y-2">
              {incident.correlation_matches.map((match, i) => (
                <div key={i} className="rounded-xl border border-white/10 bg-black/20 p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-white">Score: {match.total_score}</span>
                    <span className="rounded-lg border border-white/20 bg-white/5 px-2 py-0.5 text-xs text-slate-300">
                      {match.match_type}
                    </span>
                  </div>
                  {match.matched_entity && (
                    <p className="mt-1 text-xs text-slate-400">Entity: {match.matched_entity}</p>
                  )}
                  <div className="mt-2 flex flex-wrap gap-1">
                    {Object.entries(match.reason_codes || {}).map(([rule, pts]) => (
                      <span key={rule} className="rounded border border-white/15 bg-white/5 px-1.5 py-0.5 text-[10px] text-slate-300">
                        {rule}: +{String(pts)}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-400">New incident — no correlation matches.</p>
          )}
        </div>

        <div className="surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
          <h3 className="panel-title">MITRE ATT&CK Mapping</h3>
          <div className="mt-3 flex flex-wrap gap-2">
            {(incident.mitre_techniques ?? []).map((tech) => (
              <span key={tech} className="rounded-lg border border-aegis-purple/35 bg-aegis-purple/10 px-2.5 py-1 text-xs text-slate-200">
                {tech}
              </span>
            ))}
            {(incident.mitre_techniques ?? []).length === 0 && (
              <p className="text-sm text-slate-400">No techniques mapped.</p>
            )}
          </div>
          {incident.mitre_tactics && incident.mitre_tactics.length > 0 && (
            <div className="mt-3">
              <p className="text-xs text-slate-400">Tactics: {incident.mitre_tactics.join(", ")}</p>
            </div>
          )}

          <div className="mt-4">
            <h3 className="panel-title">Scoring Breakdown</h3>
            {incident.scoring_breakdown && Object.keys(incident.scoring_breakdown).length > 0 ? (
              <div className="mt-2 space-y-1">
                {Object.entries(incident.scoring_breakdown).map(([key, val]) => (
                  <div key={key} className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">{key}</span>
                    <span className="text-white">{String(val)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-sm text-slate-400">No breakdown available.</p>
            )}
          </div>
        </div>
      </div>

      {/* Attacker Intelligence (MemPalace) */}
      {attackerIntel && attackerIntel.total > 0 && (
        <div className="detail-reveal surface-card rounded-2xl border border-aegis-purple/25 bg-aegis-purple/[0.04] p-4">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-aegis-purple shadow-[0_0_10px_rgba(142,77,255,0.8)]" />
            <h3 className="panel-title">Attacker Intelligence (MemPalace)</h3>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Known intelligence about {attackerIntel.ip} from the AEGIS knowledge graph
          </p>
          <div className="mt-3 space-y-2">
            {attackerIntel.triples.map((triple, i) => (
              <div key={i} className="rounded-xl border border-white/10 bg-black/20 p-3">
                <div className="flex items-center gap-2">
                  <span className="rounded border border-aegis-purple/30 bg-aegis-purple/15 px-1.5 py-0.5 text-[10px] text-aegis-purple">
                    {triple.predicate}
                  </span>
                  <span className="text-sm text-white">{triple.object}</span>
                </div>
                <p className="mt-1 text-xs text-slate-500">Since: {triple.valid_from}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Timeline */}
      <div className="detail-reveal surface-card rounded-2xl border border-white/10 bg-white/[0.04] p-4">
        <h3 className="panel-title">Attack Timeline</h3>
        <div className="mt-3 space-y-2">
          {incident.alerts.map((alert, i) => (
            <div key={alert.id} className="alert-row flex items-start gap-3 rounded-xl border border-white/10 bg-black/20 p-3">
              {/* Timeline connector */}
              <div className="flex flex-col items-center pt-1">
                <span className={`h-3 w-3 rounded-full ${
                  alert.severity === "critical" ? "bg-red-400" :
                  alert.severity === "high" ? "bg-amber-400" :
                  alert.severity === "medium" ? "bg-aegis-cyan" : "bg-emerald-400"
                }`} />
                {i < incident.alerts.length - 1 && (
                  <span className="mt-1 h-6 w-px bg-white/10" />
                )}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium text-white">{alert.event_name}</p>
                  <span className={severityClass(alert.severity)}>{alert.severity}</span>
                </div>
                {alert.description && (
                  <p className="mt-1 text-xs text-slate-300">{alert.description}</p>
                )}
                <p className="mt-1 text-xs text-slate-500">
                  {alert.event_time ? new Date(alert.event_time).toLocaleString() : "—"}
                  {alert.source_ip && ` • ${alert.source_ip}`}
                  {alert.source_family && ` • [${alert.source_family.toUpperCase()}]`}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
