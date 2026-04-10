export default function KpiCard({ label, value }: { label: string; value: string | number }) {
  return (
    <article className="metric-card group relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.04] p-5 transition hover:-translate-y-0.5">
      <div className="metric-glow absolute -right-10 -top-10 h-24 w-24 rounded-full bg-aegis-cyan/15 blur-2xl transition group-hover:bg-aegis-pink/15" />
      <p className="text-xs uppercase tracking-[0.22em] text-slate-400">{label}</p>
      <p className="mt-3 text-3xl font-semibold text-white">{value}</p>
      <p className="mt-1 text-xs text-slate-400">Updated from active stream</p>
    </article>
  );
}