import { useEffect, useState } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { getMemPalaceStatus } from "../lib/api";

const navLinkClasses = ({ isActive }: { isActive: boolean }) =>
  `sidebar-link rounded-xl px-3 py-2 text-sm font-medium transition ${
    isActive
      ? "bg-white text-slate-900"
      : "text-slate-300 hover:bg-white/10 hover:text-white"
  }`;

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const [mempalaceOnline, setMempalaceOnline] = useState(false);

  useEffect(() => {
    getMemPalaceStatus()
      .then((status) => setMempalaceOnline(status.available))
      .catch(() => setMempalaceOnline(false));
  }, []);

  const pageLabel = () => {
    if (location.pathname === "/") return "Overview";
    if (location.pathname === "/pcap") return "PCAP Analysis";
    if (location.pathname === "/incidents") return "Incident Queue";
    if (location.pathname.startsWith("/incidents/")) return "Incident Dossier";
    return location.pathname;
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-aegis-bg text-slate-100">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(39,245,255,0.14),transparent_30%),radial-gradient(circle_at_80%_10%,rgba(255,47,191,0.14),transparent_28%),radial-gradient(circle_at_40%_80%,rgba(142,77,255,0.12),transparent_35%)]" />
      <div className="noise-overlay pointer-events-none absolute inset-0 opacity-30" />
      <div className="grid-overlay pointer-events-none absolute inset-0 opacity-20" />
      <div className="scanline pointer-events-none absolute inset-0 opacity-25" />
      <div className="orb orb-cyan pointer-events-none absolute -left-20 top-20" />
      <div className="orb orb-pink pointer-events-none absolute right-6 top-40" />

      <div className="relative z-10 flex min-h-screen gap-5 p-5">
        <aside className="app-sidebar w-72 shrink-0 rounded-3xl border border-white/10 bg-aegis-panel/60 p-5 backdrop-blur-xl">
          <Link to="/" className="block rounded-2xl border border-white/10 bg-white/5 p-4">
            <p className="text-xs uppercase tracking-[0.25em] text-aegis-cyan">AEGIS</p>
            <p className="mt-2 text-xl font-semibold text-white">Operations Hub</p>
            <p className="mt-1 text-xs text-slate-400">Threat intelligence workspace</p>
          </Link>

          <nav className="mt-6 space-y-2">
            <NavLink to="/" className={navLinkClasses} end>
              <span className="mr-2">◆</span> Overview
            </NavLink>
            <NavLink to="/incidents" className={navLinkClasses}>
              <span className="mr-2">◆</span> Incident Queue
            </NavLink>
            <NavLink to="/pcap" className={navLinkClasses}>
              <span className="mr-2">◆</span> PCAP Analysis
            </NavLink>
          </nav>

          <div className="mt-8 space-y-3">
            <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">System State</p>
              <div className="mt-3 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.8)]" />
                  <span className="text-sm text-slate-200">Telemetry Online</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`h-2.5 w-2.5 rounded-full ${
                    mempalaceOnline
                      ? "bg-aegis-purple shadow-[0_0_10px_rgba(142,77,255,0.8)]"
                      : "bg-slate-500"
                  }`} />
                  <span className="text-sm text-slate-200">
                    MemPalace {mempalaceOnline ? "Active" : "Offline"}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-aegis-cyan shadow-[0_0_10px_rgba(39,245,255,0.8)]" />
                  <span className="text-sm text-slate-200">DPI Engine Ready</span>
                </div>
              </div>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col gap-4">
          <header className="topbar rounded-2xl border border-white/10 bg-aegis-panel/55 px-5 py-4 backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Navigation</p>
                <p className="mt-1 text-sm text-white">{pageLabel()}</p>
              </div>
              <div className="flex items-center gap-3">
                <div className="rounded-full border border-white/15 bg-white/5 px-3 py-1 text-xs text-slate-300">Cyber Ops</div>
                <div className="rounded-full border border-aegis-cyan/35 bg-aegis-cyan/10 px-3 py-1 text-xs text-aegis-cyan">Live</div>
              </div>
            </div>
          </header>

          <main className="app-main min-w-0">{children}</main>
        </div>
      </div>
    </div>
  );
}