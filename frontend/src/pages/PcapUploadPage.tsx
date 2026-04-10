import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { animate, createScope, stagger } from "animejs";
import { uploadPcap } from "../lib/api";
import type { PcapUploadResponse } from "../types";

type UploadStage = "idle" | "uploading" | "parsing" | "correlating" | "done" | "error";

const STAGE_LABELS: Record<UploadStage, string> = {
  idle: "Ready for upload",
  uploading: "Uploading file...",
  parsing: "Parsing packets & extracting findings...",
  correlating: "Correlating alerts & scoring incidents...",
  done: "Analysis complete",
  error: "Analysis failed",
};

const STAGE_PROGRESS: Record<UploadStage, number> = {
  idle: 0,
  uploading: 15,
  parsing: 45,
  correlating: 75,
  done: 100,
  error: 0,
};

export default function PcapUploadPage() {
  const [stage, setStage] = useState<UploadStage>("idle");
  const [dragOver, setDragOver] = useState(false);
  const [result, setResult] = useState<PcapUploadResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const scope = createScope({ root: document.body }).add(() => {
      animate(".pcap-reveal", {
        translateY: [18, 0],
        opacity: [0, 1],
        duration: 700,
        easing: "outExpo",
        delay: stagger(70),
      });
    });
    return () => scope.revert();
  }, []);

  useEffect(() => {
    if (result) {
      const scope = createScope({ root: document.body }).add(() => {
        animate(".result-reveal", {
          translateY: [18, 0],
          opacity: [0, 1],
          duration: 700,
          easing: "outExpo",
          delay: stagger(60),
        });
      });
      return () => scope.revert();
    }
  }, [result]);

  const handleFile = useCallback(async (file: File) => {
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (!ext || !["pcap", "pcapng", "cap"].includes(ext)) {
      setError("Invalid file type. Please upload a .pcap or .pcapng file.");
      return;
    }

    if (file.size > 100 * 1024 * 1024) {
      setError("File too large. Maximum size: 100MB.");
      return;
    }

    setSelectedFile(file);
    setError(null);
    setResult(null);
    setStage("uploading");

    try {
      // Simulate stage progression
      setTimeout(() => setStage("parsing"), 800);
      setTimeout(() => setStage("correlating"), 2000);

      const response = await uploadPcap(file);
      setResult(response);
      setStage("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
      setStage("error");
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) void handleFile(file);
  }, [handleFile]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => setDragOver(false), []);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) void handleFile(file);
  }, [handleFile]);

  const handleReset = () => {
    setStage("idle");
    setResult(null);
    setError(null);
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  return (
    <section className="space-y-5">
      {/* Header */}
      <div className="pcap-reveal rounded-3xl border border-white/10 bg-white/[0.04] p-6 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Network Forensics</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">PCAP Analysis</h1>
            <p className="mt-2 text-sm text-slate-300">
              Upload packet captures for automated deep packet inspection, threat detection, and incident correlation
            </p>
          </div>
          <div className="flex items-center gap-2 rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
            <span className="h-2.5 w-2.5 rounded-full bg-aegis-cyan shadow-[0_0_10px_rgba(39,245,255,0.8)]" />
            <span className="text-sm text-slate-200">DPI Engine Online</span>
          </div>
        </div>
      </div>

      {/* Upload Area */}
      <div className="pcap-reveal">
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => stage === "idle" && fileInputRef.current?.click()}
          className={`relative cursor-pointer rounded-2xl border-2 border-dashed p-12 text-center transition-all duration-300 ${
            dragOver
              ? "border-aegis-cyan bg-aegis-cyan/10 shadow-[0_0_40px_rgba(39,245,255,0.15)]"
              : stage === "idle"
              ? "border-white/20 bg-white/[0.03] hover:border-white/40 hover:bg-white/[0.06]"
              : stage === "error"
              ? "border-red-500/40 bg-red-500/5"
              : stage === "done"
              ? "border-emerald-400/40 bg-emerald-400/5"
              : "border-aegis-cyan/40 bg-aegis-cyan/5"
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            onChange={handleInputChange}
            className="hidden"
          />

          {stage === "idle" && !error && (
            <>
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-white/20 bg-white/5">
                <svg className="h-8 w-8 text-aegis-cyan" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                </svg>
              </div>
              <p className="text-lg font-medium text-white">Drop your PCAP file here</p>
              <p className="mt-2 text-sm text-slate-400">or click to browse • Supports .pcap, .pcapng, .cap (max 100MB)</p>
            </>
          )}

          {(stage === "uploading" || stage === "parsing" || stage === "correlating") && (
            <>
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-aegis-cyan/30 bg-aegis-cyan/10">
                <svg className="h-8 w-8 animate-spin text-aegis-cyan" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              </div>
              <p className="text-lg font-medium text-aegis-cyan">{STAGE_LABELS[stage]}</p>
              {selectedFile && (
                <p className="mt-2 text-sm text-slate-400">{selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)</p>
              )}
              {/* Progress bar */}
              <div className="mx-auto mt-4 h-1.5 w-64 rounded-full bg-white/10">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-aegis-cyan to-aegis-purple transition-all duration-1000"
                  style={{ width: `${STAGE_PROGRESS[stage]}%` }}
                />
              </div>
            </>
          )}

          {stage === "done" && (
            <>
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-emerald-400/30 bg-emerald-400/10">
                <svg className="h-8 w-8 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="text-lg font-medium text-emerald-400">Analysis Complete</p>
              {selectedFile && (
                <p className="mt-2 text-sm text-slate-400">{selectedFile.name}</p>
              )}
            </>
          )}

          {(stage === "error" || error) && (
            <>
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-red-500/30 bg-red-500/10">
                <svg className="h-8 w-8 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                </svg>
              </div>
              <p className="text-lg font-medium text-red-400">{error || "Analysis failed"}</p>
              <button
                onClick={(e) => { e.stopPropagation(); handleReset(); }}
                className="mt-3 rounded-lg border border-white/20 bg-white/5 px-4 py-2 text-sm text-white transition hover:bg-white/10"
              >
                Try Again
              </button>
            </>
          )}
        </div>
      </div>

      {/* Results */}
      {result && stage === "done" && (
        <div className="space-y-4">
          {/* Stats Grid */}
          <div className="result-reveal grid gap-4 sm:grid-cols-3">
            <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4 text-center">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Alerts Generated</p>
              <p className="mt-2 text-3xl font-bold text-aegis-cyan">{result.alerts_generated}</p>
            </div>
            <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4 text-center">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Incidents Created</p>
              <p className="mt-2 text-3xl font-bold text-aegis-pink">{result.incidents_created.length}</p>
            </div>
            <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-4 text-center">
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">File Size</p>
              <p className="mt-2 text-3xl font-bold text-white">
                {result.file_size_bytes > 1024 * 1024
                  ? `${(result.file_size_bytes / (1024 * 1024)).toFixed(1)} MB`
                  : `${(result.file_size_bytes / 1024).toFixed(1)} KB`}
              </p>
            </div>
          </div>

          {/* Message */}
          <div className="result-reveal rounded-2xl border border-white/10 bg-white/[0.04] p-4">
            <p className="text-sm text-slate-200">{result.message}</p>
          </div>

          {/* Incident Links */}
          {result.incidents_created.length > 0 && (
            <div className="result-reveal rounded-2xl border border-white/10 bg-white/[0.04] p-4">
              <h3 className="panel-title">Linked Incidents</h3>
              <div className="mt-3 space-y-2">
                {result.incidents_created.map((incidentId) => (
                  <Link
                    key={incidentId}
                    to={`/incidents/${incidentId}`}
                    className="incident-row block rounded-xl border border-white/10 bg-black/20 p-3"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-white">Incident {incidentId.slice(0, 8)}...</span>
                      <span className="rounded-lg border border-aegis-cyan/30 bg-aegis-cyan/10 px-2 py-1 text-xs text-aegis-cyan">
                        View →
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="result-reveal flex flex-wrap gap-3">
            <button
              onClick={handleReset}
              className="rounded-xl border border-white/20 bg-white/5 px-5 py-2.5 text-sm font-medium text-white transition hover:border-white/35 hover:bg-white/10"
            >
              Upload Another PCAP
            </button>
            <Link
              to="/incidents"
              className="rounded-xl border border-aegis-cyan/35 bg-aegis-cyan/10 px-5 py-2.5 text-sm font-medium text-aegis-cyan transition hover:bg-aegis-cyan/20"
            >
              View All Incidents →
            </Link>
          </div>
        </div>
      )}

      {/* Info Panel */}
      <div className="pcap-reveal rounded-2xl border border-white/10 bg-white/[0.04] p-5">
        <h3 className="panel-title">Analysis Capabilities</h3>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[
            { title: "Port Scan Detection", desc: "SYN scans, connect scans, stealth scanning patterns" },
            { title: "SSH Brute Force", desc: "Automated credential guessing attack detection" },
            { title: "DNS Analysis", desc: "DGA domains, DNS tunneling, anomalous queries" },
            { title: "Payload Inspection", desc: "Shell commands, encoded payloads, malware indicators" },
            { title: "HTTP Attack Signatures", desc: "Path traversal, SQL injection, XSS patterns" },
            { title: "Data Exfiltration", desc: "Unusual outbound transfer volume detection" },
          ].map((cap) => (
            <div key={cap.title} className="rounded-xl border border-white/10 bg-black/20 p-3">
              <p className="text-sm font-medium text-white">{cap.title}</p>
              <p className="mt-1 text-xs text-slate-400">{cap.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
