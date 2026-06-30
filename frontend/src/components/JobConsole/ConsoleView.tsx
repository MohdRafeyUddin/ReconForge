/**
 * ConsoleView – PURE DISPLAY COMPONENT.
 *
 * This component owns NO WebSocket connection of its own.
 * All live data flows in via props from the single WebSocket
 * managed exclusively in App.tsx (MainDashboard).
 *
 * Do NOT add WebSocket / setInterval / apiCall here.
 */
import React, { useEffect, useRef } from "react";
import { Terminal, RefreshCw, XCircle, CheckCircle2, AlertCircle } from "lucide-react";

interface Job {
  id: string;
  provider_name: string;
  status: string;
  started_at: string;
  finished_at?: string | null;
}

interface ConsoleViewProps {
  activeJob: Job | null;
  /** Plain domain-name strings for the live feed, derived in App.tsx from the shared subdomains state. */
  subdomainNames: string[];
  /** Per-provider discovered counts, derived from stats.provider_counts in App.tsx. */
  providerStats: Record<string, number>;
  /** Set of providers whose streaming has finished. */
  completedProviders: Set<string>;
  onClose: () => void;
}

const PROVIDER_COLORS: Record<string, string> = {
  subfinder:   "#3B82F6",
  assetfinder: "#06B6D4",
  amass:       "#10B981",
  chaos:       "#F59E0B",
};

const PROVIDER_ORDER = ["subfinder", "assetfinder", "amass", "chaos"];

export const ConsoleView: React.FC<ConsoleViewProps> = ({
  activeJob,
  subdomainNames,
  providerStats,
  completedProviders,
  onClose,
}) => {
  const listBottomRef = useRef<HTMLDivElement>(null);

  // Mount/unmount diagnostic logs (temporary – remove after verification)
  useEffect(() => {
    console.log("[ConsoleView] Component mounted", { jobId: activeJob?.id });
    return () => {
      console.log("[ConsoleView] Component unmounted", { jobId: activeJob?.id });
    };
  }, [activeJob?.id]);

  // Auto-scroll subdomain list when new entries arrive
  useEffect(() => {
    listBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [subdomainNames.length]);

  if (!activeJob) return null;

  const status     = activeJob.status;
  const isUnified  = activeJob.provider_name === "Unified Discovery";
  const displayCount = subdomainNames.length > 0 ? subdomainNames.length : "-";

  const statusColor =
    status === "completed" ? "#10B981"
    : status === "running" ? "#06B6D4"
    : status === "failed"  ? "#EF4444"
    : "#F59E0B";

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass shadow-2xl overflow-hidden flex flex-col glow-blue">

      {/* Header */}
      <div className="bg-dark-bg border-b border-dark-border px-4 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-2.5">
          <Terminal className="w-4 h-4 text-cyber-accent" />
          <span className="font-mono text-xs font-bold text-slate-300 uppercase tracking-widest">
            {activeJob.provider_name} | Job {activeJob.id.substring(0, 8)}...
          </span>
          <span
            className="px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase border"
            style={{ backgroundColor: `${statusColor}18`, borderColor: statusColor, color: statusColor }}
          >
            {status}
          </span>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-slate-400 hover:text-white rounded transition-colors cursor-pointer"
        >
          <XCircle className="w-5 h-5" />
        </button>
      </div>

      {/* Body */}
      <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-5">

        {/* Left: metrics + provider breakdown */}
        <div className="flex flex-col gap-4">

          {/* Status card */}
          <div className="bg-dark-bg border border-dark-border rounded-lg p-4 relative overflow-hidden">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-2">Scan Status</span>
            <div className="flex items-center gap-2">
              {status === "completed" ? (
                <CheckCircle2 className="w-5 h-5" style={{ color: statusColor }} />
              ) : status === "failed" ? (
                <AlertCircle className="w-5 h-5" style={{ color: statusColor }} />
              ) : (
                <RefreshCw className="w-5 h-5 animate-spin" style={{ color: statusColor }} />
              )}
              <span className="text-base font-mono font-bold uppercase" style={{ color: statusColor }}>
                {status}
              </span>
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-2">
              Started: {new Date(activeJob.started_at).toLocaleTimeString()}
            </div>
          </div>

          {/* Total discovered */}
          <div className="bg-dark-bg border border-dark-border rounded-lg p-4">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-1">
              {isUnified ? "Total Unique Subdomains" : "Discovered Assets"}
            </span>
            <div className="text-3xl font-mono font-bold text-cyber-accent">{displayCount}</div>
            <div className="text-[10px] font-mono text-slate-500 mt-1">
              {isUnified ? "After deduplication" : "unique subdomains"}
            </div>
          </div>

          {/* Per-provider breakdown (Unified only) */}
          {isUnified && (
            <div className="bg-dark-bg border border-dark-border rounded-lg p-4 space-y-2">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-2">Provider Yield</span>
              {PROVIDER_ORDER.map((tool) => {
                const count = providerStats[tool] ?? 0;
                const done  = completedProviders.has(tool) || status === "completed" || status === "failed";
                const color = PROVIDER_COLORS[tool] ?? "#6B7280";
                return (
                  <div key={tool} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {done ? (
                        <CheckCircle2 className="w-3.5 h-3.5" style={{ color }} />
                      ) : (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" style={{ color }} />
                      )}
                      <span className="text-xs font-mono capitalize" style={{ color }}>{tool}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-slate-300">
                      {count > 0 ? count : done ? "0" : "…"}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: scrollable subdomain list */}
        <div className="md:col-span-2 bg-dark-bg border border-dark-border rounded-lg p-4 flex flex-col">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-3 border-b border-dark-border pb-2 block">
            Discovered Subdomains ({subdomainNames.length})
          </span>
          <div className="flex-1 overflow-y-auto space-y-1 max-h-64 pr-1">
            {subdomainNames.length === 0 ? (
              <div className="flex items-center justify-center h-24 text-slate-500 text-xs font-mono italic uppercase tracking-wider">
                {status === "pending" ? "Waiting for payload..." : "Scanning — results will appear here"}
              </div>
            ) : (
              subdomainNames.map((domain, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 px-2.5 py-1 bg-dark-card border border-dark-border/40 rounded hover:border-cyber-accent/30 transition-all text-xs font-mono text-slate-300"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-success flex-shrink-0" />
                  {domain}
                </div>
              ))
            )}
            <div ref={listBottomRef} />
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="bg-dark-bg border-t border-dark-border px-4 py-2 flex items-center justify-between text-[10px] font-mono text-slate-500">
        <span>PROVIDER: {activeJob.provider_name.toUpperCase()}</span>
        <span>
          {status === "running" ? "● STREAMING" : status === "completed" ? "✓ COMPLETE" : "✗ STOPPED"}
        </span>
      </div>
    </div>
  );
};
