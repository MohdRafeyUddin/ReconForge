import React, { useEffect, useRef, useState } from "react";
import { Terminal, RefreshCw, XCircle, CheckCircle2, AlertCircle } from "lucide-react";
import { getWebSocketUrl } from "../../services/api";

interface Job {
  id: string;
  provider_name: string;
  status: string;
  started_at: string;
  finished_at?: string | null;
}

interface ProviderStat {
  provider: string;
  count: number;
}

interface ConsoleViewProps {
  activeJob: Job | null;
  onClose: () => void;
}

const PROVIDER_COLORS: Record<string, string> = {
  subfinder: "#3B82F6",
  assetfinder: "#06B6D4",
  amass: "#10B981",
  chaos: "#F59E0B",
};

const PROVIDER_ORDER = ["subfinder", "assetfinder", "amass", "chaos"];

export const ConsoleView: React.FC<ConsoleViewProps> = ({ activeJob, onClose }) => {
  const [subdomains, setSubdomains] = useState<string[]>([]);
  const [status, setStatus] = useState<string>("pending");
  const [providerStats, setProviderStats] = useState<Record<string, number>>({});
  const [totalUnique, setTotalUnique] = useState<number | null>(null);
  const [completedProviders, setCompletedProviders] = useState<Set<string>>(new Set());
  const wsRef = useRef<WebSocket | null>(null);
  const listBottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!activeJob) return;
    setStatus(activeJob.status);
    setSubdomains([]);
    setProviderStats({});
    setTotalUnique(null);
    setCompletedProviders(new Set());

    const wsUrl = getWebSocketUrl(`/jobs/ws/${activeJob.id}`);
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === "status") {
          setStatus(data.status);

        } else if (data.type === "asset_discovered") {
          const domain = data.asset?.domain;
          if (domain) {
            setSubdomains((prev) =>
              prev.includes(domain) ? prev : [...prev, domain]
            );
          }

        } else if (data.type === "provider_stat") {
          const { provider, count } = data as ProviderStat;
          setProviderStats((prev) => ({ ...prev, [provider]: count }));
          setCompletedProviders((prev) => new Set([...prev, provider]));

        } else if (data.type === "scan_summary") {
          setTotalUnique(data.total_unique);
          if (data.provider_counts) {
            setProviderStats(data.provider_counts);
          }

        } else if (data.type === "log") {
          // Parse subdomains from log (replayed historical logs on WS connect)
          const matchNew = data.message?.match(/^\[\+\] New asset stored:\s*(.+?)\s+\(/);
          const matchUpdate = data.message?.match(/^\[\!\] Updated existing asset:\s*(.+?)\s+\(/);
          const matchFound = data.message?.match(/^\[\+\] (?:\[.*?\] )?Found(?:\s+subdomain)?:\s*(.+)$/);

          const domain =
            (matchNew && matchNew[1]) ||
            (matchUpdate && matchUpdate[1]) ||
            (matchFound && matchFound[1]?.split(" ")[0].trim()) ||
            null;

          if (domain && domain.includes(".")) {
            setSubdomains((prev) =>
              prev.includes(domain) ? prev : [...prev, domain]
            );
          }
        }
      } catch (err) {
        console.error("WS parse error", err);
      }
    };

    ws.onerror = () => {
      console.error("WS connection error");
    };

    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send("ping");
    }, 15000);

    return () => {
      clearInterval(interval);
      wsRef.current?.close();
    };
  }, [activeJob]);

  useEffect(() => {
    listBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [subdomains]);

  if (!activeJob) return null;

  const isUnified = activeJob.provider_name === "Unified Discovery";
  const displayCount = totalUnique ?? subdomains.length;

  const statusColor =
    status === "completed"
      ? "#10B981"
      : status === "running"
      ? "#06B6D4"
      : status === "failed"
      ? "#EF4444"
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

          {/* Per-provider breakdown (only shown for Unified) */}
          {isUnified && (
            <div className="bg-dark-bg border border-dark-border rounded-lg p-4 space-y-2">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mb-2">Provider Yield</span>
              {PROVIDER_ORDER.map((tool) => {
                const count = providerStats[tool] ?? 0;
                const done = completedProviders.has(tool) || status !== "running";
                const color = PROVIDER_COLORS[tool] ?? "#6B7280";
                return (
                  <div key={tool} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {done ? (
                        <CheckCircle2 className="w-3.5 h-3.5" style={{ color }} />
                      ) : (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" style={{ color }} />
                      )}
                      <span className="text-xs font-mono capitalize" style={{ color }}>
                        {tool}
                      </span>
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
            Discovered Subdomains ({subdomains.length})
          </span>
          <div className="flex-1 overflow-y-auto space-y-1 max-h-64 pr-1">
            {subdomains.length === 0 ? (
              <div className="flex items-center justify-center h-24 text-slate-500 text-xs font-mono italic uppercase tracking-wider">
                {status === "pending" ? "Waiting for payload..." : "Scanning — results will appear here"}
              </div>
            ) : (
              subdomains.map((domain, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 px-2.5 py-1 bg-dark-card border border-dark-border/40 rounded hover:border-cyber-accent/30 transition-all text-xs font-mono text-slate-300"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-cyber-success flex-shrink-0"></span>
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
