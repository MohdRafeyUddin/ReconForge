import React, { useEffect, useMemo, useState } from "react";
import { Play, RefreshCw, Camera, FileCode2, Crosshair, Clock, CheckCircle2, XCircle } from "lucide-react";
import { apiCall } from "../../services/api";

type DiscoveredAction = "screenshots" | "js_files" | "ffuf_arjun";

interface MinimalAsset {
  id?: string;
  domain: string;
  type: string;
  status?: string;
  value?: string;
  metadata?: Record<string, any>;
}

type ResultTab = "screenshots" | "js_files" | "content_discovery";

interface DiscoveredActionPanelProps {
  projectId?: string;
  assets: MinimalAsset[];
  onRefresh?: () => void;
  dnsRecordCount?: number;
  onOpenInventoryTab?: (tab: ResultTab) => void;
}

interface JobResult {
  id: string;
  status?: string;
  logs?: string[];
  phase_durations?: { phase: string; duration_seconds: number }[];
  executed_phases?: string[];
  targeted?: { tool?: string; hosts?: string[] };
}

const URL_ASSET_TYPES = new Set([
  "content_path", "historical_url", "gf_url", "uro_url",
  "api_spec", "graphql_endpoint", "param", "js_file",
]);
const EXCLUDED_STATUS_ASSET_TYPES = new Set(["historical_dead", "unprobed_url"]);
const TERMINAL = new Set(["completed", "failed", "stopped", "interrupted"]);

const hostnameOf = (value: string): string => {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return "";
  }
};

const formatSecs = (value?: number) => {
  if (value === undefined || value === null) return "—";
  if (value < 60) return `${Math.round(value * 10) / 10}s`;
  return `${Math.floor(value / 60)}m ${Math.round(value % 60)}s`;
};

export const DiscoveredActionPanel: React.FC<DiscoveredActionPanelProps> = ({
  projectId,
  assets,
  onRefresh,
  dnsRecordCount,
  onOpenInventoryTab,
}) => {
  const [selectedHost, setSelectedHost] = useState("");
  const [action, setAction] = useState<DiscoveredAction>("screenshots");
  const [timeCap, setTimeCap] = useState("900");
  const [job, setJob] = useState<JobResult | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const [autoRefreshed, setAutoRefreshed] = useState(false);
  const [remoteUrls, setRemoteUrls] = useState<string[]>([]);
  const [urlsLoading, setUrlsLoading] = useState(false);
  const [urlsVersion, setUrlsVersion] = useState(0);
  const [apiHosts, setApiHosts] = useState<{ host: string; url: string }[]>([]);
  const [apiDnsCount, setApiDnsCount] = useState<number | undefined>(undefined);

  const hosts = useMemo(() => {
    const map = new Map<string, string>();
    // Prefer the backend's live-host list so a stale/paginated asset feed
    // cannot hide hosts that DNS/inventory still show.
    for (const live of apiHosts) {
      const host = String(live.host || "").toLowerCase();
      if (!host || map.has(host)) continue;
      map.set(host, String(live.url || `https://${host}`));
    }
    if (map.size === 0) {
      for (const asset of assets) {
        const type = (asset.type || "").toLowerCase();
        if (!["subdomain", "host"].includes(type) || asset.status !== "live") continue;
        const url = asset.metadata?.url || asset.domain;
        if (!url) continue;
        const host = hostnameOf(url) || String(asset.domain || "").toLowerCase();
        if (!host || map.has(host)) continue;
        map.set(host, url);
      }
    }
    return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [apiHosts, assets]);

  const effectiveDnsCount = apiDnsCount ?? dnsRecordCount;

  useEffect(() => {
    if (!projectId) {
      setApiHosts([]);
      return;
    }
    let cancelled = false;
    // Debounced so a scan streaming asset events does not hammer the
    // endpoint; refreshes once the asset feed settles.
    const timer = window.setTimeout(() => {
      const loadHosts = async () => {
        const hostMap = new Map<string, string>();

        // New endpoint: authoritative live HTTP hosts + DNS count.
        try {
          const liveRes: any = await apiCall(
            `/assets/project/${projectId}/live-hosts`
          );
          if (cancelled) return;
          for (const live of liveRes?.hosts || []) {
            const host = String(live?.host || "").toLowerCase();
            if (host && !hostMap.has(host)) {
              hostMap.set(host, String(live.url || `https://${host}`));
            }
          }
          if (typeof liveRes?.dns_record_count === "number") {
            setApiDnsCount(liveRes.dns_record_count);
          }
        } catch {
          // Older backend without /live-hosts — use /subdomains below.
        }

        // This endpoint exists on older backends too, so the selector keeps
        // working without a restart and even if the asset feed is stale.
        if (hostMap.size === 0) {
          try {
            const subs: any = await apiCall(
              `/assets/project/${projectId}/subdomains`
            );
            if (cancelled) return;
            for (const asset of Array.isArray(subs) ? subs : []) {
              if (String(asset?.status || "") !== "live") continue;
              const host = String(asset?.domain || "").toLowerCase();
              if (!host || hostMap.has(host)) continue;
              const meta = asset?.metadata || {};
              hostMap.set(host, String(meta.url || `https://${host}`));
            }
          } catch {
            // Leave the selector empty rather than throwing.
          }
        }

        if (!cancelled) {
          setApiHosts(
            Array.from(hostMap, ([host, url]) => ({ host, url }))
          );
        }
      };
      loadHosts();
    }, 700);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [projectId, urlsVersion, assets.length]);

  useEffect(() => {
    if (!selectedHost && hosts.length > 0) {
      setSelectedHost(hosts[0][0]);
    }
  }, [hosts, selectedHost]);

  useEffect(() => {
    if (!projectId || !selectedHost) {
      setRemoteUrls([]);
      return;
    }
    let cancelled = false;
    // Debounced: refresh the URL list after a scan/fuzzing job updates the
    // asset feed so newly discovered paths are included in the next action.
    const timer = window.setTimeout(() => {
      setUrlsLoading(true);
      apiCall(
        `/assets/project/${projectId}/host-urls?host=${encodeURIComponent(selectedHost)}`
      )
        .then((res: any) => {
          if (!cancelled) setRemoteUrls(Array.isArray(res?.urls) ? res.urls : []);
        })
        .catch(() => {
          if (!cancelled) setRemoteUrls([]);
        })
        .finally(() => {
          if (!cancelled) setUrlsLoading(false);
        });
    }, 700);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [projectId, selectedHost, urlsVersion, assets.length]);

  const extractedUrls = useMemo(() => {
    if (!selectedHost) return [];
    const ordered: string[] = [];
    const seen = new Set<string>();
    const add = (value: any) => {
      const raw = String(value || "").trim();
      if (!raw.startsWith("http://") && !raw.startsWith("https://")) return;
      if (hostnameOf(raw) !== selectedHost) return;
      if (seen.has(raw)) return;
      seen.add(raw);
      ordered.push(raw);
    };

    // The backend list is complete and priority-ordered. Local assets stay
    // as an immediate fallback and include in-flight WebSocket updates.
    for (const url of remoteUrls) add(url);

    for (const asset of assets) {
      const type = (asset.type || "").toLowerCase();
      const meta = asset.metadata || {};

      if (type === "subdomain" || type === "host") {
        if ((asset.domain || "").toLowerCase() === selectedHost) {
          add(meta.url || asset.domain);
          for (const katanaUrl of (meta.katana?.urls || [])) add(katanaUrl);
          for (const endpoint of (meta.katana?.endpoints || [])) add(endpoint);
          for (const jsUrl of (meta.katana?.js_files || [])) add(jsUrl);
        }
        continue;
      }

      if (EXCLUDED_STATUS_ASSET_TYPES.has(type)) continue;
      if (URL_ASSET_TYPES.has(type)) {
        add(meta.url || (asset as any).value);
      }
    }

    return ordered;
  }, [assets, selectedHost, remoteUrls]);

  useEffect(() => {
    if (!job?.id || TERMINAL.has(String(job.status || ""))) {
      if (job?.id && TERMINAL.has(String(job.status || "")) && !autoRefreshed) {
        setAutoRefreshed(true);
        setUrlsVersion((version) => version + 1);
        onRefresh?.();
      }
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const updated = await apiCall(`/jobs/${job.id}`);
        if (!cancelled) setJob(updated);
      } catch (err: any) {
        if (!cancelled) setError(err.message || "Failed to read job status");
      }
    };
    const timer = window.setInterval(poll, 1500);
    poll();
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [job?.id, job?.status, autoRefreshed, onRefresh]);

  if (!projectId) return null;

  const running = Boolean(job?.id) && !TERMINAL.has(String(job?.status || ""));

  const completedTool = job?.targeted?.tool || action;
  const resultTarget: { tab: ResultTab; label: string } =
    completedTool === "screenshots"
      ? { tab: "screenshots", label: "Screenshots" }
      : completedTool === "js_files"
        ? { tab: "js_files", label: "JS Files" }
        : { tab: "content_discovery", label: "Content Discovery" };

  const runAction = async () => {
    if (!selectedHost || extractedUrls.length === 0) return;
    setStarting(true);
    setError("");
    setAutoRefreshed(false);
    try {
      const created = await apiCall(`/jobs/project/${projectId}/targeted`, {
        method: "POST",
        body: JSON.stringify({
          tool: action,
          hosts: extractedUrls,
          time_cap_seconds: Number(timeCap) || 900,
        }),
      });
      setJob(created);
    } catch (err: any) {
      setError(err.message || "Failed to start action");
    } finally {
      setStarting(false);
    }
  };

  const actions: { id: DiscoveredAction; label: string; icon: React.ReactNode }[] = [
    { id: "screenshots", label: "Screenshots", icon: <Camera className="w-3.5 h-3.5" /> },
    { id: "js_files", label: "JS Files", icon: <FileCode2 className="w-3.5 h-3.5" /> },
    { id: "ffuf_arjun", label: "FFUF + Arjun", icon: <Crosshair className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-dark-border pb-2">
        <div>
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-cyber-accent">
            Extracted URL Actions
          </h4>
          <p className="text-[11px] text-slate-500 font-mono mt-0.5">
            Pick a host, then run the selected action on all of its extracted URLs.
          </p>
          {effectiveDnsCount !== undefined && effectiveDnsCount > hosts.length && (
            <p className="text-[10px] text-amber-300/80 font-mono mt-1">
              {hosts.length} live HTTP host(s) of {effectiveDnsCount} DNS record(s).
              Resolved-only records cannot be screenshotted until they respond
              over HTTP.
            </p>
          )}
        </div>
        <span className="text-[10px] font-mono text-slate-400">
          {urlsLoading
            ? "Loading extracted URLs..."
            : `${extractedUrls.length} extracted URL(s)`}
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
        <div className="lg:col-span-2">
          <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">Host</label>
          <select
            value={selectedHost}
            onChange={(e) => setSelectedHost(e.target.value)}
            className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
          >
            {hosts.length === 0 && <option value="">No live hosts discovered</option>}
            {hosts.map(([host, url]) => (
              <option key={host} value={host}>{host} — {url}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">Action</label>
          <div className="grid grid-cols-3 gap-1">
            {actions.map((item) => (
              <button
                key={item.id}
                onClick={() => setAction(item.id)}
                className={`flex flex-col items-center justify-center gap-1 px-1.5 py-2 rounded border text-[9px] font-mono font-bold uppercase cursor-pointer ${
                  action === item.id
                    ? "bg-cyber-accent/15 border-cyber-accent/50 text-cyber-accent"
                    : "bg-dark-input border-dark-border text-slate-400 hover:text-slate-200"
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-end gap-2">
          <div className="flex-1">
            <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">Time cap (s)</label>
            <input
              type="number"
              min={1}
              max={7200}
              value={timeCap}
              onChange={(e) => setTimeCap(e.target.value)}
              className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
            />
          </div>
          <button
            onClick={runAction}
            disabled={starting || running || urlsLoading || !selectedHost || extractedUrls.length === 0}
            className="flex items-center justify-center gap-1.5 px-3 py-2 rounded bg-cyber-accent/15 border border-cyber-accent/50 text-cyber-accent text-xs font-bold hover:bg-cyber-accent/25 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer whitespace-nowrap"
          >
            {starting || running ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            <span>{running ? "Running..." : starting ? "Starting..." : "Run"}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 text-[11px] font-mono text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded p-2">
          <XCircle className="w-3.5 h-3.5" /> {error}
        </div>
      )}

      {job?.id && (
        <div className="bg-dark-bg border border-dark-border rounded p-3 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
            <span className="text-slate-300 flex items-center gap-1.5">
              {TERMINAL.has(String(job.status || "")) ? (
                job.status === "completed"
                  ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  : <XCircle className="w-3.5 h-3.5 text-rose-400" />
              ) : (
                <RefreshCw className="w-3.5 h-3.5 text-cyber-accent animate-spin" />
              )}
              {action.replace(/_/g, " ")} — {job.status || "pending"}
            </span>
            <div className="flex items-center gap-2">
              {job.status === "completed" && onOpenInventoryTab && (
                <button
                  onClick={() => onOpenInventoryTab(resultTarget.tab)}
                  className="px-2 py-1 rounded border border-cyber-accent/50 bg-cyber-accent/10 text-cyber-accent text-[10px] font-bold uppercase hover:bg-cyber-accent/20 cursor-pointer"
                >
                  View {resultTarget.label}
                </button>
              )}
              <span className="text-slate-500">job {job.id.slice(-8)}</span>
            </div>
          </div>

          {job.phase_durations && job.phase_durations.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {job.phase_durations.map((pd, idx) => (
                <span key={`${pd.phase}-${idx}`} className="px-2 py-0.5 rounded border border-dark-border bg-dark-card text-[10px] font-mono text-slate-300 flex items-center gap-1">
                  <Clock className="w-3 h-3 text-cyber-accent" />
                  {pd.phase.replace(/_/g, " ")}: {formatSecs(pd.duration_seconds)}
                </span>
              ))}
            </div>
          )}

          {(job.logs || []).length > 0 && (
            <pre className="text-[10px] text-slate-400 font-mono whitespace-pre-wrap break-all max-h-32 overflow-y-auto bg-black/20 rounded p-2">
              {(job.logs || []).slice(-8).join("\n")}
            </pre>
          )}
        </div>
      )}
    </div>
  );
};
