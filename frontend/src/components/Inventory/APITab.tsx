import React, { useEffect, useMemo, useState } from "react";
import { Braces, Loader2, RefreshCw, AlertCircle, Play, Crosshair } from "lucide-react";
import { apiCall } from "../../services/api";
import { Pagination, usePagination } from "../Common/Pagination";
import { FetchBodyButton } from "./FetchBodyButton";

interface ApiEndpointRecord {
  url: string;
  host: string;
  path: string;
  api_type: string;
  has_params?: boolean;
  params?: string[];
  parent_host?: string;
  source?: string;
  asset_id?: string;
  asset_type?: string;
}

interface APITabProps {
  projectId?: string;
}

interface TargetedJob {
  id: string;
  status?: string;
  logs?: string[];
  targeted?: { tool?: string; hosts?: string[] };
}

const TERMINAL = new Set(["completed", "failed", "stopped", "interrupted"]);

export const APITab: React.FC<APITabProps> = ({ projectId }) => {
  const [records, setRecords] = useState<ApiEndpointRecord[]>([]);
  const [byType, setByType] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [refreshTick, setRefreshTick] = useState(0);
  const [job, setJob] = useState<TargetedJob | null>(null);
  const [jobLabel, setJobLabel] = useState("");

  const load = () => setRefreshTick((tick) => tick + 1);

  useEffect(() => {
    if (!projectId) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError("");
    apiCall(`/assets/project/${projectId}/api-endpoints`)
      .then((res: any) => {
        if (cancelled) return;
        setRecords(Array.isArray(res?.items) ? res.items : []);
        setByType(res?.by_type || {});
      })
      .catch((err: any) => {
        if (!cancelled) setError(err?.message || "Failed to load API endpoints");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, refreshTick]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return records.filter((record) => {
      if (typeFilter !== "all" && record.api_type !== typeFilter) return false;
      if (!q) return true;
      return (
        record.url.toLowerCase().includes(q) ||
        record.host.toLowerCase().includes(q) ||
        record.path.toLowerCase().includes(q) ||
        record.api_type.toLowerCase().includes(q) ||
        (record.parent_host || "").toLowerCase().includes(q) ||
        (record.params || []).some((param) => param.toLowerCase().includes(q))
      );
    });
  }, [records, search, typeFilter]);

  const pager = usePagination(filtered, 20, `${search}|${typeFilter}`);

  useEffect(() => {
    if (!job?.id || TERMINAL.has(String(job.status || ""))) {
      if (job?.id && TERMINAL.has(String(job.status || ""))) {
        load();
      }
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const updated = await apiCall(`/jobs/${job.id}`);
        if (!cancelled) setJob(updated);
      } catch (err: any) {
        if (!cancelled) setError(err?.message || "Failed to read fuzz job status");
      }
    };
    const timer = window.setInterval(poll, 1500);
    poll();
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job?.id, job?.status]);

  const startFuzz = async (record: ApiEndpointRecord, tool: "ffuf" | "arjun") => {
    if (!projectId) return;
    setError("");
    setJobLabel(tool === "ffuf" ? "FFUF path fuzz" : "Arjun parameter discovery");
    try {
      const created = await apiCall(`/jobs/project/${projectId}/targeted`, {
        method: "POST",
        body: JSON.stringify({
          tool,
          hosts: [record.url],
          time_cap_seconds: tool === "ffuf" ? 600 : 300,
        }),
      });
      setJob(created);
    } catch (err: any) {
      setError(err?.message || "Failed to start fuzz job");
    }
  };

  const fuzzRunning = Boolean(job?.id) && !TERMINAL.has(String(job?.status || ""));
  if (!projectId) return null;

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      <div className="p-4 border-b border-dark-border flex flex-wrap items-center justify-between gap-3 bg-dark-bg/50">
        <div className="flex items-center gap-2">
          <Braces className="w-4 h-4 text-cyber-accent" />
          <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            API Endpoints
          </span>
          <span className="text-[10px] font-mono text-slate-500">
            {records.length} API URL(s)
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search API paths, hosts, params..."
              className="w-56 bg-dark-input border border-dark-border rounded pl-2.5 pr-2 py-1.5 text-[11px] font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent"
            />
          </div>
          <select
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
            className="bg-dark-input border border-dark-border rounded px-2 py-1.5 text-[11px] font-mono text-slate-300 focus:outline-none focus:border-cyber-accent"
          >
            <option value="all">All types</option>
            {Object.keys(byType)
              .sort()
              .map((type) => (
                <option key={type} value={type}>
                  {type} ({byType[type]})
                </option>
              ))}
          </select>
          <button
            onClick={load}
            className="p-1.5 rounded border border-dark-border bg-dark-input hover:bg-dark-hover text-slate-300 cursor-pointer"
            title="Refresh API endpoints"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 text-xs font-mono text-rose-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4" /> {error}
        </div>
      )}

      {job?.id && (
        <div className="px-4 py-2 border-b border-dark-border bg-dark-bg/40 text-[10px] font-mono text-slate-400 flex flex-wrap items-center gap-3">
          <span className="flex items-center gap-1.5 text-slate-300">
            {fuzzRunning ? (
              <Loader2 className="w-3 h-3 animate-spin text-cyber-accent" />
            ) : (
              <Play className="w-3 h-3 text-emerald-400" />
            )}
            {jobLabel}: {job.status || "pending"}
          </span>
          <span className="text-slate-600">job {job.id.slice(-8)}</span>
          {(job.logs || []).length > 0 && (
            <span className="text-slate-500 truncate max-w-xl">
              {(job.logs || []).slice(-1)[0]}
            </span>
          )}
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[10px]">
              <th className="p-3">API Endpoint</th>
              <th className="p-3">Host</th>
              <th className="p-3">Type</th>
              <th className="p-3">Params</th>
              <th className="p-3">Related Host / Source</th>
              <th className="p-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && records.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono text-[10px]">
                  Loading API endpoints...
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-8 text-center text-slate-500 font-mono text-[10px]">
                  <div className="uppercase tracking-widest">No API endpoints detected</div>
                  <div className="mt-2 normal-case text-slate-600">
                    API-like URLs are detected automatically from discovered URLs
                    (<code>/api</code>, <code>/rest</code>, <code>/v1</code>, <code>/graphql</code>,
                    <code>/openapi</code>, etc.) plus API specs and GraphQL discovery.
                  </div>
                </td>
              </tr>
            ) : (
              pager.pageItems.map((record) => (
                <tr
                  key={record.url}
                  className="border-b border-dark-border/50 hover:bg-dark-hover/30 font-mono text-[11px]"
                >
                  <td className="p-3 break-all max-w-lg">
                    <a
                      href={record.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyber-accent hover:underline"
                    >
                      {record.url}
                    </a>
                  </td>
                  <td className="p-3 text-slate-300 break-all">{record.host}</td>
                  <td className="p-3">
                    <span className="px-1.5 py-0.5 rounded border border-cyber-accent/35 bg-cyber-accent/10 text-cyber-accent text-[9px] font-bold uppercase">
                      {record.api_type}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400 break-all">
                    {(record.params || []).length > 0
                      ? (record.params || []).join(", ")
                      : record.has_params
                        ? "yes"
                        : "—"}
                  </td>
                  <td className="p-3 text-slate-500 break-all">
                    {record.parent_host || record.source || "—"}
                  </td>
                  <td className="p-3">
                    <div className="flex flex-wrap items-center gap-1">
                      <button
                        onClick={() => startFuzz(record, "ffuf")}
                        disabled={fuzzRunning}
                        className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-dark-border bg-dark-input text-[9px] font-mono font-bold uppercase text-slate-300 hover:text-cyber-accent hover:border-cyber-accent/50 disabled:opacity-40 cursor-pointer"
                        title="Fuzz <API path>/FUZZ with FFUF"
                      >
                        <Crosshair className="w-3 h-3" /> FFUF
                      </button>
                      <button
                        onClick={() => startFuzz(record, "arjun")}
                        disabled={fuzzRunning}
                        className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-dark-border bg-dark-input text-[9px] font-mono font-bold uppercase text-slate-300 hover:text-cyber-accent hover:border-cyber-accent/50 disabled:opacity-40 cursor-pointer"
                        title="Discover hidden parameters with Arjun"
                      >
                        <Crosshair className="w-3 h-3" /> Arjun
                      </button>
                      <FetchBodyButton projectId={projectId} url={record.url} compact />
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <Pagination
        page={pager.page}
        pageSize={pager.pageSize}
        total={pager.total}
        onPageChange={pager.setPage}
        onPageSizeChange={pager.setPageSize}
        itemLabel="API endpoint(s)"
      />
    </div>
  );
};
