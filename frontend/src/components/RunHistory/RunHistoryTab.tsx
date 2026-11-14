import React, { useState, useEffect, useMemo } from "react";
import { History, GitCompare, Eye, FileText, ChevronLeft, ChevronRight, AlertCircle, CheckCircle, Search } from "lucide-react";
import { apiCall } from "../../services/api";
import { HighlightText, ExactMatchBadge } from "../Common/HighlightText";

interface ScanRun {
  job_id: string;
  project_id: string;
  started_at: string;
  finished_at?: string;
  duration_sec?: number;
  status: string;
  scan_mode?: string;
  scan_profile?: string;
  executed_phases?: string[];
  stage_markers?: {
    stage: string;
    status: string;
    reason?: string;
    timestamp?: string;
  }[];
  counts?: {
    subdomains?: number;
    resolved?: number;
    live?: number;
    ports?: number;
    urls_by_source?: Record<string, number>;
    content_paths?: number;
    params?: number;
    findings?: number;
    rejected_urls?: number;
  };
  tool_versions?: Record<string, string>;
  config_snapshot?: {
    scope?: { in_scope?: string[]; out_of_scope?: string[] };
    rate_limits?: any;
    custom_header_names?: string[];
    scan_profile?: string;
    port_range?: string;
  };
}

interface RunAsset {
  type: string;
  value: string;
  domain?: string;
  status?: string;
  status_code?: number;
  severity?: string;
  discovered_by?: string;
  first_seen?: string;
}

interface CompareResult {
  job_a: string;
  job_b: string;
  compared_at: string;
  summary: Record<string, { added_count: number; removed_count: number; retained_count: number }>;
  added: Record<string, string[]>;
  removed: Record<string, string[]>;
}

interface RunHistoryTabProps {
  projectId: string;
}

export const RunHistoryTab: React.FC<RunHistoryTabProps> = ({ projectId }) => {
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const limit = 15;

  // Selected run for detail modal
  const [selectedRun, setSelectedRun] = useState<ScanRun | null>(null);
  const [runAssets, setRunAssets] = useState<RunAsset[]>([]);
  const [runAssetsTotal, setRunAssetsTotal] = useState(0);
  const [runAssetsPage, setRunAssetsPage] = useState(1);
  const [runAssetsType, setRunAssetsType] = useState<string>("all");
  const [loadingAssets, setLoadingAssets] = useState(false);

  // Compare mode
  const [compareA, setCompareA] = useState<string>("");
  const [compareB, setCompareB] = useState<string>("");
  const [compareResult, setCompareResult] = useState<CompareResult | null>(null);
  const [comparing, setComparing] = useState(false);

  const [runsSearch, setRunsSearch] = useState<string>("");
  const [compareSearch, setCompareSearch] = useState<string>("");
  const [runAssetSearch, setRunAssetSearch] = useState<string>("");

  const filteredRuns = useMemo(() => {
    const q = runsSearch.toLowerCase().trim();
    if (!q) return runs;
    return runs.filter((r) => {
      const jobId = (r.job_id || "").toLowerCase();
      const status = (r.status || "").toLowerCase();
      const mode = (r.scan_mode || "").toLowerCase();
      const profile = (r.scan_profile || "").toLowerCase();
      const started = new Date(r.started_at).toLocaleString().toLowerCase();
      const duration = String(r.duration_sec ?? "");
      const subs = String(r.counts?.subdomains ?? "");
      const live = String(r.counts?.live ?? "");
      const findings = String(r.counts?.findings ?? "");
      const phases = (r.executed_phases || []).join(" ").toLowerCase();
      const markers = (r.stage_markers || [])
        .map((sm) => `${sm.stage} ${sm.status} ${sm.reason || ""}`)
        .join(" ")
        .toLowerCase();
      const config = JSON.stringify(r.config_snapshot || {}).toLowerCase();
      return (
        jobId.includes(q) ||
        status.includes(q) ||
        mode.includes(q) ||
        profile.includes(q) ||
        started.includes(q) ||
        duration.includes(q) ||
        subs.includes(q) ||
        live.includes(q) ||
        findings.includes(q) ||
        phases.includes(q) ||
        markers.includes(q) ||
        config.includes(q)
      );
    });
  }, [runs, runsSearch]);

  const exactRunsCount = useMemo(() => {
    if (!runsSearch.trim()) return 0;
    const q = runsSearch.trim().toLowerCase();
    return filteredRuns.filter(
      (r) =>
        r.job_id.toLowerCase().includes(q) ||
        r.status.toLowerCase() === q ||
        (r.scan_mode && r.scan_mode.toLowerCase() === q) ||
        (r.scan_profile && r.scan_profile.toLowerCase() === q)
    ).length;
  }, [filteredRuns, runsSearch]);

  const filteredCompareAdded = useMemo(() => {
    if (!compareResult) return [];
    const q = compareSearch.toLowerCase().trim();
    const items = Object.entries(compareResult.added).flatMap(([type, list]) =>
      list.map((item) => ({ type, item }))
    );
    if (!q) return items;
    return items.filter(
      ({ type, item }) => type.toLowerCase().includes(q) || item.toLowerCase().includes(q)
    );
  }, [compareResult, compareSearch]);

  const filteredCompareRemoved = useMemo(() => {
    if (!compareResult) return [];
    const q = compareSearch.toLowerCase().trim();
    const items = Object.entries(compareResult.removed).flatMap(([type, list]) =>
      list.map((item) => ({ type, item }))
    );
    if (!q) return items;
    return items.filter(
      ({ type, item }) => type.toLowerCase().includes(q) || item.toLowerCase().includes(q)
    );
  }, [compareResult, compareSearch]);

  const filteredRunAssets = useMemo(() => {
    const q = runAssetSearch.toLowerCase().trim();
    if (!q) return runAssets;
    return runAssets.filter((a) => {
      const val = (a.value || "").toLowerCase();
      const type = (a.type || "").toLowerCase();
      const domain = (a.domain || "").toLowerCase();
      const status = (a.status || "").toLowerCase();
      const discovered = (a.discovered_by || "").toLowerCase();
      const severity = (a.severity || "").toLowerCase();
      const code = String(a.status_code ?? "");
      return (
        val.includes(q) ||
        type.includes(q) ||
        domain.includes(q) ||
        status.includes(q) ||
        discovered.includes(q) ||
        severity.includes(q) ||
        code.includes(q)
      );
    });
  }, [runAssets, runAssetSearch]);

  const exactRunAssetsCount = useMemo(() => {
    if (!runAssetSearch.trim()) return 0;
    const q = runAssetSearch.trim().toLowerCase();
    return filteredRunAssets.filter(
      (a) =>
        (a.value && a.value.toLowerCase() === q) ||
        (a.type && a.type.toLowerCase() === q) ||
        (a.discovered_by && a.discovered_by.toLowerCase() === q) ||
        (a.domain && a.domain.toLowerCase() === q)
    ).length;
  }, [filteredRunAssets, runAssetSearch]);

  const fetchRuns = async () => {
    if (!projectId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await apiCall(`/projects/${projectId}/runs?page=${page}&limit=${limit}`);
      setRuns(data.items || []);
      setTotal(data.total || 0);
    } catch (err: any) {
      setError(err.message || "Failed to fetch scan runs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
  }, [projectId, page]);

  const openRunDetails = async (run: ScanRun) => {
    setSelectedRun(run);
    setRunAssetsPage(1);
    setRunAssetsType("all");
    loadRunAssets(run.job_id, 1, "all");
  };

  const loadRunAssets = async (jobId: string, p: number, t: string) => {
    setLoadingAssets(true);
    try {
      const typeParam = t === "all" ? "" : `&type=${t}`;
      const data = await apiCall(`/projects/${projectId}/runs/${jobId}/assets?page=${p}&limit=30${typeParam}`);
      setRunAssets(data.items || []);
      setRunAssetsTotal(data.total || 0);
    } catch (err: any) {
      console.error("Failed to load run assets:", err);
    } finally {
      setLoadingAssets(false);
    }
  };

  const handleCompare = async () => {
    if (!compareA || !compareB || compareA === compareB) {
      alert("Please select two distinct runs to compare");
      return;
    }
    setComparing(true);
    try {
      const data = await apiCall(`/projects/${projectId}/runs/compare?a=${compareA}&b=${compareB}`);
      setCompareResult(data);
    } catch (err: any) {
      alert(err.message || "Failed to compare runs");
    } finally {
      setComparing(false);
    }
  };

  const formatSecs = (sec?: number) => {
    if (sec === undefined || sec === null) return "-";
    if (sec < 60) return `${Math.round(sec)}s`;
    const m = Math.floor(sec / 60);
    const s = Math.round(sec % 60);
    return `${m}m ${s}s`;
  };

  return (
    <div className="space-y-6">
      {/* Run History Header */}
      <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <History className="w-5 h-5 text-cyber-accent" />
            <span>Scan Run History</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Historical audit log of all automated and on-demand discovery runs.
          </p>
        </div>

        {/* Compare Runs Toolbar */}
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <select
            value={compareA}
            onChange={(e) => setCompareA(e.target.value)}
            className="bg-dark-bg border border-dark-border rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyber-accent"
          >
            <option value="">Select Run A</option>
            {runs.map((r) => (
              <option key={r.job_id} value={r.job_id}>
                {r.job_id.slice(-6)} ({r.scan_mode || "scan"}, {new Date(r.started_at).toLocaleDateString()})
              </option>
            ))}
          </select>

          <span className="text-xs text-slate-500 font-bold">vs</span>

          <select
            value={compareB}
            onChange={(e) => setCompareB(e.target.value)}
            className="bg-dark-bg border border-dark-border rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyber-accent"
          >
            <option value="">Select Run B</option>
            {runs.map((r) => (
              <option key={r.job_id} value={r.job_id}>
                {r.job_id.slice(-6)} ({r.scan_mode || "scan"}, {new Date(r.started_at).toLocaleDateString()})
              </option>
            ))}
          </select>

          <button
            onClick={handleCompare}
            disabled={!compareA || !compareB || compareA === compareB || comparing}
            className="bg-cyber-primary/20 hover:bg-cyber-primary/40 text-cyber-accent border border-cyber-primary/40 px-3 py-1.5 rounded text-xs font-bold transition-all disabled:opacity-40 flex items-center gap-1.5 cursor-pointer"
          >
            <GitCompare className="w-3.5 h-3.5" />
            <span>{comparing ? "Comparing..." : "Compare"}</span>
          </button>
        </div>
      </div>

      {/* Comparison Results Card */}
      {compareResult && (
        <div className="bg-dark-card border border-cyber-accent/30 rounded-xl p-5 glass animate-fadeIn">
          <div className="flex items-center justify-between mb-4 border-b border-dark-border pb-3">
            <h4 className="text-sm font-bold text-cyber-accent flex items-center gap-2">
              <GitCompare className="w-4 h-4" />
              <span>
                Run Comparison: <span className="font-mono text-slate-200">{compareResult.job_a.slice(-6)}</span> vs{" "}
                <span className="font-mono text-slate-200">{compareResult.job_b.slice(-6)}</span>
              </span>
            </h4>
            <button
              onClick={() => setCompareResult(null)}
              className="text-xs text-slate-400 hover:text-white"
            >
              ✕ Close
            </button>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            {Object.entries(compareResult.summary).map(([type, counts]) => (
              <div key={type} className="bg-dark-bg border border-dark-border rounded-lg p-3">
                <div className="text-[10px] font-mono uppercase text-slate-400 font-bold mb-1">{type}</div>
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-cyber-success">+{counts.added_count} added</span>
                  <span className="text-slate-600">|</span>
                  <span className="text-cyber-danger">-{counts.removed_count} removed</span>
                </div>
              </div>
            ))}
          </div>

          {/* Comparison Search */}
          <div className="relative w-full mb-3">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search comparison diffs by asset, type..."
              value={compareSearch}
              onChange={(e) => setCompareSearch(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-cyber-accent outline-none font-mono"
            />
          </div>

          {/* Added & Removed Lists */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-dark-bg border border-emerald-500/20 rounded-lg p-3">
              <div className="text-xs font-bold text-emerald-400 mb-2 flex items-center justify-between">
                <div className="flex items-center gap-1">
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>Newly Added Assets</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">{filteredCompareAdded.length} items</span>
              </div>
              <div className="max-h-48 overflow-y-auto space-y-1 font-mono text-[11px] text-slate-300">
                {filteredCompareAdded.map(({ type, item }, idx) => {
                  const exactMatch = Boolean(
                    compareSearch.trim() &&
                    (item.toLowerCase() === compareSearch.trim().toLowerCase() ||
                     type.toLowerCase() === compareSearch.trim().toLowerCase())
                  );

                  return (
                    <div key={`${type}-${idx}`} className="truncate flex items-center gap-1.5">
                      <span className="text-slate-500">[{type}]</span>
                      {item.startsWith("http://") || item.startsWith("https://") ? (
                        <a href={item} target="_blank" rel="noopener noreferrer" className="hover:text-cyber-accent hover:underline">
                          <HighlightText text={item} highlight={compareSearch} />
                        </a>
                      ) : type === "subdomain" || type === "live_host" ? (
                        <a href={`https://${item}`} target="_blank" rel="noopener noreferrer" className="hover:text-cyber-accent hover:underline">
                          <HighlightText text={item} highlight={compareSearch} />
                        </a>
                      ) : (
                        <span><HighlightText text={item} highlight={compareSearch} /></span>
                      )}
                      {exactMatch && <ExactMatchBadge />}
                    </div>
                  );
                })}
                {filteredCompareAdded.length === 0 && (
                  <div className="text-slate-500 text-xs">
                    {compareSearch ? "No matching added assets." : "No new assets added."}
                  </div>
                )}
              </div>
            </div>

            <div className="bg-dark-bg border border-red-500/20 rounded-lg p-3">
              <div className="text-xs font-bold text-red-400 mb-2 flex items-center justify-between">
                <div className="flex items-center gap-1">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>Removed / Vanished Assets</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500">{filteredCompareRemoved.length} items</span>
              </div>
              <div className="max-h-48 overflow-y-auto space-y-1 font-mono text-[11px] text-slate-300">
                {filteredCompareRemoved.map(({ type, item }, idx) => {
                  const exactMatch = Boolean(
                    compareSearch.trim() &&
                    (item.toLowerCase() === compareSearch.trim().toLowerCase() ||
                     type.toLowerCase() === compareSearch.trim().toLowerCase())
                  );

                  return (
                    <div key={`${type}-${idx}`} className="truncate flex items-center gap-1.5">
                      <span className="text-slate-500">[{type}]</span>
                      {item.startsWith("http://") || item.startsWith("https://") ? (
                        <a href={item} target="_blank" rel="noopener noreferrer" className="hover:text-cyber-accent hover:underline">
                          <HighlightText text={item} highlight={compareSearch} />
                        </a>
                      ) : type === "subdomain" || type === "live_host" ? (
                        <a href={`https://${item}`} target="_blank" rel="noopener noreferrer" className="hover:text-cyber-accent hover:underline">
                          <HighlightText text={item} highlight={compareSearch} />
                        </a>
                      ) : (
                        <span><HighlightText text={item} highlight={compareSearch} /></span>
                      )}
                      {exactMatch && <ExactMatchBadge />}
                    </div>
                  );
                })}
                {filteredCompareRemoved.length === 0 && (
                  <div className="text-slate-500 text-xs">
                    {compareSearch ? "No matching removed assets." : "No assets removed."}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Runs Table */}
      <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden glass">
        <div className="p-4 border-b border-dark-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-dark-bg/40">
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-200">Execution History</h4>
            <span className="text-[10px] text-slate-500 font-mono">
              {filteredRuns.length} of {runs.length} runs on this page ({total} total recorded)
              {runsSearch.trim() && (
                exactRunsCount > 0 ? (
                  <span className="text-amber-300 font-bold ml-2">🎯 {exactRunsCount} exact match{exactRunsCount === 1 ? "" : "es"}</span>
                ) : (
                  <span className="text-slate-500 ml-2">Partial matches</span>
                )
              )}
            </span>
          </div>
          <div className="relative w-full sm:w-72">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search runs by ID, status, profile, counts..."
              value={runsSearch}
              onChange={(e) => setRunsSearch(e.target.value)}
              className="w-full bg-dark-bg border border-dark-border rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-cyber-accent outline-none font-mono"
            />
          </div>
        </div>

        {loading ? (
          <div className="p-12 text-center text-slate-400 font-mono text-xs">Loading run history...</div>
        ) : error ? (
          <div className="p-8 text-center text-cyber-danger font-mono text-xs">{error}</div>
        ) : runs.length === 0 ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs uppercase tracking-wider">
            No historical runs recorded for this project yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="bg-dark-bg/80 border-b border-dark-border text-slate-400 uppercase tracking-wider text-[11px]">
                  <th className="p-3">Job ID</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Mode / Profile</th>
                  <th className="p-3">Started</th>
                  <th className="p-3">Duration</th>
                  <th className="p-3">Subdomains</th>
                  <th className="p-3">Live Hosts</th>
                  <th className="p-3">Findings</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRuns.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="p-8 text-center text-slate-500 font-mono text-xs">
                      No runs match your search query "{runsSearch}".
                    </td>
                  </tr>
                ) : (
                  filteredRuns.map((r) => {
                    let statusBadge = "bg-slate-500/10 text-slate-400 border-slate-500/30";
                    if (r.status === "completed") statusBadge = "bg-cyber-success/10 text-cyber-success border-cyber-success/30 font-bold";
                    else if (r.status === "failed") statusBadge = "bg-cyber-danger/10 text-cyber-danger border-cyber-danger/30 font-bold";
                    else if (r.status === "interrupted") statusBadge = "bg-amber-500/10 text-amber-400 border-amber-500/30";
                    else if (r.status === "running") statusBadge = "bg-cyber-accent/10 text-cyber-accent border-cyber-accent/30 animate-pulse";

                    const exactMatch = Boolean(
                      runsSearch.trim() &&
                      (r.job_id.toLowerCase().includes(runsSearch.trim().toLowerCase()) ||
                       r.status.toLowerCase() === runsSearch.trim().toLowerCase() ||
                       (r.scan_mode && r.scan_mode.toLowerCase() === runsSearch.trim().toLowerCase()) ||
                       (r.scan_profile && r.scan_profile.toLowerCase() === runsSearch.trim().toLowerCase()))
                    );

                    return (
                      <tr key={r.job_id} className="border-b border-dark-border hover:bg-dark-hover/30 transition-colors">
                        <td className="p-3 font-bold text-slate-200">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <HighlightText text={r.job_id.slice(-8)} highlight={runsSearch} />
                            {exactMatch && <ExactMatchBadge />}
                          </div>
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded border text-[10px] uppercase ${statusBadge}`}>
                            <HighlightText text={r.status} highlight={runsSearch} />
                          </span>
                        </td>
                        <td className="p-3 text-slate-300">
                          <HighlightText text={r.scan_mode || "fast"} highlight={runsSearch} /> / <span className="text-slate-400"><HighlightText text={r.scan_profile || "recon"} highlight={runsSearch} /></span>
                        </td>
                        <td className="p-3 text-slate-400">
                          {new Date(r.started_at).toLocaleString()}
                        </td>
                        <td className="p-3 text-slate-300">
                          {formatSecs(r.duration_sec)}
                        </td>
                        <td className="p-3 text-slate-200 font-bold">
                          {r.counts?.subdomains ?? "-"}
                        </td>
                        <td className="p-3 text-slate-200 font-bold">
                          {r.counts?.live ?? "-"}
                        </td>
                        <td className="p-3 text-slate-200 font-bold">
                          {r.counts?.findings ?? 0}
                        </td>
                        <td className="p-3 text-right">
                          <button
                            onClick={() => openRunDetails(r)}
                            className="px-2.5 py-1 bg-dark-bg hover:bg-dark-hover border border-dark-border text-cyber-accent rounded text-[11px] font-bold transition-all flex items-center gap-1 ml-auto cursor-pointer"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            <span>Inspect</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {total > limit && (
          <div className="p-3 bg-dark-bg/60 border-t border-dark-border flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>
              Showing {((page - 1) * limit) + 1} - {Math.min(page * limit, total)} of {total} runs
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="px-2 py-1 bg-dark-bg border border-dark-border rounded hover:bg-dark-hover disabled:opacity-40"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span>Page {page}</span>
              <button
                onClick={() => setPage((p) => p + 1)}
                disabled={page * limit >= total}
                className="px-2 py-1 bg-dark-bg border border-dark-border rounded hover:bg-dark-hover disabled:opacity-40"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Run Detail Modal */}
      {selectedRun && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="bg-dark-card border border-dark-border max-w-4xl w-full max-h-[90vh] flex flex-col rounded-xl glass shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-5 border-b border-dark-border flex items-center justify-between bg-dark-bg/50">
              <div className="flex items-center gap-3">
                <FileText className="w-5 h-5 text-cyber-accent" />
                <div>
                  <h3 className="text-sm font-bold text-slate-100 font-mono">
                    Run Inspection: {selectedRun.job_id}
                  </h3>
                  <div className="text-xs text-slate-400 font-mono">
                    Mode: {selectedRun.scan_mode || "fast"} | Profile: {selectedRun.scan_profile || "recon"} | Started:{" "}
                    {new Date(selectedRun.started_at).toLocaleString()}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedRun(null)}
                className="text-slate-400 hover:text-white text-base font-bold px-2 py-1 cursor-pointer"
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto space-y-5 text-xs font-mono">
              {/* Counts & Markers Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-dark-bg border border-dark-border rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase">Duration</div>
                  <div className="text-base font-bold text-slate-200 mt-1">{formatSecs(selectedRun.duration_sec)}</div>
                </div>
                <div className="bg-dark-bg border border-dark-border rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase">Subdomains</div>
                  <div className="text-base font-bold text-slate-200 mt-1">{selectedRun.counts?.subdomains ?? 0}</div>
                </div>
                <div className="bg-dark-bg border border-dark-border rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase">Live Hosts</div>
                  <div className="text-base font-bold text-slate-200 mt-1">{selectedRun.counts?.live ?? 0}</div>
                </div>
                <div className="bg-dark-bg border border-dark-border rounded-lg p-3">
                  <div className="text-[10px] text-slate-500 uppercase">Findings</div>
                  <div className="text-base font-bold text-cyber-accent mt-1">{selectedRun.counts?.findings ?? 0}</div>
                </div>
              </div>

              {/* Stage Markers (Skipped/Timeout/Error) */}
              {selectedRun.stage_markers && selectedRun.stage_markers.length > 0 && (
                <div className="bg-dark-bg border border-dark-border rounded-lg p-4">
                  <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider mb-2">
                    Stage Execution Markers
                  </div>
                  <div className="space-y-1.5">
                    {selectedRun.stage_markers.map((sm, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-[11px]">
                        <span className="text-amber-400 font-bold">[{sm.stage}]</span>
                        <span className="text-slate-400">({sm.status}):</span>
                        <span className="text-slate-300">{sm.reason || "No detail"}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Config Snapshot (Safe Header Names Only) */}
              {selectedRun.config_snapshot && (
                <div className="bg-dark-bg border border-dark-border rounded-lg p-4">
                  <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider mb-2">
                    Config Snapshot (Sanitized)
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-400">
                    <div>
                      <span className="text-slate-500 font-bold">In-Scope Rules: </span>
                      {selectedRun.config_snapshot.scope?.in_scope?.join(", ") || "None"}
                    </div>
                    <div>
                      <span className="text-slate-500 font-bold">Out-of-Scope Rules: </span>
                      {selectedRun.config_snapshot.scope?.out_of_scope?.join(", ") || "None"}
                    </div>
                    <div>
                      <span className="text-slate-500 font-bold">Custom Header Names: </span>
                      {selectedRun.config_snapshot.custom_header_names?.length
                        ? selectedRun.config_snapshot.custom_header_names.join(", ")
                        : "None"}
                    </div>
                    <div>
                      <span className="text-slate-500 font-bold">Port Range: </span>
                      {selectedRun.config_snapshot.port_range || "1-10000"}
                    </div>
                  </div>
                </div>
              )}

              {/* Run Assets Explorer */}
              <div className="border border-dark-border rounded-lg overflow-hidden">
                <div className="p-3 bg-dark-bg border-b border-dark-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                  <div className="font-bold text-slate-200 flex items-center gap-2">
                    <span>Assets Discovered in this Run ({filteredRunAssets.length} / {runAssetsTotal})</span>
                    {runAssetSearch.trim() && exactRunAssetsCount > 0 && (
                      <span className="text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 rounded-full font-mono flex items-center gap-1">
                        <span>🎯</span>
                        <span>{exactRunAssetsCount} exact</span>
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 w-full sm:w-auto">
                    <div className="relative flex-1 sm:w-56">
                      <Search className="w-3 h-3 text-slate-500 absolute left-2 top-2" />
                      <input
                        type="text"
                        placeholder="Search run assets..."
                        value={runAssetSearch}
                        onChange={(e) => setRunAssetSearch(e.target.value)}
                        className="w-full bg-dark-card border border-dark-border rounded pl-6 pr-2 py-1 text-[11px] text-slate-200 placeholder-slate-500 focus:border-cyber-accent outline-none font-mono"
                      />
                    </div>
                    <select
                      value={runAssetsType}
                      onChange={(e) => {
                        setRunAssetsType(e.target.value);
                        setRunAssetsPage(1);
                        loadRunAssets(selectedRun.job_id, 1, e.target.value);
                      }}
                      className="bg-dark-card border border-dark-border rounded px-2 py-1 text-[11px] text-slate-300 font-mono"
                    >
                      <option value="all">All Types</option>
                      <option value="subdomain">Subdomains</option>
                      <option value="live_host">Live Hosts</option>
                      <option value="url">URLs</option>
                      <option value="content_path">Content Paths</option>
                      <option value="param">Params</option>
                      <option value="finding">Findings</option>
                    </select>
                  </div>
                </div>

                <div className="max-h-64 overflow-y-auto">
                  {loadingAssets ? (
                    <div className="p-6 text-center text-slate-500">Loading assets...</div>
                  ) : filteredRunAssets.length === 0 ? (
                    <div className="p-6 text-center text-slate-500">
                      {runAssetSearch ? "No assets match your search." : "No assets recorded for this filter."}
                    </div>
                  ) : (
                    <table className="w-full text-left text-[11px] font-mono">
                      <tbody>
                        {filteredRunAssets.map((a, idx) => {
                          const isExact =
                            runAssetSearch.trim() &&
                            ((a.value && a.value.toLowerCase() === runAssetSearch.trim().toLowerCase()) ||
                             (a.type && a.type.toLowerCase() === runAssetSearch.trim().toLowerCase()) ||
                             (a.discovered_by && a.discovered_by.toLowerCase() === runAssetSearch.trim().toLowerCase()));
                          return (
                            <tr key={idx} className="border-b border-dark-border/40 hover:bg-dark-hover/20">
                              <td className="p-2 text-slate-500 w-28 uppercase">
                                [<HighlightText text={a.type || ""} highlight={runAssetSearch} />]
                              </td>
                              <td className="p-2 text-slate-200 font-semibold truncate">
                                <div className="flex items-center gap-2">
                                  {a.value.startsWith("http://") || a.value.startsWith("https://") ? (
                                    <a href={a.value} target="_blank" rel="noopener noreferrer" className="hover:text-cyber-accent hover:underline">
                                      <HighlightText text={a.value} highlight={runAssetSearch} />
                                    </a>
                                  ) : a.type === "subdomain" || a.type === "live_host" ? (
                                    <a href={`https://${a.value}`} target="_blank" rel="noopener noreferrer" className="hover:text-cyber-accent hover:underline">
                                      <HighlightText text={a.value} highlight={runAssetSearch} />
                                    </a>
                                  ) : (
                                    <span><HighlightText text={a.value} highlight={runAssetSearch} /></span>
                                  )}
                                  {isExact && <ExactMatchBadge label="Exact Match" />}
                                </div>
                              </td>
                              <td className="p-2 text-slate-400 text-right">
                                <HighlightText text={a.discovered_by || "-"} highlight={runAssetSearch} />
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>

                {runAssetsTotal > 30 && (
                  <div className="p-2.5 bg-dark-bg border-t border-dark-border flex items-center justify-between text-[11px] text-slate-400">
                    <span>
                      Page {runAssetsPage} of {Math.ceil(runAssetsTotal / 30)}
                    </span>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => {
                          const p = Math.max(1, runAssetsPage - 1);
                          setRunAssetsPage(p);
                          loadRunAssets(selectedRun.job_id, p, runAssetsType);
                        }}
                        disabled={runAssetsPage <= 1}
                        className="px-2 py-0.5 bg-dark-card border border-dark-border rounded disabled:opacity-40"
                      >
                        Prev
                      </button>
                      <button
                        onClick={() => {
                          const p = runAssetsPage + 1;
                          setRunAssetsPage(p);
                          loadRunAssets(selectedRun.job_id, p, runAssetsType);
                        }}
                        disabled={runAssetsPage * 30 >= runAssetsTotal}
                        className="px-2 py-0.5 bg-dark-card border border-dark-border rounded disabled:opacity-40"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
