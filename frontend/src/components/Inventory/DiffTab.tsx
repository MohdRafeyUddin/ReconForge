import React, { useState, useEffect } from "react";
import {
  Sparkles,
  ArrowUpRight,
  ArrowDownRight,
  Server,
  Globe2,
  FileCode,
  FolderSearch,
  ShieldAlert,
  RefreshCw,
  Clock,
  Layers,
  ChevronRight,
  Filter,
} from "lucide-react";
import { apiCall } from "../../services/api";

export interface ScanDiffSummary {
  new_subdomains_count: number;
  stale_subdomains_count: number;
  new_live_hosts_count: number;
  new_ports_count: number;
  closed_ports_count: number;
  changed_hosts_count: number;
  new_js_files_count: number;
  new_findings_count: number;
  new_content_paths_count?: number;
  total_changes: number;
}

export interface HostFingerprintChange {
  domain: string;
  changes: {
    field: string;
    priority?: string;
    old?: any;
    new?: any;
    added?: string[];
    removed?: string[];
  }[];
  old_fingerprint?: Record<string, any>;
  new_fingerprint?: Record<string, any>;
}

export interface ScanDiffData {
  new_subdomains: string[];
  stale_subdomains: string[];
  new_live_hosts: string[];
  new_ports: { domain: string; port: number }[];
  closed_ports: { domain: string; port: number }[];
  changed_hosts: HostFingerprintChange[];
  new_js_files: string[];
  new_findings: {
    domain?: string;
    matched_url: string;
    source?: string;
    severity?: string;
    payload?: string;
    parameter?: string;
  }[];
  new_content_paths?: {
    url?: string;
    value?: string;
    domain?: string;
    host?: string;
    status_code?: number;
    content_length?: number;
  }[];
}

export interface ScanDiffDoc {
  id?: string;
  _id?: string;
  project_id: string;
  current_job_id: string;
  previous_job_id?: string | null;
  summary: ScanDiffSummary;
  diff: ScanDiffData;
  created_at: string;
}

interface DiffTabProps {
  projectId: string;
  projectName?: string;
  latestDiffProp?: ScanDiffDoc | null;
}

type DiffSection =
  | "all"
  | "subdomains"
  | "stale"
  | "live"
  | "ports"
  | "fingerprints"
  | "findings"
  | "content_paths"
  | "js";

export const DiffTab: React.FC<DiffTabProps> = ({
  projectId,
  projectName = "Project",
  latestDiffProp,
}) => {
  const [diffDoc, setDiffDoc] = useState<ScanDiffDoc | null>(latestDiffProp || null);
  const [history, setHistory] = useState<ScanDiffDoc[]>([]);
  const [loading, setLoading] = useState<boolean>(!latestDiffProp);
  const [selectedSection, setSelectedSection] = useState<DiffSection>("all");
  const [searchFilter, setSearchFilter] = useState<string>("");

  const fetchDiffs = async () => {
    if (!projectId) return;
    setLoading(true);
    try {
      const [latestRes, historyRes] = await Promise.all([
        apiCall(`/projects/${projectId}/diffs/latest`) as Promise<ScanDiffDoc>,
        apiCall(`/projects/${projectId}/diffs?limit=15`) as Promise<ScanDiffDoc[]>,
      ]);
      if (latestRes && (latestRes as any).diff) {
        setDiffDoc(latestRes);
      } else {
        setDiffDoc(null);
      }
      if (Array.isArray(historyRes)) {
        setHistory(historyRes);
      }
    } catch (err) {
      console.error("[DiffTab] Failed to fetch scan diffs:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (latestDiffProp) {
      setDiffDoc(latestDiffProp);
    } else {
      fetchDiffs();
    }
  }, [projectId, latestDiffProp]);

  const selectHistoricalDiff = (diffId: string) => {
    const found = history.find((h) => (h.id || h._id) === diffId);
    if (found) {
      setDiffDoc(found);
    }
  };

  const diff = diffDoc?.diff || {
    new_subdomains: [],
    stale_subdomains: [],
    new_live_hosts: [],
    new_ports: [],
    closed_ports: [],
    changed_hosts: [],
    new_js_files: [],
    new_findings: [],
    new_content_paths: [],
  };

  const summary = diffDoc?.summary || {
    new_subdomains_count: 0,
    stale_subdomains_count: 0,
    new_live_hosts_count: 0,
    new_ports_count: 0,
    closed_ports_count: 0,
    changed_hosts_count: 0,
    new_js_files_count: 0,
    new_findings_count: 0,
    new_content_paths_count: 0,
    total_changes: 0,
  };

  const filterText = searchFilter.toLowerCase();

  const filteredNewSubs = diff.new_subdomains.filter((s) => s.toLowerCase().includes(filterText));
  const filteredStaleSubs = diff.stale_subdomains.filter((s) => s.toLowerCase().includes(filterText));
  const filteredNewLive = diff.new_live_hosts.filter((s) => s.toLowerCase().includes(filterText));
  const filteredNewPorts = diff.new_ports.filter(
    (p) => p.domain.toLowerCase().includes(filterText) || String(p.port).includes(filterText)
  );
  const filteredClosedPorts = diff.closed_ports.filter(
    (p) => p.domain.toLowerCase().includes(filterText) || String(p.port).includes(filterText)
  );
  const filteredChangedHosts = diff.changed_hosts.filter((h) =>
    h.domain.toLowerCase().includes(filterText)
  );
  const filteredFindings = diff.new_findings.filter(
    (f) =>
      f.matched_url.toLowerCase().includes(filterText) ||
      (f.source && f.source.toLowerCase().includes(filterText)) ||
      (f.severity && f.severity.toLowerCase().includes(filterText))
  );
  const filteredJs = diff.new_js_files.filter((u) => u.toLowerCase().includes(filterText));
  const filteredContentPaths = (diff.new_content_paths || []).filter(
    (cp) =>
      (cp.url || cp.value || "").toLowerCase().includes(filterText) ||
      (cp.domain || cp.host || "").toLowerCase().includes(filterText) ||
      String(cp.status_code || "").includes(filterText)
  );

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-16 space-y-3 bg-dark-card border border-dark-border rounded-xl">
        <RefreshCw className="w-8 h-8 text-cyber-accent animate-spin" />
        <span className="font-mono text-xs text-slate-400 uppercase tracking-widest">
          Analyzing Continuous Monitoring Diffs...
        </span>
      </div>
    );
  }

  if (!diffDoc) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-xl p-12 text-center space-y-4">
        <div className="w-14 h-14 mx-auto rounded-full bg-cyber-accent/10 border border-cyber-accent/30 flex items-center justify-center text-cyber-accent">
          <Sparkles className="w-7 h-7" />
        </div>
        <h3 className="text-base font-bold text-slate-200">No Scan Diffs Recorded Yet</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
          Diff tracking automatically runs after every discovery scan. Complete your initial scan
          and subsequent scans to monitor for new subdomains, changed HTTP responses, open ports,
          and newly surfaced vulnerabilities.
        </p>
        <button
          onClick={fetchDiffs}
          className="inline-flex items-center space-x-2 px-4 py-2 bg-dark-bg hover:bg-dark-hover border border-dark-border text-cyber-accent rounded text-xs font-bold transition-all cursor-pointer"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Check Again</span>
        </button>
      </div>
    );
  }

  const formattedDate = diffDoc.created_at
    ? new Date(diffDoc.created_at).toLocaleString()
    : "Just now";

  return (
    <div className="space-y-6">
      {/* Top Header & History Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-dark-card border border-dark-border rounded-xl p-4 glass">
        <div>
          <div className="flex items-center space-x-2">
            <Sparkles className="w-5 h-5 text-cyber-accent" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100">
              Continuous Monitoring & Attack Surface Diffs
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Tracking asset evolution, response fingerprint changes, and new findings for{" "}
            <span className="text-cyber-accent font-semibold">{projectName}</span>.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {history.length > 1 && (
            <div className="flex items-center space-x-2">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={diffDoc.id || diffDoc._id || ""}
                onChange={(e) => selectHistoricalDiff(e.target.value)}
                className="bg-dark-bg border border-dark-border text-slate-200 text-xs rounded px-2.5 py-1.5 focus:border-cyber-accent outline-none font-mono"
              >
                {history.map((h, idx) => (
                  <option key={h.id || h._id || idx} value={h.id || h._id}>
                    {new Date(h.created_at).toLocaleDateString()} {new Date(h.created_at).toLocaleTimeString()} ({h.summary.total_changes} changes)
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            onClick={fetchDiffs}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-dark-bg hover:bg-dark-hover border border-dark-border text-slate-300 hover:text-white rounded text-xs font-bold transition-all cursor-pointer"
            title="Reload latest diff"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Meta Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 bg-dark-bg/60 border border-dark-border rounded-lg text-xs font-mono text-slate-400">
        <div className="flex items-center space-x-4">
          <span>
            Diff Generated: <strong className="text-slate-200">{formattedDate}</strong>
          </span>
          <span>
            Current Job: <strong className="text-cyber-accent">{diffDoc.current_job_id}</strong>
          </span>
          {diffDoc.previous_job_id ? (
            <span>
              vs Previous Job: <strong className="text-slate-300">{diffDoc.previous_job_id}</strong>
            </span>
          ) : (
            <span className="text-cyber-warning font-semibold">Initial Baseline Scan</span>
          )}
        </div>
        <div className="text-right">
          Total Delta:{" "}
          <span className="text-cyber-accent font-bold text-sm">
            {summary.total_changes} changes detected
          </span>
        </div>
      </div>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        {/* New Subdomains */}
        <div
          onClick={() => setSelectedSection("subdomains")}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedSection === "subdomains"
              ? "bg-emerald-950/30 border-emerald-500/50 ring-1 ring-emerald-500/30"
              : "bg-dark-card border-dark-border hover:border-slate-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>New Subs</span>
            <ArrowUpRight className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400">
            +{summary.new_subdomains_count}
          </div>
        </div>

        {/* Stale Subdomains */}
        <div
          onClick={() => setSelectedSection("stale")}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedSection === "stale"
              ? "bg-rose-950/30 border-rose-500/50 ring-1 ring-rose-500/30"
              : "bg-dark-card border-dark-border hover:border-slate-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Stale Subs</span>
            <ArrowDownRight className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400">
            -{summary.stale_subdomains_count}
          </div>
        </div>

        {/* New Live Hosts */}
        <div
          onClick={() => setSelectedSection("live")}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedSection === "live"
              ? "bg-blue-950/30 border-blue-500/50 ring-1 ring-blue-500/30"
              : "bg-dark-card border-dark-border hover:border-slate-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>New Live</span>
            <Globe2 className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-xl font-bold font-mono text-blue-400">
            +{summary.new_live_hosts_count}
          </div>
        </div>

        {/* Ports (Open / Closed) */}
        <div
          onClick={() => setSelectedSection("ports")}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedSection === "ports"
              ? "bg-amber-950/30 border-amber-500/50 ring-1 ring-amber-500/30"
              : "bg-dark-card border-dark-border hover:border-slate-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Port Delta</span>
            <Server className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400">
            +{summary.new_ports_count} <span className="text-xs text-slate-500">/-{summary.closed_ports_count}</span>
          </div>
        </div>

        {/* Changed Responses */}
        <div
          onClick={() => setSelectedSection("fingerprints")}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedSection === "fingerprints"
              ? "bg-purple-950/30 border-purple-500/50 ring-1 ring-purple-500/30"
              : "bg-dark-card border-dark-border hover:border-slate-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Resp Changes</span>
            <Layers className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-xl font-bold font-mono text-purple-400">
            {summary.changed_hosts_count}
          </div>
        </div>

        {/* New Findings */}
        <div
          onClick={() => setSelectedSection("findings")}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedSection === "findings"
              ? "bg-red-950/30 border-red-500/50 ring-1 ring-red-500/30"
              : "bg-dark-card border-dark-border hover:border-slate-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Findings</span>
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
          </div>
          <div className="text-xl font-bold font-mono text-red-400">
            +{summary.new_findings_count}
          </div>
        </div>

        {/* Content Paths */}
        <div
          onClick={() => setSelectedSection("content_paths")}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedSection === "content_paths"
              ? "bg-amber-950/30 border-amber-500/50 ring-1 ring-amber-500/30"
              : "bg-dark-card border-dark-border hover:border-slate-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Content Paths</span>
            <FolderSearch className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400">
            +{summary.new_content_paths_count || 0}
          </div>
        </div>

        {/* New JS Files */}
        <div
          onClick={() => setSelectedSection("js")}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedSection === "js"
              ? "bg-cyan-950/30 border-cyan-500/50 ring-1 ring-cyan-500/30"
              : "bg-dark-card border-dark-border hover:border-slate-600"
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>New JS</span>
            <FileCode className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-cyan-400">
            +{summary.new_js_files_count}
          </div>
        </div>
      </div>

      {/* Filter and Sub-navigation Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border-b border-dark-border pb-2">
        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
          {[
            { id: "all", label: "All Changes", count: summary.total_changes },
            { id: "subdomains", label: "New Subdomains", count: summary.new_subdomains_count },
            { id: "stale", label: "Stale Subdomains", count: summary.stale_subdomains_count },
            { id: "live", label: "New Live", count: summary.new_live_hosts_count },
            { id: "ports", label: "Ports", count: summary.new_ports_count + summary.closed_ports_count },
            { id: "fingerprints", label: "Changed Responses", count: summary.changed_hosts_count },
            { id: "findings", label: "New Findings", count: summary.new_findings_count },
            { id: "content_paths", label: "New Content Paths", count: summary.new_content_paths_count || 0 },
            { id: "js", label: "New JS", count: summary.new_js_files_count },
          ].map((sec) => (
            <button
              key={sec.id}
              onClick={() => setSelectedSection(sec.id as DiffSection)}
              className={`px-3 py-1.5 rounded text-xs font-bold transition-all whitespace-nowrap cursor-pointer ${
                selectedSection === sec.id
                  ? "bg-dark-card text-cyber-accent border border-dark-border shadow-sm"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {sec.label}
              {sec.count > 0 && (
                <span className="ml-1.5 px-1.5 py-0.2 bg-dark-bg text-[10px] rounded-full font-mono">
                  {sec.count}
                </span>
              )}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <input
            type="text"
            placeholder="Filter changes..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full bg-dark-bg border border-dark-border text-xs rounded-lg pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:border-cyber-accent outline-none font-mono"
          />
          <Filter className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
        </div>
      </div>

      {/* Content Panels */}
      <div className="space-y-6">
        {/* New Subdomains Section */}
        {(selectedSection === "all" || selectedSection === "subdomains") && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass">
            <div className="flex items-center justify-between mb-3 border-b border-dark-border pb-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  New Subdomains ({filteredNewSubs.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-emerald-400 font-bold uppercase">
                Discovered in this scan
              </span>
            </div>
            {filteredNewSubs.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-2">
                No new subdomains in this scan.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {filteredNewSubs.map((sub) => (
                  <div
                    key={sub}
                    className="flex items-center justify-between px-3 py-2 bg-emerald-950/20 border border-emerald-500/20 rounded-lg text-xs font-mono text-emerald-300"
                  >
                    <span className="truncate" title={sub}>{sub}</span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-emerald-500/20 text-emerald-300 rounded font-bold ml-2">
                      +NEW
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Stale Subdomains Section */}
        {(selectedSection === "all" || selectedSection === "stale") && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass">
            <div className="flex items-center justify-between mb-3 border-b border-dark-border pb-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  Stale Subdomains ({filteredStaleSubs.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-rose-400 font-bold uppercase">
                Disappeared (Marked stale, not deleted)
              </span>
            </div>
            {filteredStaleSubs.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-2">
                No stale or disappeared subdomains.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {filteredStaleSubs.map((sub) => (
                  <div
                    key={sub}
                    className="flex items-center justify-between px-3 py-2 bg-rose-950/20 border border-rose-500/20 rounded-lg text-xs font-mono text-rose-300"
                  >
                    <span className="truncate line-through opacity-80" title={sub}>
                      {sub}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-rose-500/20 text-rose-300 rounded font-bold ml-2">
                      STALE
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* New Live Hosts Section */}
        {(selectedSection === "all" || selectedSection === "live") && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass">
            <div className="flex items-center justify-between mb-3 border-b border-dark-border pb-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  New Live HTTP Hosts ({filteredNewLive.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-blue-400 font-bold uppercase">
                HTTP 200/300 Live Target Delta
              </span>
            </div>
            {filteredNewLive.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-2">
                No new live HTTP hosts in this scan.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                {filteredNewLive.map((host) => (
                  <div
                    key={host}
                    className="flex items-center justify-between px-3 py-2 bg-blue-950/20 border border-blue-500/20 rounded-lg text-xs font-mono text-blue-300"
                  >
                    <span className="truncate" title={host}>{host}</span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-blue-500/20 text-blue-300 rounded font-bold ml-2">
                      LIVE
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Changed HTTP Response Fingerprints */}
        {(selectedSection === "all" || selectedSection === "fingerprints") && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass">
            <div className="flex items-center justify-between mb-3 border-b border-dark-border pb-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  HTTP Response & Fingerprint Changes ({filteredChangedHosts.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-purple-400 font-bold uppercase">
                Content / Status / Title Delta
              </span>
            </div>
            {filteredChangedHosts.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-2">
                No host response changes detected.
              </p>
            ) : (
              <div className="space-y-3">
                {filteredChangedHosts.map((ch) => (
                  <div
                    key={ch.domain}
                    className="bg-dark-bg/80 border border-purple-500/30 rounded-lg p-3 space-y-2 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between font-bold text-slate-200">
                      <span className="text-cyber-accent">{ch.domain}</span>
                      <span className="text-[10px] px-2 py-0.5 bg-purple-500/20 text-purple-300 rounded">
                        {ch.changes.length} change(s)
                      </span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1 border-t border-dark-border/50 text-[11px]">
                      {ch.changes.map((change, cIdx) => (
                        <div key={cIdx} className="bg-dark-card/60 p-2 rounded border border-dark-border">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-slate-400 uppercase font-bold text-[10px] block">
                              {change.field}
                            </span>
                            {change.priority === "low" || change.field === "body_hash" || change.field === "content_length" ? (
                              <span className="text-[9px] px-1.5 py-0.5 bg-slate-800 text-slate-400 border border-slate-700 rounded font-mono font-medium">
                                Low Priority
                              </span>
                            ) : (
                              <span className="text-[9px] px-1.5 py-0.5 bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded font-mono font-bold">
                                Alertable
                              </span>
                            )}
                          </div>
                          {change.field === "technologies" ? (
                            <div className="space-y-1">
                              {change.added && change.added.length > 0 && (
                                <div className="text-emerald-400">
                                  + Added: {change.added.join(", ")}
                                </div>
                              )}
                              {change.removed && change.removed.length > 0 && (
                                <div className="text-rose-400">
                                  - Removed: {change.removed.join(", ")}
                                </div>
                              )}
                            </div>
                          ) : (
                            <div className="flex items-center space-x-2">
                              <span className="text-rose-400 line-through">
                                {String(change.old ?? "none")}
                              </span>
                              <ChevronRight className="w-3 h-3 text-slate-500" />
                              <span className="text-emerald-400 font-bold">
                                {String(change.new ?? "none")}
                              </span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Port Changes */}
        {(selectedSection === "all" || selectedSection === "ports") && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass">
            <div className="flex items-center justify-between mb-3 border-b border-dark-border pb-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  Port Changes (+{filteredNewPorts.length} Open / -{filteredClosedPorts.length} Closed)
                </h3>
              </div>
              <span className="text-[10px] font-mono text-amber-400 font-bold uppercase">
                Port Delta
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="text-[11px] font-bold text-emerald-400 uppercase mb-2">
                  Newly Opened Ports ({filteredNewPorts.length})
                </h4>
                {filteredNewPorts.length === 0 ? (
                  <p className="text-xs text-slate-500 font-mono">No new ports opened.</p>
                ) : (
                  <div className="space-y-1.5">
                    {filteredNewPorts.map((p, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between px-3 py-1.5 bg-emerald-950/20 border border-emerald-500/20 rounded text-xs font-mono text-emerald-300"
                      >
                        <span className="truncate">{p.domain}</span>
                        <span className="font-bold bg-emerald-500/30 px-2 py-0.5 rounded text-[10px]">
                          :{p.port}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <h4 className="text-[11px] font-bold text-rose-400 uppercase mb-2">
                  Closed Ports ({filteredClosedPorts.length})
                </h4>
                {filteredClosedPorts.length === 0 ? (
                  <p className="text-xs text-slate-500 font-mono">No ports closed.</p>
                ) : (
                  <div className="space-y-1.5">
                    {filteredClosedPorts.map((p, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between px-3 py-1.5 bg-rose-950/20 border border-rose-500/20 rounded text-xs font-mono text-rose-300"
                      >
                        <span className="truncate">{p.domain}</span>
                        <span className="font-bold bg-rose-500/30 px-2 py-0.5 rounded text-[10px] line-through">
                          :{p.port}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* New Vulnerabilities & Findings */}
        {(selectedSection === "all" || selectedSection === "findings") && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass">
            <div className="flex items-center justify-between mb-3 border-b border-dark-border pb-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  New Vulnerability Findings ({filteredFindings.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-red-400 font-bold uppercase">
                New Security Alerts
              </span>
            </div>
            {filteredFindings.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-2">
                No new vulnerability findings in this scan.
              </p>
            ) : (
              <div className="space-y-2">
                {filteredFindings.map((f, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-red-950/20 border border-red-500/30 rounded-lg text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-red-300 truncate" title={f.matched_url}>
                        {f.matched_url}
                      </span>
                      <span className="px-2 py-0.5 bg-red-500/20 border border-red-500/40 text-red-400 rounded text-[10px] font-bold uppercase">
                        {f.severity || "medium"}
                      </span>
                    </div>
                    <div className="flex items-center space-x-4 text-slate-400 text-[11px]">
                      <span>Source: <strong className="text-slate-200">{f.source || "recon"}</strong></span>
                      {f.parameter && (
                        <span>Parameter: <strong className="text-amber-400">{f.parameter}</strong></span>
                      )}
                      {f.payload && (
                        <span className="truncate max-w-xs">
                          Payload: <code className="text-slate-300">{f.payload}</code>
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* New Content Paths */}
        {(selectedSection === "all" || selectedSection === "content_paths") && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass">
            <div className="flex items-center justify-between mb-3 border-b border-dark-border pb-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  New Content Paths ({filteredContentPaths.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-amber-400 font-bold uppercase">
                Newly Discovered Endpoints
              </span>
            </div>
            {filteredContentPaths.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-2">
                No new content paths discovered in this scan.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                      <th className="p-2.5">URL</th>
                      <th className="p-2.5">Host</th>
                      <th className="p-2.5">Status</th>
                      <th className="p-2.5">Length</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredContentPaths.map((cp: any, idx: number) => {
                      const url = cp.url || cp.value || "";
                      const host = cp.domain || cp.host || "";
                      const sc = cp.status_code || 200;
                      return (
                        <tr key={idx} className="border-b border-dark-border hover:bg-dark-hover/30 transition-colors font-mono">
                          <td className="p-2.5 text-slate-200 break-all max-w-md">{url}</td>
                          <td className="p-2.5 text-slate-400">{host}</td>
                          <td className="p-2.5">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              sc >= 200 && sc < 300
                                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                                : sc >= 300 && sc < 400
                                ? "bg-blue-500/20 text-blue-400 border border-blue-500/40"
                                : sc === 401 || sc === 403
                                ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                                : "bg-slate-700/40 text-slate-400 border border-slate-600/40"
                            }`}>
                              {sc}
                            </span>
                          </td>
                          <td className="p-2.5 text-slate-400">{cp.content_length ?? 0} B</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* New JavaScript Files */}
        {(selectedSection === "all" || selectedSection === "js") && (
          <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass">
            <div className="flex items-center justify-between mb-3 border-b border-dark-border pb-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  New JavaScript Endpoints ({filteredJs.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase">
                Newly Tracked Scripts
              </span>
            </div>
            {filteredJs.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono py-2">
                No new JS files in this scan.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {filteredJs.map((jsUrl, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between px-3 py-2 bg-cyan-950/20 border border-cyan-500/20 rounded text-xs font-mono text-cyan-300"
                  >
                    <span className="truncate" title={jsUrl}>{jsUrl}</span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-cyan-500/20 text-cyan-300 rounded font-bold ml-2">
                      +JS
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
