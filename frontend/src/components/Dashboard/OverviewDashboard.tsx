import React, { useEffect, useState } from "react";
import { StatCard } from "./StatCard";
import { DnsxCard } from "./DnsxCard";
import { SubzyCard } from "./SubzyCard";
import { UroCard } from "./UroCard";
import { GfCard } from "./GfCard";
import type { GfCategoryStats } from "./GfCard";
import { Globe, Server, Radio, ShieldAlert, Play, Pause, Square, RotateCcw, RefreshCw, FileText, Link, AlertCircle } from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from "recharts";
import { apiCall } from "../../services/api";

interface DashboardStats {
  total_assets: number;
  total_subdomains: number;
  live_hosts: number;
  open_ports_count: number;
  last_scan_time: string | null;
  ports_distribution: { port: number; count: number }[];
  sources_distribution: { name: string; value: number }[];
  provider_counts?: {
    subfinder?: number;
    assetfinder?: number;
    amass?: number;
    chaos?: number;
  };
  // new provider counters
  dnsx_resolved?: number;
  dnsx_nxdomain?: number;
  dnsx_wildcards?: number;
  dnsx_unique_ips?: number;
  subzy_vulnerable?: number;
  subzy_not_vulnerable?: number;
  subzy_unknown?: number;
  uro_input?: number;
  uro_normalised?: number;
  uro_removed?: number;
  gf_categories?: Partial<GfCategoryStats>;
  gf_total?: number;
  normalized_urls_count?: number;
  gf_urls_count?: number;
}

interface Project {
  id: string;
  name: string;
  description?: string;
  seed_domains: string[];
}

interface Asset {
  id: string;
  domain: string;
  type: string;
  status: string;
  open_ports?: number[];
  discovered_by?: string;
  created_at?: string;
  sources?: string[];
  metadata?: {
    url?: string;
    status_code?: number;
    title?: string;
    ip_address?: string;
    technologies?: string[];
    katana?: {
      endpoints?: string[];
      js_files?: string[];
      forms?: any[];
      third_party_urls?: string[];
    };
    nuclei?: {
      findings?: {
        template_id: string;
        name: string;
        severity: string;
        matched_url: string;
        description: string;
        tags: string[];
        cve?: string;
        reference_urls?: string[];
        timestamp: string;
      }[];
    };
    [key: string]: any;
  };
}

interface OverviewDashboardProps {
  stats: DashboardStats;
  assets?: Asset[];
  activeProject: Project;
  onLaunchScan: (providerName: string) => void;
  onRefresh: () => void;
  activeJob?: any | null;
  completedProviders?: Set<string>;
  currentPhase?: string;
  onPauseScan?: () => void;
  onResumeScan?: () => void;
  onStopScan?: () => void;
  onResetScan?: () => void;
  stages?: Record<string, "PENDING" | "RUNNING" | "COMPLETED" | "FAILED">;
  providerStatus?: Record<string, "PENDING" | "RUNNING" | "COMPLETED" | "FAILED">;
}

const COLORS = ["#3B82F6", "#06B6D4", "#10B981", "#F59E0B", "#EF4444"];

const FALLBACK_PROVIDERS = [
  "Unified Discovery",
  "Subfinder",
  "Assetfinder",
  "Amass",
  "Chaos",
];

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  stats,
  assets = [],
  activeProject,
  onLaunchScan,
  onRefresh,
  activeJob = null,
  currentPhase = "waiting",
  onPauseScan,
  onResumeScan,
  onStopScan,
  onResetScan,
  stages = {},
  providerStatus = {},
}) => {
  const [selectedProvider, setSelectedProvider] = useState("Unified Discovery");
  const [providers, setProviders] = useState<string[]>(FALLBACK_PROVIDERS);
  const [generatingReport, setGeneratingReport] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const fetchProviders = async () => {
      try {
        const registeredProviders = await apiCall("/jobs/providers");
        const names = registeredProviders
          .map((provider: { name?: string }) => provider.name)
          .filter((name: string | undefined): name is string => Boolean(name));

        if (!cancelled && names.length > 0) {
          setProviders(names);

          setSelectedProvider((current) =>
            names.includes(current) ? current : names[0]
          );
        }
      } catch (err) {
        console.error("Failed to load registered providers", err);
      }
    };

    fetchProviders();

    return () => {
      cancelled = true;
    };
  }, []);



  const getPhaseText = (phaseName: string, phaseLabel: string) => {
    const status = stages[phaseName] || "PENDING";
    if (status === "COMPLETED") return `${phaseLabel} ✓`;
    if (status === "RUNNING") {
      if (activeJob?.status === "paused") return `${phaseLabel} (Paused)`;
      if (activeJob?.status === "stopped") return `${phaseLabel} (Stopped)`;
      return `${phaseLabel} ⟳ Running`;
    }
    if (status === "FAILED") return `${phaseLabel} ✕ Failed`;
    return phaseLabel === "Discovery" ? "Discovery Waiting" : phaseLabel;
  };

  const getPhaseClass = (phaseName: string) => {
    const status = stages[phaseName] || "PENDING";
    if (status === "RUNNING") {
      if (activeJob?.status === "paused") return "bg-cyber-warning/20 border border-cyber-warning/50 text-cyber-warning font-bold";
      if (activeJob?.status === "stopped") return "bg-cyber-danger/20 border border-cyber-danger/50 text-cyber-danger font-bold";
      return "bg-cyber-accent/20 border border-cyber-accent/50 text-cyber-accent animate-pulse font-bold";
    }
    if (status === "COMPLETED") return "bg-cyber-success/10 border border-cyber-success/30 text-cyber-success";
    if (status === "FAILED") return "bg-cyber-danger/20 border border-cyber-danger/50 text-cyber-danger font-bold";
    return "text-slate-500 border border-transparent";
  };

  const handleExportHTML = async () => {
    setGeneratingReport(true);
    try {
      const htmlContent = await apiCall(`/reports/project/${activeProject.id}/export/html`);
      const blob = new Blob([htmlContent], { type: "text/html" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reconforge_report_${activeProject.name.toLowerCase()}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to export report", err);
    } finally {
      setGeneratingReport(false);
    }
  };

  const [showExportDropdown, setShowExportDropdown] = useState(false);

  const getProviderStatus = (tool: string): "waiting" | "running" | "completed" | "failed" | "paused" | "stopped" => {
    const status = providerStatus[tool.toLowerCase()] || "PENDING";
    if (status === "COMPLETED") return "completed";
    if (status === "FAILED") return "failed";
    if (status === "RUNNING") {
      if (activeJob?.status === "paused") return "paused";
      if (activeJob?.status === "stopped") return "stopped";
      return "running";
    }
    return "waiting";
  };

  const escapeCSV = (val: any) => {
    if (val === null || val === undefined) return '""';
    let str = String(val);
    str = str.replace(/"/g, '""');
    return `"${str}"`;
  };

  const handleExportFullCSV = () => {
    const headers = [
      "Subdomain", "Source", "Discovery Time", "Live Status", "URL",
      "Technologies", "HTTP Status", "Title", "Open Ports", "Katana URLs",
      "JS Files", "Parameters", "Nuclei Findings", "Metadata"
    ];

    const rows = assets.map(asset => {
      const source = (asset.sources || []).join("; ") || asset.discovered_by || "unknown";
      const discoveryTime = asset.created_at || (asset as any).first_seen || "";
      const url = asset.metadata?.url || "";
      const technologies = (asset.metadata?.technologies || []).join("; ");
      const httpStatus = asset.metadata?.status_code !== undefined ? asset.metadata.status_code : "";
      const title = asset.metadata?.title || "";
      const openPorts = (asset.open_ports || []).join("; ");
      const katanaUrls = (asset.metadata?.katana?.endpoints || []).join("; ");
      const jsFiles = (asset.metadata?.katana?.js_files || []).join("; ");
      const parameters = (asset.metadata?.katana?.forms || []).map((f: any) => typeof f === "string" ? f : (f.action || "")).join("; ");
      const nucleiFindings = (asset.metadata?.nuclei?.findings || []).map((f: any) => `[${f.severity}] ${f.name || f.template_id}`).join("; ");
      const metadata = JSON.stringify(asset.metadata || {});

      return [
        asset.domain, source, discoveryTime, asset.status, url,
        technologies, httpStatus, title, openPorts, katanaUrls,
        jsFiles, parameters, nucleiFindings, metadata
      ];
    });

    const csvContent = [headers, ...rows]
      .map(row => row.map(escapeCSV).join(","))
      .join("\r\n");

    const blob = new Blob(["\uFEFF" + csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reconforge_full_export_${activeProject.name.toLowerCase()}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportSubdomainsOnlyCSV = () => {
    const uniqueDomains = Array.from(new Set(assets.map(a => a.domain))).sort();
    const csvContent = uniqueDomains.join("\r\n");

    const blob = new Blob(["\uFEFF" + csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "subdomains.csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Derive main dashboard stats dynamically from assets
  const derivedTotalAssets = assets.length;
  const derivedTotalSubdomains = assets.filter((a) => a.type === "subdomain").length;
  const derivedLiveHosts = assets.filter((a) => a.status === "live").length;

  // Derive provider counts dynamically from assets array
  const pc = {
    subfinder: assets.filter((a) => (a.sources || []).some((s) => s.toLowerCase() === "subfinder") || a.discovered_by?.toLowerCase() === "subfinder").length,
    assetfinder: assets.filter((a) => (a.sources || []).some((s) => s.toLowerCase() === "assetfinder") || a.discovered_by?.toLowerCase() === "assetfinder").length,
    amass: assets.filter((a) => (a.sources || []).some((s) => s.toLowerCase() === "amass") || a.discovered_by?.toLowerCase() === "amass").length,
    chaos: assets.filter((a) => (a.sources || []).some((s) => s.toLowerCase() === "chaos") || a.discovered_by?.toLowerCase() === "chaos").length,
  };

  const totalOpenPortFindings = assets.reduce(
    (total, asset) => total + (asset.open_ports?.length ?? 0),
    0
  );
  const hostsWithOpenPorts = assets.filter(
    (asset) => (asset.open_ports?.length ?? 0) > 0
  ).length;

  const totalUrlsDiscovered = assets.reduce(
    (total, asset) => total + (
      (asset.metadata?.katana?.endpoints?.length || 0) +
      (asset.metadata?.katana?.js_files?.length || 0) +
      (asset.metadata?.katana?.forms?.length || 0) +
      (asset.metadata?.katana?.third_party_urls?.length || 0)
    ),
    0
  );

  const criticalCount = assets.reduce((t, a) => t + (a.metadata?.nuclei?.findings?.filter(f => (f.severity || "").toLowerCase() === "critical").length || 0), 0);
  const highCount = assets.reduce((t, a) => t + (a.metadata?.nuclei?.findings?.filter(f => (f.severity || "").toLowerCase() === "high").length || 0), 0);
  const mediumCount = assets.reduce((t, a) => t + (a.metadata?.nuclei?.findings?.filter(f => (f.severity || "").toLowerCase() === "medium").length || 0), 0);
  const lowCount = assets.reduce((t, a) => t + (a.metadata?.nuclei?.findings?.filter(f => (f.severity || "").toLowerCase() === "low").length || 0), 0);
  const infoCount = assets.reduce((t, a) => t + (a.metadata?.nuclei?.findings?.filter(f => (f.severity || "").toLowerCase() === "info").length || 0), 0);
  const totalNucleiFindings = criticalCount + highCount + mediumCount + lowCount + infoCount;

  // Recompute ports distribution dynamically from assets
  const portCounts: Record<number, number> = {};
  assets.forEach((a) => {
    (a.open_ports || []).forEach((p: number) => {
      portCounts[p] = (portCounts[p] || 0) + 1;
    });
  });
  const derivedPortsDistribution = Object.entries(portCounts)
    .map(([port, count]) => ({
      port: parseInt(port),
      count: count as number,
    }))
    .sort((a, b) => b.count - a.count);

  // Recompute sources distribution dynamically from assets
  const sourceGroups: Record<string, number> = {};
  assets.forEach((a) => {
    const src = a.discovered_by || "unknown";
    sourceGroups[src] = (sourceGroups[src] || 0) + 1;
  });
  const derivedSourcesDistribution = Object.entries(sourceGroups).map(([name, value]) => ({
    name,
    value: value as number,
  }));

  const providerBreakdown = [
    { label: "Subfinder", tool: "subfinder", color: "#3B82F6" },
    { label: "Assetfinder", tool: "assetfinder", color: "#06B6D4" },
    { label: "Amass", tool: "amass", color: "#10B981" },
    { label: "Chaos", tool: "chaos", color: "#F59E0B" },
  ].map(p => {
    const pStatus = getProviderStatus(p.tool);
    const rawCount = pc[p.tool as keyof typeof pc] ?? 0;
    const countDisplay = (activeJob && pStatus === "waiting") ? "-" : rawCount;
    return {
      ...p,
      status: pStatus,
      countDisplay,
      count: rawCount,
    };
  });

  return (
    <div className="space-y-6">
      {/* Phase Tracker for Active Scan */}
      {activeJob && ["running", "pending", "paused", "stopped"].includes(activeJob.status) && (
        <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass animate-fadeIn">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              {activeJob.status === "paused" ? (
                <Pause className="w-4 h-4 text-cyber-warning animate-pulse" />
              ) : activeJob.status === "stopped" ? (
                <Square className="w-4 h-4 text-cyber-danger fill-current" />
              ) : (
                <RefreshCw className="w-4 h-4 text-cyber-accent animate-spin" />
              )}
              <span className="font-mono text-xs text-slate-200 uppercase tracking-wider font-semibold">
                Active Scan Progress:{" "}
                <span className={
                  activeJob.status === "paused" ? "text-cyber-warning" :
                  activeJob.status === "stopped" ? "text-cyber-danger" :
                  "text-cyber-accent"
                }>
                  {activeJob.status.toUpperCase()}
                </span>
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
              {([
                ["discovery", "Passive"],
                ["dnsx",      "DNSx"],
                ["subzy",     "Subzy"],
                ["naabu",     "Naabu"],
                ["httpx",     "HTTPX"],
                ["katana",    "Katana"],
                ["uro",       "Uro"],
                ["gf",        "GF"],
                ["nuclei",    "Nuclei"],
              ] as [string, string][]).map(([phase, label], i, arr) => (
                <React.Fragment key={phase}>
                  <span className={`px-2 py-0.5 rounded ${getPhaseClass(phase)}`}>
                    {getPhaseText(phase, label)}
                  </span>
                  {i < arr.length - 1 && <span className="text-slate-700">{"\u2192"}</span>}
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Upper stats row */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-4">
        <StatCard
          title="Total Domains/Assets"
          value={derivedTotalAssets > 0 ? derivedTotalAssets : "-"}
          subtext="Total unique targets discovered"
          icon={<Globe className="w-6 h-6" />}
          colorClass="text-cyber-primary"
          glowClass="glow-blue"
        />
        <StatCard
          title="Discovered Subdomains"
          value={derivedTotalSubdomains > 0 ? derivedTotalSubdomains : "-"}
          subtext="Target child hosts mapped"
          icon={<Server className="w-6 h-6" />}
          colorClass="text-cyber-accent"
          glowClass="glow-cyan"
        />
        <StatCard
          title="Live Probed Hosts"
          value={derivedLiveHosts > 0 ? derivedLiveHosts : "-"}
          subtext="Hosts responding to requests"
          icon={<Radio className="w-6 h-6 animate-pulse" />}
          colorClass="text-cyber-success"
          glowClass="glow-cyan"
        />
        <StatCard
          title="Exposed Open Ports"
          value={totalOpenPortFindings > 0 ? totalOpenPortFindings : "-"}
          subtext={`${hostsWithOpenPorts} hosts | ${stats.open_ports_count} unique ports`}
          icon={<ShieldAlert className="w-6 h-6" />}
          colorClass="text-cyber-danger"
          glowClass="glow-blue"
        />
        <StatCard
          title="Crawled URLs"
          value={totalUrlsDiscovered > 0 ? totalUrlsDiscovered : "-"}
          subtext="Discovered endpoints & resources"
          icon={<Link className="w-6 h-6" />}
          colorClass="text-cyber-warning"
          glowClass="glow-orange"
        />
        <StatCard
          title="Security Findings"
          value={totalNucleiFindings > 0 ? totalNucleiFindings : "-"}
          subtext="Vulnerabilities & exposures"
          icon={<AlertCircle className="w-6 h-6" />}
          colorClass="text-cyber-danger"
          glowClass="glow-red"
        />
      </div>

      {/* Provider Yield Breakdown */}
      {(providerBreakdown.some(p => p.count > 0) || activeJob) && (
        <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
          <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2">
            Provider Yield Breakdown
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {providerBreakdown.map((p) => (
              <div key={p.label} className="bg-dark-bg border border-dark-border rounded-lg p-3 flex flex-col items-center text-center relative overflow-hidden">
                <div className="flex items-center gap-1.5 mb-1.5 justify-center">
                  {p.status === "completed" && <span className="text-cyber-success text-xs font-bold">✓</span>}
                  {p.status === "running" && <RefreshCw className="w-3 h-3 animate-spin text-cyber-accent" />}
                  {p.status === "waiting" && <span className="text-slate-500 text-xs">○</span>}
                  {p.status === "failed" && <span className="text-cyber-danger text-xs font-bold">✕</span>}
                  {p.status === "paused" && <Pause className="w-3 h-3 text-cyber-warning" />}
                  {p.status === "stopped" && <Square className="w-3 h-3 text-cyber-danger fill-current" />}
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">{p.label}</span>
                </div>
                <span className="text-2xl font-mono font-bold" style={{ color: p.color }}>{p.countDisplay}</span>
                <span className="text-[9px] text-slate-500 mt-1 capitalize">{p.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* New Provider Cards (DNSx, Subzy, Uro, GF) — shown when data exists or job running */}
      {(activeJob || stats.dnsx_resolved !== undefined || stats.subzy_vulnerable !== undefined ||
        stats.uro_normalised !== undefined || stats.gf_total !== undefined) && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <DnsxCard
            stats={{
              resolved: stats.dnsx_resolved ?? 0,
              unique_ips: stats.dnsx_unique_ips ?? 0,
              wildcard_filtered: stats.dnsx_wildcards ?? 0,
              nxdomain: stats.dnsx_nxdomain ?? 0,
            }}
            isRunning={activeJob?.status === "running" && currentPhase === "dnsx"}
          />
          <SubzyCard
            stats={{
              vulnerable: stats.subzy_vulnerable ?? 0,
              not_vulnerable: stats.subzy_not_vulnerable ?? 0,
              unknown: stats.subzy_unknown ?? 0,
            }}
            isRunning={activeJob?.status === "running" && currentPhase === "subzy"}
          />
          <UroCard
            stats={{
              input_urls: stats.uro_input ?? 0,
              normalised_urls: stats.uro_normalised ?? 0,
              removed: stats.uro_removed ?? 0,
            }}
            isRunning={activeJob?.status === "running" && currentPhase === "uro"}
          />
          <GfCard
            stats={{
              xss:      stats.gf_categories?.xss ?? 0,
              sqli:     stats.gf_categories?.sqli ?? 0,
              ssrf:     stats.gf_categories?.ssrf ?? 0,
              redirect: stats.gf_categories?.redirect ?? 0,
              lfi:      stats.gf_categories?.lfi ?? 0,
              rce:      stats.gf_categories?.rce ?? 0,
              idor:     stats.gf_categories?.idor ?? 0,
              ssti:     stats.gf_categories?.ssti ?? 0,
              debug:    stats.gf_categories?.debug ?? 0,
              upload:   stats.gf_categories?.upload ?? 0,
              aws:      stats.gf_categories?.aws ?? 0,
              graphql:  stats.gf_categories?.graphql ?? 0,
            }}
            isRunning={activeJob?.status === "running" && currentPhase === "gf"}
          />
        </div>
      )}

      {/* Vulnerability Summary Card */}
      <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
        <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2">
          Vulnerability Summary (Nuclei)
        </h4>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: "Critical", count: criticalCount, color: "text-cyber-danger", border: "border-cyber-danger/30" },
            { label: "High", count: highCount, color: "text-orange-500", border: "border-orange-500/30" },
            { label: "Medium", count: mediumCount, color: "text-cyber-warning", border: "border-cyber-warning/30" },
            { label: "Low", count: lowCount, color: "text-cyber-accent", border: "border-cyber-accent/30" },
            { label: "Info", count: infoCount, color: "text-slate-400", border: "border-slate-500/30" }
          ].map((item) => (
            <div key={item.label} className={`bg-dark-bg border ${item.border} rounded-lg p-3.5 flex flex-col items-center text-center transition-all hover:scale-[1.02] hover:bg-dark-hover/10`}>
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">{item.label}</span>
              <span className={`text-3xl font-mono font-bold ${item.color}`}>{item.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Main split grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Scope Control Panel */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-6 glass lg:col-span-1 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-dark-border pb-3 mb-4">
              <h3 className="font-bold text-white uppercase tracking-wider text-sm font-mono flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-cyber-accent" />
                <span>Scope Orchestrator</span>
              </h3>
              <button
                onClick={onRefresh}
                className="p-1 hover:bg-dark-bg border border-transparent hover:border-dark-border text-slate-400 hover:text-white rounded transition-all cursor-pointer"
                title="Refresh stats"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block mb-1">DESIGNATION</span>
                <span className="text-white font-bold text-sm">{activeProject.name}</span>
              </div>

              <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block mb-1">SEED TARGETS</span>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {activeProject.seed_domains.map(d => (
                    <span key={d} className="px-2 py-1 bg-dark-bg border border-dark-border rounded text-xs font-mono text-slate-300">
                      {d}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block mb-2">PIPELINE STATS</span>
                <div className="space-y-1">
                  {stats.dnsx_resolved !== undefined && (
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-500">DNSx Resolved</span>
                      <span className="text-cyber-accent">{stats.dnsx_resolved}</span>
                    </div>
                  )}
                  {stats.subzy_vulnerable !== undefined && stats.subzy_vulnerable > 0 && (
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-500">Takeovers Found</span>
                      <span className="text-cyber-danger font-bold">{stats.subzy_vulnerable}</span>
                    </div>
                  )}
                  {stats.uro_normalised !== undefined && (
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-500">Normalized URLs</span>
                      <span className="text-cyber-primary">{stats.uro_normalised}</span>
                    </div>
                  )}
                  {stats.gf_total !== undefined && stats.gf_total > 0 && (
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-500">Interesting Endpoints</span>
                      <span className="text-cyber-warning">{stats.gf_total}</span>
                    </div>
                  )}
                  {stats.dnsx_resolved === undefined && stats.uro_normalised === undefined && (
                    <span className="text-slate-600 text-[10px] font-mono uppercase tracking-wider">Run a full scan to see pipeline stats</span>
                  )}
                </div>
              </div>

              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block mb-1">LAST SCAN OPERATION</span>
                <span className="text-slate-300 text-xs font-mono">
                  {stats.last_scan_time ? new Date(stats.last_scan_time).toLocaleString() : "Never Scanned"}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-8 pt-4 border-t border-dark-border space-y-4">
            {activeJob && ["pending", "running", "paused", "stopped"].includes(activeJob.status) ? (
              <div className="space-y-3">
                <span className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1">Scan Control Console</span>
                <div className="grid grid-cols-2 gap-2">
                  {activeJob.status === "paused" ? (
                    <button
                      onClick={onResumeScan}
                      className="flex items-center justify-center space-x-1.5 bg-cyber-success/20 border border-cyber-success/40 hover:bg-cyber-success/30 text-cyber-success py-2 rounded text-xs font-bold uppercase tracking-wider transition-all cursor-pointer"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Resume</span>
                    </button>
                  ) : (
                    <button
                      onClick={onPauseScan}
                      disabled={activeJob.status !== "running" && activeJob.status !== "pending"}
                      className="flex items-center justify-center space-x-1.5 bg-cyber-warning/20 border border-cyber-warning/40 hover:bg-cyber-warning/30 text-cyber-warning py-2 rounded text-xs font-bold uppercase tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                    >
                      <Pause className="w-3.5 h-3.5" />
                      <span>Pause</span>
                    </button>
                  )}

                  <button
                    onClick={onStopScan}
                    disabled={activeJob.status !== "running" && activeJob.status !== "pending" && activeJob.status !== "paused"}
                    className="flex items-center justify-center space-x-1.5 bg-cyber-danger/20 border border-cyber-danger/40 hover:bg-cyber-danger/30 text-cyber-danger py-2 rounded text-xs font-bold uppercase tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                  >
                    <Square className="w-3.5 h-3.5 fill-current" />
                    <span>Stop</span>
                  </button>
                </div>
                
                <button
                  onClick={onResetScan}
                  className="w-full flex items-center justify-center space-x-1.5 bg-slate-800/80 border border-slate-700 hover:bg-slate-700 text-slate-200 py-2.5 rounded text-xs font-bold uppercase tracking-wider transition-all cursor-pointer font-semibold"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Reset Scan Dashboard</span>
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1.5">Discovery Provider</label>
                  <select
                    value={selectedProvider}
                    onChange={(e) => setSelectedProvider(e.target.value)}
                    className="w-full bg-dark-bg border border-dark-border rounded p-2 text-sm text-slate-200 focus:outline-none focus:border-cyber-accent font-semibold"
                  >
                    {providers.map(p => (
                      <option key={p} value={p}>{p}</option>
                    ))}
                  </select>
                </div>

                <button
                  onClick={() => onLaunchScan(selectedProvider)}
                  className="w-full bg-gradient-to-r from-cyber-primary to-cyber-accent text-white py-2.5 rounded text-xs font-bold uppercase tracking-wider hover:opacity-90 active:scale-[0.98] transition-all flex items-center justify-center space-x-2 shadow-lg cursor-pointer"
                >
                  <Play className="w-4 h-4" />
                  <span>Launch Discovery Job</span>
                </button>

                {(assets.length > 0 || (activeJob && ["completed", "failed"].includes(activeJob.status))) && (
                  <button
                    onClick={onResetScan}
                    className="w-full flex items-center justify-center space-x-1.5 bg-slate-800/80 border border-slate-700 hover:bg-slate-700 text-slate-200 py-2.5 rounded text-xs font-bold uppercase tracking-wider transition-all cursor-pointer font-semibold"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reset Scan Dashboard</span>
                  </button>
                )}
              </div>
            )}

            <div className="relative w-full">
              <button
                onClick={() => setShowExportDropdown(!showExportDropdown)}
                className="w-full bg-dark-bg border border-dark-border hover:border-cyber-accent/50 text-slate-300 hover:text-white py-2.5 rounded text-xs font-bold uppercase tracking-wider transition-all flex items-center justify-center space-x-2 cursor-pointer font-semibold animate-pulse"
              >
                <FileText className="w-4 h-4" />
                <span>Export ▼</span>
              </button>
              {showExportDropdown && (
                <div className="absolute right-0 left-0 mt-1 bg-dark-card border border-dark-border rounded-lg shadow-xl z-50 overflow-hidden text-xs">
                  <button
                    onClick={() => {
                      setShowExportDropdown(false);
                      handleExportFullCSV();
                    }}
                    className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border font-semibold"
                  >
                    • Full CSV
                  </button>
                  <button
                    onClick={() => {
                      setShowExportDropdown(false);
                      handleExportSubdomainsOnlyCSV();
                    }}
                    className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border font-semibold"
                  >
                    • Subdomains Only CSV
                  </button>
                  <button
                    onClick={async () => {
                      setShowExportDropdown(false);
                      await handleExportHTML();
                    }}
                    disabled={generatingReport}
                    className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer font-semibold"
                  >
                    • Audit Report (HTML)
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Center/Right Columns: Charts */}
        <div className="lg:col-span-2 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Open Ports Chart */}
            <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
              <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2">
                Open Ports Frequency
              </h4>
              <div className="h-64">
                {derivedPortsDistribution.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500 uppercase tracking-widest font-mono">
                    No Port Data Discovered
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={derivedPortsDistribution}>
                      <XAxis dataKey="port" stroke="#6B7280" fontSize={11} tickLine={false} />
                      <YAxis stroke="#6B7280" fontSize={11} tickLine={false} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{ backgroundColor: "#111622", borderColor: "#1E2638", color: "#F3F4F6", borderRadius: "6px" }}
                        labelFormatter={(label) => `Port ${label}`}
                      />
                      <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]}>
                        {derivedPortsDistribution.map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* Discovery Source Distribution */}
            <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
              <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2">
                Discovery Provider Yield
              </h4>
              <div className="h-64 flex flex-col justify-between">
                <div className="h-48">
                  {derivedSourcesDistribution.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-xs text-slate-500 uppercase tracking-widest font-mono">
                      No Yield Data Available
                    </div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={derivedSourcesDistribution}
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={70}
                          paddingAngle={5}
                          dataKey="value"
                        >
                          {derivedSourcesDistribution.map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: "#111622", borderColor: "#1E2638", color: "#F3F4F6", borderRadius: "6px" }} />
                      </PieChart>
                    </ResponsiveContainer>
                  )}
                </div>
                {/* Legend */}
                <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs">
                  {derivedSourcesDistribution.map((entry, index) => (
                    <div key={entry.name} className="flex items-center space-x-1.5">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }}></span>
                      <span className="text-slate-400">{entry.name} ({entry.value})</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
