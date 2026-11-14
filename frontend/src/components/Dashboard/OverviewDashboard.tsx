import React, { useEffect, useState } from "react";
import { StatCard } from "./StatCard";
import { DnsxCard } from "./DnsxCard";
import { SubzyCard } from "./SubzyCard";
import { UroCard } from "./UroCard";
import { GfCard } from "./GfCard";
import type { GfCategoryStats } from "./GfCard";
import { Globe, Server, Radio, ShieldAlert, Play, Pause, Square, RotateCcw, RefreshCw, FileText, Link, AlertCircle, CheckCircle } from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from "recharts";
import { apiCall } from "../../services/api";

interface DashboardStats {
  total_assets: number;
  total_subdomains: number;
  live_hosts: number;
  open_ports_count: number;
  last_scan_time: string | null;
  last_scan_duration?: string;
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
  // Per-scan Nuclei findings (new dual-mode pipeline)
  nuclei_host_findings?: number;
  nuclei_endpoint_findings?: number;
}

interface Project {
  id: string;
  name: string;
  description?: string;
  seed_domains: string[];
  scope?: {
    in_scope?: string[];
    out_of_scope?: string[];
  };
  rate_limits?: {
    global_rps?: number;
    per_tool?: Record<string, number>;
    tool_overrides?: Record<string, number>;
  };
  custom_headers?: Record<string, string>;
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
      urls?: string[];
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
  risk?: any;
  hunt_priority?: number;
  hunt_reasons?: string[];
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
  stages?: Record<string, string>;
  providerStatus?: Record<string, string>;
  onSelectSeverity?: (severity: string) => void;
  pipelineHalted?: { reason: string; message: string } | null;
  providerSkippedReasons?: Record<string, string>;
  onOpenSettings?: () => void;
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
  currentPhase = "",
  onPauseScan,
  onResumeScan,
  onStopScan,
  onResetScan,
  stages = {},
  providerStatus = {},
  onSelectSeverity,
  pipelineHalted = null,
  providerSkippedReasons = {},
  onOpenSettings,
}) => {
  const [selectedProvider, setSelectedProvider] = useState("Unified Discovery");
  const [providers, setProviders] = useState<string[]>(FALLBACK_PROVIDERS);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [activeDuration, setActiveDuration] = useState<string | null>(null);

  useEffect(() => {
    if (!activeJob || !["running", "pending", "paused"].includes(activeJob.status) || !activeJob.started_at) {
      setActiveDuration(null);
      return;
    }
    const update = () => {
      const start = new Date(activeJob.started_at).getTime();
      const diffMs = Date.now() - start;
      if (diffMs < 0) {
        setActiveDuration("0s");
        return;
      }
      const diffSecs = Math.floor(diffMs / 1000);
      const m = Math.floor(diffSecs / 60);
      const s = diffSecs % 60;
      setActiveDuration(m > 0 ? `${m}m ${s}s` : `${s}s`);
    };
    update();
    const timer = setInterval(update, 1000);
    return () => clearInterval(timer);
  }, [activeJob]);

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



  const getProviderStatus = (tool: string): "waiting" | "running" | "completed" | "failed" | "paused" | "stopped" | "skipped" => {
    const jobStatus = activeJob?.status;
    const t = tool.toLowerCase();

    // 0. Explicit skipped checks
    if (providerStatus[t] === "SKIPPED") return "skipped";

    // 1. Job completed/failed cases
    if (jobStatus === "completed" || currentPhase === "completed") return "completed";
    if (jobStatus === "failed") {
      if (providerStatus[t] === "COMPLETED") return "completed";
      if (providerStatus[t] === "SKIPPED") return "skipped";
      return "failed";
    }

    // 2. Explicit provider status checks
    if (providerStatus[t] === "COMPLETED") return "completed";
    if (providerStatus[t] === "FAILED") return "failed";

    if (jobStatus === "stopped") return "stopped";

    if (providerStatus[t] === "RUNNING") {
      return jobStatus === "paused" ? "paused" : "running";
    }

    // 3. Fallback based on current phase
    const PROVIDER_ORDER = [
      "subfinder", "assetfinder", "chaos", "amass",
      "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf",
      "nuclei_host", "nuclei_endpoint", "nuclei"
    ];
    
    const currentPhaseLower = currentPhase?.toLowerCase();
    
    if (currentPhaseLower === "discovery") {
      if (["subfinder", "assetfinder", "chaos", "amass"].includes(t)) {
        return jobStatus === "paused" ? "paused" : "running";
      }
    } else if (currentPhaseLower === t) {
      return jobStatus === "paused" ? "paused" : "running";
    }

    // If a phase after t is running or completed, then t must have completed
    const currentIdx = PROVIDER_ORDER.indexOf(currentPhaseLower);
    const toolIdx = PROVIDER_ORDER.indexOf(t);
    if (currentIdx !== -1 && toolIdx !== -1 && toolIdx < currentIdx) {
      if (currentPhaseLower !== "discovery") {
        return "completed";
      }
    }

    return "waiting";
  };

  const getElementStatus = (phase: string): "waiting" | "running" | "completed" | "failed" | "paused" | "stopped" | "skipped" => {
    if (phase === "discovery") {
      const status = stages.discovery || "PENDING";
      if (status === "SKIPPED") return "skipped";
      if (status === "COMPLETED") return "completed";
      if (status === "FAILED") return "failed";
      if (status === "RUNNING") {
        if (activeJob?.status === "paused") return "paused";
        if (activeJob?.status === "stopped") return "stopped";
        return "running";
      }
      return "waiting";
    }

    if (phase === "completed") {
      if (activeJob?.status === "completed") return "completed";
      if (activeJob?.status === "failed") return "failed";
      if (activeJob?.status === "stopped") return "stopped";
      return "waiting";
    }

    const explicitStatus = providerStatus[phase] || "PENDING";
    if (explicitStatus === "SKIPPED") return "skipped";

    return getProviderStatus(phase);
  };

  const renderPipelineItem = (phase: string, label: string) => {
    const status = getElementStatus(phase);
    
    let badgeClass = "px-2 py-0.5 rounded text-[10px] font-mono flex items-center space-x-1.5 transition-all ";
    let icon = null;
    
    if (status === "completed") {
      badgeClass += "bg-cyber-success/10 border border-cyber-success/30 text-cyber-success";
      icon = <span className="text-[10px] font-bold">✓</span>;
    } else if (status === "skipped") {
      badgeClass += "bg-slate-500/10 border border-slate-500/30 text-slate-500 line-through opacity-60";
      icon = <span className="text-[10px] opacity-40">»</span>;
    } else if (status === "running") {
      badgeClass += "bg-cyber-accent/20 border border-cyber-accent/50 text-cyber-accent animate-pulse font-bold";
      icon = <RefreshCw className="w-2.5 h-2.5 animate-spin" />;
    } else if (status === "paused") {
      badgeClass += "bg-cyber-warning/20 border border-cyber-warning/50 text-cyber-warning font-bold";
      icon = <Pause className="w-2.5 h-2.5" />;
    } else if (status === "stopped") {
      badgeClass += "bg-cyber-danger/20 border border-cyber-danger/50 text-cyber-danger font-bold";
      icon = <Square className="w-2.5 h-2.5 fill-current" />;
    } else if (status === "failed") {
      badgeClass += "bg-cyber-danger/20 border border-cyber-danger/50 text-cyber-danger font-bold";
      icon = <span className="text-[10px] font-bold">✗</span>;
    } else {
      badgeClass += "text-slate-500 border border-transparent";
      icon = <span className="text-[10px] opacity-40">○</span>;
    }

    return (
      <span className={badgeClass}>
        {icon}
        <span>{label}</span>
      </span>
    );
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
      // Flat URL list stored by Katana provider
      (asset.metadata?.katana?.urls?.length || 0) +
      // Structured sub-keys stored by some katana versions
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

  // Risk score calculations
  const hosts = assets.filter(a => a.type && ["subdomain", "domain", "ip", "service"].includes(a.type.toLowerCase()));
  const criticalRiskCount = hosts.filter(h => h.risk && h.risk.score >= 90).length;
  const highRiskCount = hosts.filter(h => h.risk && h.risk.score >= 70 && h.risk.score < 90).length;
  const mediumRiskCount = hosts.filter(h => h.risk && h.risk.score >= 40 && h.risk.score < 70).length;
  const lowRiskCount = hosts.filter(h => h.risk && h.risk.score >= 1 && h.risk.score < 40).length;
  const infoRiskCount = hosts.filter(h => h.risk && h.risk.score === 0).length;
  const notScoredCount = hosts.filter(h => !h.risk).length;

  const hostsWithRisk = hosts.map(h => {
    const risk = h.risk;
    const score = risk?.score ?? 0;
    const importance = risk?.importance_score ?? 0;
    const exposure = risk?.exposure_score ?? 0;
    const priorityScore = score + importance + exposure;
    return { ...h, priorityScore };
  });
  hostsWithRisk.sort((a, b) => b.priorityScore - a.priorityScore);
  const topRiskAssets = hostsWithRisk.filter(h => h.risk).slice(0, 5);
  const topHuntTargets = assets
    .filter((a) => (a as any).hunt_priority !== undefined || a.status === "live")
    .sort((a, b) => (((b as any).hunt_priority ?? 0) - ((a as any).hunt_priority ?? 0)))
    .slice(0, 5);


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
    { label: "Chaos", tool: "chaos", color: "#F59E0B" },
    { label: "Amass", tool: "amass", color: "#10B981" },
    { label: "DNSx", tool: "dnsx", color: "#22D3EE" },
    { label: "Subzy", tool: "subzy", color: "#EC4899" },
    { label: "Naabu", tool: "naabu", color: "#F43F5E" },
    { label: "HTTPX", tool: "httpx", color: "#8B5CF6" },
    { label: "Katana", tool: "katana", color: "#06B6D4" },
    { label: "Uro",             tool: "uro",             color: "#10B981" },
    { label: "GF",              tool: "gf",              color: "#F59E0B" },
    { label: "Nuclei Host",     tool: "nuclei_host",     color: "#EF4444" },
    { label: "Nuclei Endpoint", tool: "nuclei_endpoint", color: "#F97316" },
  ].map(p => {
    const pStatus = getProviderStatus(p.tool);
    
    let rawCount = 0;
    if (p.tool === "subfinder" || p.tool === "assetfinder" || p.tool === "chaos" || p.tool === "amass") {
      rawCount = pc[p.tool as keyof typeof pc] ?? 0;
    } else if (p.tool === "dnsx") {
      rawCount = stats.dnsx_resolved ?? 0;
    } else if (p.tool === "subzy") {
      rawCount = (stats.subzy_vulnerable ?? 0) + (stats.subzy_not_vulnerable ?? 0) + (stats.subzy_unknown ?? 0);
    } else if (p.tool === "naabu") {
      rawCount = totalOpenPortFindings;
    } else if (p.tool === "httpx") {
      rawCount = derivedLiveHosts;
    } else if (p.tool === "katana") {
      rawCount = totalUrlsDiscovered;
    } else if (p.tool === "uro") {
      rawCount = stats.uro_normalised ?? 0;
    } else if (p.tool === "gf") {
      rawCount = stats.gf_total ?? 0;
    } else if (p.tool === "nuclei_host") {
      // Sum findings from assets where scan mode was host-level
      rawCount = assets.reduce(
        (t, a) => t + (a.metadata?.nuclei?.findings?.filter(
          (f: any) => f.pass_name === "HostExposure" || f.source === "nuclei_host"
        ).length || 0),
        0
      ) || (stats.nuclei_host_findings ?? 0);
    } else if (p.tool === "nuclei_endpoint") {
      rawCount = assets.reduce(
        (t, a) => t + (a.metadata?.nuclei?.findings?.filter(
          (f: any) => f.pass_name === "EndpointBugClass" || f.pass_name === "EndpointCritical" || f.source === "nuclei_endpoint"
        ).length || 0),
        0
      ) || (stats.nuclei_endpoint_findings ?? 0);
    } else if (p.tool === "nuclei") {
      rawCount = totalNucleiFindings;
    }

    const isSkippedUpstream = providerSkippedReasons[p.tool] === "no_live_hosts_upstream";
    const countDisplay = isSkippedUpstream
      ? "Skipped — no live hosts"
      : (activeJob && pStatus === "waiting") ? "-" : rawCount;

    return {
      ...p,
      status: isSkippedUpstream ? "skipped" : pStatus,
      countDisplay,
      count: rawCount,
      isSkippedUpstream,
    };
  });

  return (
    <div className="space-y-6">
      {/* Scope Warning Banner if unconfigured */}
      {(!activeProject.scope?.in_scope?.length && !activeProject.scope?.out_of_scope?.length) && (
        <div className="bg-cyber-warning/10 border border-cyber-warning/30 rounded-xl p-3.5 flex items-center justify-between text-cyber-warning glass animate-fadeIn">
          <div className="flex items-center space-x-2.5 text-xs font-mono">
            <span className="text-base">⚠</span>
            <span>
              <strong>Scope Notice:</strong> Scope rules are not configured for this project. Discovered subdomains and resolved IPs will be scanned without boundary checking.
            </span>
          </div>
          {onOpenSettings && (
            <button
              onClick={onOpenSettings}
              className="px-3 py-1 bg-cyber-warning/20 border border-cyber-warning/40 hover:bg-cyber-warning/30 text-cyber-warning text-[11px] font-bold font-mono rounded cursor-pointer transition-colors shrink-0 ml-3"
            >
              Configure Scope
            </button>
          )}
        </div>
      )}

      {/* Pipeline Halted Banner */}
      {pipelineHalted && pipelineHalted.reason === "no_live_hosts" && (
        <div className="bg-cyber-danger/10 border border-cyber-danger/30 rounded-xl p-4 flex items-center space-x-3 text-cyber-danger glass animate-pulse">
          <span className="text-xl">⚠</span>
          <div className="text-xs font-mono font-bold leading-relaxed">
            No live hosts found — scan stopped early. Nothing to crawl or scan. Check Naabu/HTTPX raw output in the logs panel if this seems unexpected.
          </div>
        </div>
      )}

      {/* Phase Tracker for Active Scan */}
      <div className="bg-dark-card border border-dark-border rounded-xl p-4 glass animate-fadeIn">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            {activeJob ? (
              activeJob.status === "completed" ? (
                <CheckCircle className="w-4 h-4 text-cyber-success" />
              ) : activeJob.status === "paused" ? (
                <Pause className="w-4 h-4 text-cyber-warning animate-pulse" />
              ) : activeJob.status === "stopped" ? (
                <Square className="w-4 h-4 text-cyber-danger fill-current" />
              ) : (
                <RefreshCw className="w-4 h-4 text-cyber-accent animate-spin" />
              )
            ) : (
              <RefreshCw className="w-4 h-4 text-slate-500" />
            )}
            <span className="font-mono text-xs text-slate-200 uppercase tracking-wider font-semibold">
              Active Scan Progress:{" "}
              <span className={
                activeJob ? (
                  activeJob.status === "paused" ? "text-cyber-warning" :
                  activeJob.status === "stopped" ? "text-cyber-danger" :
                  "text-cyber-accent"
                ) : "text-slate-500"
              }>
                {activeJob ? activeJob.status.toUpperCase() : "IDLE"}
              </span>
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
            {([
              ["discovery",   "Passive Discovery"],
              ["subfinder",   "Subfinder"],
              ["assetfinder", "Assetfinder"],
              ["chaos",       "Chaos"],
              ["amass",       "Amass"],
              ["dnsx",        "DNSx"],
              ["subzy",       "Subzy"],
              ["naabu",       "Naabu"],
              ["httpx",       "HTTPX"],
              ["katana",      "Katana"],
              ["uro",            "Uro"],
              ["gf",             "GF"],
              ["nuclei_host",    "Nuclei Host"],
              ["nuclei_endpoint","Nuclei Endpoint"],
              ["completed",       "Completed"],
            ] as [string, string][]).map(([phase, label], i, arr) => (
              <React.Fragment key={phase}>
                {renderPipelineItem(phase, label)}
                {i < arr.length - 1 && <span className="text-slate-700">{"\u2192"}</span>}
              </React.Fragment>
            ))}
          </div>
        </div>
      </div>

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
          subtext="Unique endpoints & resources stored"
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
      <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
        <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2">
          Provider Yield Breakdown
        </h4>
        <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-3">
          {providerBreakdown.map((p) => (
            <div key={p.label} className="bg-dark-bg border border-dark-border rounded-lg p-3 flex flex-col items-center text-center relative overflow-hidden">
              <div className="flex items-center gap-1.5 mb-1.5 justify-center">
                {(p.status === "completed" && !p.isSkippedUpstream) && <span className="text-cyber-success text-xs font-bold">✓</span>}
                {p.status === "running" && <RefreshCw className="w-3 h-3 animate-spin text-cyber-accent" />}
                {p.status === "waiting" && <span className="text-slate-500 text-xs">○</span>}
                {p.status === "failed" && <span className="text-cyber-danger text-xs font-bold">✕</span>}
                {p.status === "paused" && <Pause className="w-3 h-3 text-cyber-warning animate-pulse" />}
                {p.status === "stopped" && <Square className="w-3 h-3 text-cyber-danger fill-current" />}
                {p.status === "skipped" && <span className="text-slate-500 text-xs font-bold">»</span>}
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">{p.label}</span>
              </div>
              <span className={`font-mono font-bold text-center ${p.isSkippedUpstream ? "text-[10px] text-slate-500 py-1" : "text-2xl"}`} style={{ color: p.isSkippedUpstream ? undefined : p.color }}>
                {p.countDisplay}
              </span>
              <span className="text-[9px] text-slate-500 mt-1 capitalize">{p.status}</span>
              
              {/* Progress bar for sub-providers (Subfinder, Assetfinder, Chaos, Amass) */}
              {["subfinder", "assetfinder", "chaos", "amass"].includes(p.tool) && (
                <div className="w-full mt-3 h-1 bg-dark-card border border-dark-border/40 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      p.status === "completed" ? "bg-cyber-success w-full" :
                      p.status === "failed" ? "bg-cyber-danger w-full" :
                      p.status === "running" ? "bg-cyber-accent w-2/3 animate-pulse" :
                      p.status === "paused" ? "bg-cyber-warning w-1/2 animate-pulse" :
                      p.status === "stopped" ? "bg-cyber-danger w-1/3" :
                      "bg-slate-700 w-0"
                    }`}
                  />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

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
      {/* Risk Scoring Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        {/* Risk Overview Card */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2 flex items-center justify-between">
              <span>Risk Overview</span>
              <span className="text-[10px] font-mono text-slate-500 uppercase">ASM Scoring</span>
            </h4>
            <div className="grid grid-cols-3 gap-3">
              <div className="bg-dark-bg border border-red-500/20 rounded-lg p-3.5 flex flex-col items-center text-center">
                <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider mb-1">Critical Risk</span>
                <span className="text-2xl font-mono font-bold text-red-500">{criticalRiskCount}</span>
              </div>
              <div className="bg-dark-bg border border-orange-500/20 rounded-lg p-3.5 flex flex-col items-center text-center">
                <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider mb-1">High Risk</span>
                <span className="text-2xl font-mono font-bold text-orange-500">{highRiskCount}</span>
              </div>
              <div className="bg-dark-bg border border-yellow-500/20 rounded-lg p-3.5 flex flex-col items-center text-center">
                <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider mb-1">Medium Risk</span>
                <span className="text-2xl font-mono font-bold text-yellow-500">{mediumRiskCount}</span>
              </div>
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-dark-border/40 text-[10px] font-mono text-slate-500 flex justify-between">
            <span>Low Risk: {lowRiskCount}</span>
            <span>Info: {infoRiskCount}</span>
            <span>Unscored Hosts: {notScoredCount}</span>
          </div>
        </div>

        {/* Top Risk Assets */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
          <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2 flex items-center justify-between">
            <span>Top Priority Critical Assets</span>
            <span className="text-[10px] font-mono text-slate-500 uppercase">Weighted Ranking</span>
          </h4>
          <div className="space-y-2">
            {topRiskAssets.length === 0 ? (
              <div className="text-center py-6 text-xs text-slate-500 font-mono">
                No scored assets found. Scans may be running or pending scoring.
              </div>
            ) : (
              topRiskAssets.map((asset) => {
                const score = asset.risk?.score ?? 0;
                let badgeColor = "bg-slate-500/10 text-slate-400 border-slate-500/20";
                if (score >= 90) badgeColor = "bg-red-500/10 text-red-500 border-red-500/20";
                else if (score >= 70) badgeColor = "bg-orange-500/10 text-orange-500 border-orange-500/20";
                else if (score >= 40) badgeColor = "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
                else if (score >= 1) badgeColor = "bg-blue-500/10 text-blue-400 border-blue-500/20";
                
                const mainReason = asset.risk?.reasons?.[0] || "No critical findings detected";
                
                return (
                  <div key={asset.id} className="flex items-center justify-between p-2.5 bg-dark-bg border border-dark-border rounded-lg hover:bg-dark-hover/10 transition-all">
                    <div className="flex flex-col min-w-0 pr-2">
                      <span className="text-xs font-mono text-slate-300 truncate font-semibold">{asset.domain}</span>
                      <span className="text-[10px] text-slate-500 font-mono truncate">{mainReason}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {asset.risk?.exposure_factors?.includes("Internet Exposed") && (
                        <span className="text-[9px] font-mono uppercase bg-cyber-primary/10 text-cyber-primary px-1.5 py-0.5 rounded border border-cyber-primary/20">
                          Exposed
                        </span>
                      )}
                      <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${badgeColor}`}>
                        {score}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      
        {/* Top Hunt Targets Card */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
          <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-cyber-accent">
              <span>🎯 Top Hunt Targets</span>
            </span>
            <span className="text-[10px] font-mono text-slate-500 uppercase">Bug Bounty Priority</span>
          </h4>
          <div className="space-y-2">
            {topHuntTargets.length === 0 ? (
              <div className="text-center py-6 text-xs text-slate-500 font-mono">
                No live host targets identified yet.
              </div>
            ) : (
              topHuntTargets.map((asset) => {
                const hp = (asset as any).hunt_priority ?? 0;
                let badgeColor = "bg-slate-500/10 text-slate-400 border-slate-500/20";
                if (hp >= 80) badgeColor = "bg-cyan-500/15 text-cyan-300 border-cyan-500/40 font-bold";
                else if (hp >= 50) badgeColor = "bg-amber-500/15 text-amber-300 border-amber-500/40 font-bold";
                else if (hp >= 20) badgeColor = "bg-blue-500/15 text-blue-300 border-blue-500/40";

                const mainReason = (asset as any).hunt_reasons?.[0] || "Live attack surface";

                return (
                  <div key={asset.id} className="flex items-center justify-between p-2.5 bg-dark-bg border border-dark-border rounded-lg hover:bg-dark-hover/10 transition-all">
                    <div className="flex flex-col min-w-0 pr-2">
                      <span className="text-xs font-mono text-slate-200 truncate font-semibold">{asset.domain}</span>
                      <span className="text-[10px] text-slate-500 font-mono truncate">{mainReason}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-mono px-2 py-0.5 rounded border ${badgeColor}`}>
                        🎯 {hp}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
</div>

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
            <div
              key={item.label}
              onClick={() => onSelectSeverity && onSelectSeverity(item.label)}
              className={`bg-dark-bg border ${item.border} rounded-lg p-3.5 flex flex-col items-center text-center transition-all hover:scale-[1.02] hover:bg-dark-hover/10 cursor-pointer`}
            >
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
                  {totalNucleiFindings > 0 && (
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-500">Security Findings</span>
                      <span className="text-cyber-danger font-bold">{totalNucleiFindings}</span>
                    </div>
                  )}
                  {stats.dnsx_resolved === undefined && stats.uro_normalised === undefined && (
                    <span className="text-slate-600 text-[10px] font-mono uppercase tracking-wider">Run a full scan to see pipeline stats</span>
                  )}
                </div>
              </div>

              <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block mb-1">SCAN TIME / DURATION</span>
                <div className="text-slate-300 text-xs font-mono flex flex-col space-y-1">
                  {activeDuration ? (
                    <span className="text-cyber-accent font-bold animate-pulse">Running: {activeDuration}</span>
                  ) : stats.last_scan_duration ? (
                    <span className="text-cyber-success font-semibold">Finished in {stats.last_scan_duration}</span>
                  ) : null}
                  {stats.last_scan_time && (
                    <span className="text-slate-400 text-[10px]">
                      Completed: {new Date(stats.last_scan_time).toLocaleString()}
                    </span>
                  )}
                  {!activeDuration && !stats.last_scan_time && <span>Never Scanned</span>}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8 pt-4 border-t border-dark-border space-y-5">
            {/* Launch Section */}
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1.5">Discovery Provider</label>
                <select
                  value={selectedProvider}
                  onChange={(e) => setSelectedProvider(e.target.value)}
                  disabled={!!activeJob && ["running", "pending", "paused"].includes(activeJob.status)}
                  className="w-full bg-dark-bg border border-dark-border rounded p-2 text-sm text-slate-200 focus:outline-none focus:border-cyber-accent font-semibold disabled:opacity-50"
                >
                  {providers.map(p => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>

              <button
                onClick={() => onLaunchScan(selectedProvider)}
                disabled={!!activeJob && ["running", "pending", "paused"].includes(activeJob.status)}
                className="w-full bg-gradient-to-r from-cyber-primary to-cyber-accent text-white py-2.5 rounded text-xs font-bold uppercase tracking-wider hover:opacity-90 active:scale-[0.98] transition-all flex items-center justify-center space-x-2 shadow-lg cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Play className="w-4 h-4" />
                <span>Launch Discovery Job</span>
              </button>
            </div>

            {/* Scan Control Console */}
            <div className="space-y-3 pt-4 border-t border-dark-border/40">
              <span className="block text-xs font-mono text-slate-400 uppercase tracking-widest mb-1">Scan Control Console</span>
              <div className="grid grid-cols-2 gap-2">
                {activeJob?.status === "paused" ? (
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
                    disabled={!activeJob || (activeJob.status !== "running" && activeJob.status !== "pending")}
                    className="flex items-center justify-center space-x-1.5 bg-cyber-warning/20 border border-cyber-warning/40 hover:bg-cyber-warning/30 text-cyber-warning py-2 rounded text-xs font-bold uppercase tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                  >
                    <Pause className="w-3.5 h-3.5" />
                    <span>Pause</span>
                  </button>
                )}

                <button
                  onClick={onStopScan}
                  disabled={!activeJob || (activeJob.status !== "running" && activeJob.status !== "pending" && activeJob.status !== "paused")}
                  className="flex items-center justify-center space-x-1.5 bg-cyber-danger/20 border border-cyber-danger/40 hover:bg-cyber-danger/30 text-cyber-danger py-2 rounded text-xs font-bold uppercase tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                >
                  <Square className="w-3.5 h-3.5 fill-current" />
                  <span>Stop</span>
                </button>
              </div>
              
              <button
                onClick={onResetScan}
                disabled={assets.length === 0 && (!activeJob || !["completed", "failed", "stopped"].includes(activeJob.status))}
                className="w-full flex items-center justify-center space-x-1.5 bg-slate-800/80 border border-slate-700 hover:bg-slate-700 text-slate-200 py-2.5 rounded text-xs font-bold uppercase tracking-wider transition-all cursor-pointer font-semibold disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset Scan Dashboard</span>
              </button>
            </div>

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
