import React, { useState, useEffect, useRef } from "react";
import { Navbar } from "./components/Common/Navbar";
import { OverviewDashboard } from "./components/Dashboard/OverviewDashboard";
import { AssetTable } from "./components/Inventory/AssetTable";
import type { DnsRecord } from "./components/Inventory/DnsTab";
import type { TakeoverRecord } from "./components/Inventory/TakeoverTab";
import type { NormalizedUrlRecord } from "./components/Inventory/NormalizedUrlTab";
import type { GfUrlRecord } from "./components/Inventory/GfTab";
import type { ContentPathRecord } from "./components/Inventory/ContentDiscoveryTab";
import { DiffTab } from "./components/Inventory/DiffTab";
import type { ScanDiffDoc } from "./components/Inventory/DiffTab";
import { ConsoleView } from "./components/JobConsole/ConsoleView";
import { SubdomainsTab } from "./components/Subdomains/SubdomainsTab";
import { RunHistoryTab } from "./components/RunHistory/RunHistoryTab";
import { apiCall, getWebSocketUrl } from "./services/api";
import { LayoutDashboard, Database, RefreshCw, Sparkles, Globe2, Sliders, AlertTriangle, History as HistoryIcon } from "lucide-react";
import { ProjectSettingsModal } from "./components/ProjectSettings/ProjectSettingsModal";

interface Project {
  id: string;
  name: string;
  description?: string;
  seed_domains: string[];
  target_type?: string;
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
  schedule?: {
    enabled?: boolean;
    interval_hours?: number;
    scan_mode?: string;
    last_run?: string | null;
    next_run?: string | null;
  };
  alerts?: {
    enabled?: boolean;
    discord_webhook_url?: string;
    telegram_bot_token?: string;
    telegram_chat_id?: string;
    min_priority?: string;
    events?: Record<string, boolean>;
  };
}

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
    [key: string]: number | undefined;
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
  gf_categories?: Record<string, number>;
  gf_total?: number;
  normalized_urls_count?: number;
  gf_urls_count?: number;
  // Dual-mode Nuclei pipeline findings
  nuclei_host_findings?: number;
  nuclei_endpoint_findings?: number;
}



let wsCount = 0;

type TabId = "dashboard" | "diffs" | "runs" | "subdomains" | "inventory";

interface ScanState {
  jobId: string | null;
  scanStatus: string | null;
  currentStage: string;
  stages: Record<string, string>;
  providerCounts: Record<string, number>;
  dnsx_resolved: number | null;
  dnsx_nxdomain: number | null;
  dnsx_wildcards: number | null;
  dnsx_unique_ips: number | null;
  subzy_vulnerable: number | null;
  subzy_not_vulnerable: number | null;
  subzy_unknown: number | null;
  uro_input: number | null;
  uro_normalised: number | null;
  uro_removed: number | null;
  gf_total: number | null;
  gf_categories: Record<string, number>;
  assets: any[];
  subdomains: any[];
  dnsRecords: DnsRecord[];
  takeoverRecords: TakeoverRecord[];
  normalizedUrlRecords: NormalizedUrlRecord[];
  gfRecords: GfUrlRecord[];
  contentPathRecords: ContentPathRecord[];
  riskScores: any[];
  pipelineHalted: { reason: string; message: string } | null;
  providerSkippedReasons: Record<string, string>;
  completedProviders: Set<string>;
  activeJobObject: any | null;
  lastCompletedJobObject: any | null;
  providerStatus: Record<string, string>;
  lastWsEventTime: number;
}

const initialScanState: ScanState = {
  jobId: null,
  scanStatus: null,
  currentStage: "waiting",
  lastCompletedJobObject: null,
  stages: {
    discovery: "PENDING",
    dnsx: "PENDING",
    subzy: "PENDING",
    naabu: "PENDING",
    httpx: "PENDING",
    katana: "PENDING",
    uro: "PENDING",
    gf: "PENDING",
    nuclei_host: "PENDING",
    nuclei_endpoint: "PENDING",
    // Legacy key kept for backward-compat with any existing WS events.
    nuclei: "PENDING",
  },
  providerCounts: {},
  dnsx_resolved: null,
  dnsx_nxdomain: null,
  dnsx_wildcards: null,
  dnsx_unique_ips: null,
  subzy_vulnerable: null,
  subzy_not_vulnerable: null,
  subzy_unknown: null,
  uro_input: null,
  uro_normalised: null,
  uro_removed: null,
  gf_total: null,
  gf_categories: {},
  assets: [],
  subdomains: [],
  dnsRecords: [],
  takeoverRecords: [],
  normalizedUrlRecords: [],
  gfRecords: [],
  contentPathRecords: [],
  riskScores: [],
  pipelineHalted: null,
  providerSkippedReasons: {},
  completedProviders: new Set<string>(),
  activeJobObject: null,
  providerStatus: {
    subfinder: "PENDING",
    assetfinder: "PENDING",
    amass: "PENDING",
    chaos: "PENDING",
    dnsx: "PENDING",
    subzy: "PENDING",
    naabu: "PENDING",
    httpx: "PENDING",
    katana: "PENDING",
    uro: "PENDING",
    gf: "PENDING",
    nuclei_host: "PENDING",
    nuclei_endpoint: "PENDING",
    nuclei: "PENDING",
    gau: "PENDING",
    subjs: "PENDING",
    linkfinder: "PENDING",
    gowitness: "PENDING",
    dalfox: "PENDING",
    openredirex: "PENDING",
  },
  lastWsEventTime: 0,
};

const transitionToStage = (
  currentStages: Record<string, string>,
  newStage: string
): {
  currentStage: string;
  stages: Record<string, string>;
} => {
  const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei_host", "nuclei_endpoint", "nuclei"];
  const targetIdx = PIPELINE_ORDER.indexOf(newStage.toLowerCase());
  
  if (targetIdx === -1) {
    if (newStage.toLowerCase() === "completed") {
      const nextStages = { ...currentStages };
      PIPELINE_ORDER.forEach((s) => {
        if (nextStages[s] !== "SKIPPED") {
          nextStages[s] = "COMPLETED";
        }
      });
      return { currentStage: "completed", stages: nextStages };
    }
    return { currentStage: newStage, stages: currentStages };
  }

  const nextStages = { ...currentStages };
  PIPELINE_ORDER.forEach((stage, idx) => {
    if (idx < targetIdx) {
      if (nextStages[stage] !== "SKIPPED") {
        nextStages[stage] = "COMPLETED";
      }
    } else if (idx === targetIdx) {
      if (nextStages[stage] !== "SKIPPED") {
        nextStages[stage] = "RUNNING";
      }
    } else {
      if (nextStages[stage] !== "SKIPPED") {
        nextStages[stage] = "PENDING";
      }
    }
  });

  return { currentStage: newStage.toLowerCase(), stages: nextStages };
};

const updateProviderStatus = (
  current: Record<string, string>,
  provider: string,
  newStatus: string
): Record<string, string> => {
  const p = provider.toLowerCase();
  const currentStatus = current[p];
  if (currentStatus === "COMPLETED" || currentStatus === "SKIPPED") {
    return current;
  }
  const next = { ...current };
  next[p] = newStatus;
  return next;
};

const mergeFindingIntoAssets = (currentAssets: any[], finding: any) => {
  if (!finding || !finding.matched_url) return currentAssets;
  
  let host = (finding.host || "").toLowerCase().trim();
  if (!host) {
    try {
      const parsed = new URL(finding.matched_url);
      host = (parsed.hostname || parsed.pathname).toLowerCase();
      if (host.includes(":")) {
        host = host.split(":")[0];
      }
    } catch (e) {
      host = "";
    }
  }
  if (!host) return currentAssets;

  const exists = currentAssets.some((a) => a.domain.toLowerCase() === host || host.endsWith("." + a.domain.toLowerCase()) || a.domain.toLowerCase().endsWith("." + host));
  
  if (exists) {
    return currentAssets.map((a) => {
      const match = a.domain.toLowerCase() === host || host.endsWith("." + a.domain.toLowerCase()) || a.domain.toLowerCase().endsWith("." + host);
      if (!match) return a;
      
      const metadata = a.metadata || {};
      const nuclei = metadata.nuclei || {};
      const findings = nuclei.findings || [];
      
      const alreadyHas = findings.some((f: any) => 
        (f.template_id === finding.template_id || f.template_name === finding.template_name) && 
        f.matched_url === finding.matched_url
      );
      
      if (alreadyHas) return a;
      
      return {
        ...a,
        metadata: {
          ...metadata,
          nuclei: {
            ...nuclei,
            findings: [...findings, finding],
            scanned_at: Math.floor(Date.now() / 1000)
          }
        }
      };
    });
  } else {
    return [
      ...currentAssets,
      {
        id: `nuclei-${Date.now()}-${Math.random()}`,
        domain: host,
        type: "subdomain",
        status: "live",
        open_ports: [],
        discovered_by: "nuclei",
        created_at: new Date().toISOString(),
        sources: ["nuclei"],
        metadata: {
          source: "nuclei",
          nuclei: {
            findings: [finding],
            scanned_at: Math.floor(Date.now() / 1000)
          }
        }
      }
    ];
  }
};

const MainDashboard: React.FC = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
  const [initialInventoryTab, setInitialInventoryTab] = useState<"assets" | "dns" | "takeovers" | "normalized_urls" | "gf" | "nuclei" | "historical_urls" | "js_files" | "screenshots">("assets");
  const [initialSeverityFilter, setInitialSeverityFilter] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [isReconnect, setIsReconnect] = useState(false);
  const [scanMode, setScanMode] = useState<"fast" | "deep">("fast");
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [latestDiff, setLatestDiff] = useState<ScanDiffDoc | null>(null);

  const handleProjectUpdated = (updatedProj: Project) => {
    setActiveProject(updatedProj);
    setProjects((prev) => prev.map((p) => (p.id === updatedProj.id ? updatedProj : p)));
  };

  const [scanState, setScanState] = useState<ScanState>(initialScanState);

  const [isInMemoryDb, setIsInMemoryDb] = useState(false);

  useEffect(() => {
    const checkDbStatus = async () => {
      try {
        const res = await apiCall("/system/status");
        if (res && res.in_memory_db) {
          setIsInMemoryDb(true);
        }
      } catch (e) {
        // Non-fatal if system/status fails
      }
    };
    checkDbStatus();
  }, []);

  const activeProjectRef = useRef<Project | null>(null);
  const jobIdRef = useRef<string | null>(null);

  // Keep refs synchronised every render so closure-captured values are fresh.
  activeProjectRef.current = activeProject;
  jobIdRef.current = scanState.jobId;

  useEffect(() => {
    activeProjectRef.current = activeProject;
  }, [activeProject]);

  useEffect(() => {
    jobIdRef.current = scanState.jobId;
  }, [scanState.jobId]);

  const {
    assets,
    subdomains,
    dnsRecords,
    takeoverRecords,
    normalizedUrlRecords,
    gfRecords,
    contentPathRecords,
    providerStatus,
    stages,
    currentStage: currentPhase,
  } = scanState;

  const activeJob = scanState.activeJobObject;

  const completedProviders = new Set(
    Object.entries(scanState.providerStatus)
      .filter(([_, status]) => status === "COMPLETED")
      .map(([provider]) => provider)
  );

  const portCounts: Record<number, number> = {};
  scanState.assets.forEach((a: any) => {
    (a.open_ports || []).forEach((p: number) => {
      portCounts[p] = (portCounts[p] || 0) + 1;
    });
  });
  const ports_distribution = Object.entries(portCounts).map(([port, count]) => ({
    port: parseInt(port),
    count: count as number
  })).sort((a, b) => b.count - a.count);

  const sourceGroups: Record<string, number> = {};
  scanState.assets.forEach((a: any) => {
    const src = a.discovered_by || "unknown";
    sourceGroups[src] = (sourceGroups[src] || 0) + 1;
  });
  const sources_distribution = Object.entries(sourceGroups).map(([name, value]) => ({
    name,
    value: value as number
  }));

  // Derive Uro statistics
  const derivedUroInput = React.useMemo(() => {
    const hasUroRun = (scanState.uro_normalised !== null && scanState.uro_normalised !== undefined) || scanState.normalizedUrlRecords.some(r => r.source === "uro");
    if (!hasUroRun) return undefined;
    if (scanState.uro_input !== null && scanState.uro_input !== undefined && scanState.uro_input > 0) {
      return scanState.uro_input;
    }
    // Fallback: total unique input URLs (from katana and httpx)
    const inputCount = scanState.normalizedUrlRecords.filter(r => r.source === "katana" || r.source === "httpx").length;
    if (inputCount > 0) return inputCount;
    return undefined;
  }, [scanState.normalizedUrlRecords, scanState.uro_input, scanState.uro_normalised]);

  const derivedUroNormalised = React.useMemo(() => {
    const hasUroRun = (scanState.uro_normalised !== null && scanState.uro_normalised !== undefined) || scanState.normalizedUrlRecords.some(r => r.source === "uro");
    if (!hasUroRun) return undefined;
    if (scanState.uro_normalised !== null && scanState.uro_normalised !== undefined) {
      return scanState.uro_normalised;
    }
    // Fallback: URLs in the list with source 'uro'
    const uroCount = scanState.normalizedUrlRecords.filter(r => r.source === "uro").length;
    if (uroCount > 0) return uroCount;
    if (scanState.uro_input !== null && scanState.uro_input !== undefined) {
      return 0;
    }
    return undefined;
  }, [scanState.normalizedUrlRecords, scanState.uro_normalised, scanState.uro_input]);

  const derivedUroRemoved = React.useMemo(() => {
    if (derivedUroInput === undefined || derivedUroNormalised === undefined) return undefined;
    return Math.max(0, derivedUroInput - derivedUroNormalised);
  }, [derivedUroInput, derivedUroNormalised]);

  // Derive GF statistics
  const derivedGfCategories = React.useMemo(() => {
    const cats: Record<string, number> = {};
    scanState.gfRecords.forEach((r) => {
      r.categories.forEach((cat) => {
        const lower = cat.toLowerCase();
        cats[lower] = (cats[lower] ?? 0) + 1;
      });
    });
    return cats;
  }, [scanState.gfRecords]);

  const derivedGfTotal = React.useMemo(() => {
    const hasGfRun = scanState.gfRecords.length > 0 || (scanState.gf_total !== null && scanState.gf_total !== undefined);
    if (!hasGfRun) return undefined;
    
    return Object.values(derivedGfCategories).reduce((a, b) => a + b, 0);
  }, [derivedGfCategories, scanState.gfRecords.length, scanState.gf_total]);

  const lastScanDuration = React.useMemo(() => {
    const job = scanState.lastCompletedJobObject;
    if (!job || !job.started_at || !job.finished_at) return null;
    const start = new Date(job.started_at).getTime();
    const end = new Date(job.finished_at).getTime();
    const diffMs = end - start;
    if (diffMs < 0) return "0s";
    const diffSecs = Math.floor(diffMs / 1000);
    const m = Math.floor(diffSecs / 60);
    const s = diffSecs % 60;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }, [scanState.lastCompletedJobObject]);

  const stats: DashboardStats = {
    total_assets: scanState.assets.length,
    total_subdomains: scanState.subdomains.length,
    live_hosts: scanState.assets.filter((a: any) => a.status === "live").length,
    open_ports_count: ports_distribution.length,
    last_scan_time: scanState.lastCompletedJobObject?.finished_at || null,
    last_scan_duration: lastScanDuration || undefined,
    ports_distribution,
    sources_distribution,
    // Merge nuclei count into provider_counts so Nuclei Yield card shows correctly.
    provider_counts: {
      ...scanState.providerCounts,
      nuclei: scanState.assets.reduce(
        (t: number, a: any) => t + (a.metadata?.nuclei?.findings?.length ?? 0), 0
      ),
    },
    
    dnsx_resolved: scanState.dnsx_resolved ?? undefined,
    dnsx_nxdomain: scanState.dnsx_nxdomain ?? undefined,
    dnsx_wildcards: scanState.dnsx_wildcards ?? undefined,
    dnsx_unique_ips: scanState.dnsx_unique_ips ?? undefined,
    
    subzy_vulnerable: scanState.subzy_vulnerable ?? undefined,
    subzy_not_vulnerable: scanState.subzy_not_vulnerable ?? undefined,
    subzy_unknown: scanState.subzy_unknown ?? undefined,
    
    uro_input: derivedUroInput,
    uro_normalised: derivedUroNormalised,
    uro_removed: derivedUroRemoved,
    
    gf_total: derivedGfTotal,
    gf_categories: derivedGfCategories,
    // Per-scan Nuclei totals — populated from providerCounts when WS summary events arrive.
    nuclei_host_findings: scanState.providerCounts.nuclei_host ?? undefined,
    nuclei_endpoint_findings: scanState.providerCounts.nuclei_endpoint ?? undefined,
  };

  const wsRef = useRef<WebSocket | null>(null);
  const fetchProjectDataRef = useRef<(() => Promise<void>) | null>(null);

  const fetchProjects = async () => {
    try {
      const projs = await apiCall("/projects");
      setProjects(projs);
      if (projs.length > 0 && !activeProject) {
        setActiveProject(projs[0]);
      }
    } catch (err) {
      console.error("Failed to load projects", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjectData = async () => {
    if (!activeProject) return;
    const projectId = activeProject.id;
    try {
      const [assetList, subdomainList, dashboardStats, jobsList, riskScores, contentPathsRes, dnsRes] = await Promise.all([
        apiCall(`/assets/project/${projectId}`),
        apiCall(`/assets/project/${projectId}/subdomains`),
        apiCall(`/assets/project/${projectId}/dashboard-stats`),
        apiCall(`/jobs/project/${projectId}`),
        apiCall(`/projects/${projectId}/risk-scores`).catch(() => []),
        apiCall(`/assets/project/${projectId}/content-paths?limit=500`).catch(() => ({ items: [] })),
        apiCall(`/assets/project/${projectId}/dns`).catch(() => []),
      ]);

      if (activeProjectRef.current?.id !== projectId) {
        console.log("Ignoring stale API fetch result for project", projectId);
        return;
      }

      const dns: DnsRecord[] = [];
      const takeovers: TakeoverRecord[] = [];
      const seenUrls = new Set<string>();

      // Parse logs first to get counts and status of providers
      let dnsx_nxdomain = 0;
      let dnsx_wildcards = 0;
      let subzy_not_vulnerable = 0;
      let subzy_unknown = 0;
      let uro_input = 0;
      let uro_normalised = 0;
      let uro_removed = 0;
      const completedFromLogs = new Set<string>();
      const skippedFromLogs = new Set<string>();
      let pipelineHaltedObj: { reason: string; message: string } | null = null;
      const skippedReasonsMap: Record<string, string> = {};

      [...jobsList].reverse().forEach((job: any) => {
        if (Array.isArray(job.logs)) {
          job.logs.forEach((log: string) => {
            const dnsxMatch = log.match(/DNSx completed\.\s+Resolved:\s*(\d+)\s*\|\s*NXDOMAIN:\s*(\d+)\s*\|\s*Wildcards filtered:\s*(\d+)/i);
            if (dnsxMatch) {
              dnsx_nxdomain = parseInt(dnsxMatch[2]);
              dnsx_wildcards = parseInt(dnsxMatch[3]);
            }
            
            const subzyMatch = log.match(/Subzy completed\.\s+Vulnerable:\s*(\d+)\s*\|\s*Not Vulnerable:\s*(\d+)\s*\|\s*Unknown:\s*(\d+)/i);
            if (subzyMatch) {
              subzy_not_vulnerable = parseInt(subzyMatch[2]);
              subzy_unknown = parseInt(subzyMatch[3]);
            }

            const uroMatch = log.match(/Uro completed\.\s+Input:\s*(\d+)\s*\|\s*Normalised:\s*(\d+)\s*\|\s*Removed:\s*(\d+)/i);
            if (uroMatch) {
              uro_input = parseInt(uroMatch[1]);
              uro_normalised = parseInt(uroMatch[2]);
              uro_removed = parseInt(uroMatch[3]);
            }

            const completedMatch = log.match(/\[√\] Provider (\S+) completed/i);
            if (completedMatch) {
              completedFromLogs.add(completedMatch[1].toLowerCase());
            }
            const skippedMatch = log.match(/\[!\] Provider (\S+) skipped/i);
            if (skippedMatch) {
              skippedFromLogs.add(skippedMatch[1].toLowerCase());
            }

            if (log.includes("No live HTTP hosts were found")) {
              pipelineHaltedObj = {
                reason: "no_live_hosts",
                message: "No live HTTP hosts were found. Katana, GAU, SubJS, LinkFinder, GoWitness, GF, and Nuclei were all skipped because there is nothing for them to scan."
              };
            }

            if (log.includes("Katana completed. No LIVE targets to crawl.")) {
              skippedReasonsMap["katana"] = "no_live_hosts_upstream";
            }
            if (log.includes("GAU completed. No target hosts provided.")) {
              skippedReasonsMap["gau"] = "no_live_hosts_upstream";
            }
            if (log.includes("SubJS completed. No input URLs provided.")) {
              skippedReasonsMap["subjs"] = "no_live_hosts_upstream";
            }
            if (log.includes("GoWitness completed. No target URLs provided.")) {
              skippedReasonsMap["gowitness"] = "no_live_hosts_upstream";
            }
            if (log.includes("GF completed. No URLs provided.")) {
              skippedReasonsMap["gf"] = "no_live_hosts_upstream";
            }
            if (log.includes("Nuclei Host Scan completed. No URLs to scan.")) {
              skippedReasonsMap["nuclei_host"] = "no_live_hosts_upstream";
            }
            if (log.includes("Nuclei Endpoint Scan completed. No URLs to scan.")) {
              skippedReasonsMap["nuclei_endpoint"] = "no_live_hosts_upstream";
            }
            if (log.includes("Dalfox completed. No input URLs provided.")) {
              skippedReasonsMap["dalfox"] = "no_live_hosts_upstream";
            }
            if (log.includes("OpenRedirex completed. No input URLs provided.")) {
              skippedReasonsMap["openredirex"] = "no_live_hosts_upstream";
            }
          });
        }
      });

      const originalUrls: { original_url: string; normalized_url: string; duplicate_removed: boolean; source: string }[] = [];

      // 1. Merge subdomains and assets so core target subdomains and hosts are guaranteed present
      const combinedAssetMap = new Map<string, any>();
      (subdomainList || []).forEach((sub: any) => {
        if (sub && sub.domain) {
          combinedAssetMap.set(sub.domain, sub);
        }
      });
      (assetList || []).forEach((a: any) => {
        const key = a.domain || a.value || a.id;
        if (!combinedAssetMap.has(key)) {
          combinedAssetMap.set(key, a);
        } else {
          const existing = combinedAssetMap.get(key);
          combinedAssetMap.set(key, { ...existing, ...a, metadata: { ...existing.metadata, ...a.metadata } });
        }
      });
      const allUnifiedAssets = Array.from(combinedAssetMap.values());

      // Separate real assets from Uro/GF URL assets
      const realAssets = allUnifiedAssets.filter((a: any) => a.type !== "uro_url" && a.type !== "gf_url");
      const uroAssets = allUnifiedAssets.filter((a: any) => a.type === "uro_url");
      const gfAssets = allUnifiedAssets.filter((a: any) => a.type === "gf_url");

      // Populate DNS records from dedicated API endpoint first if available
      (dnsRes || []).forEach((rec: DnsRecord) => {
        if (rec && rec.subdomain && !dns.some((r) => r.subdomain === rec.subdomain)) {
          dns.push(rec);
        }
      });

      realAssets.forEach((asset: any) => {
        if (asset.metadata?.dnsx) {
          const dnsx = asset.metadata.dnsx;
          if (!dns.some((r) => r.subdomain === asset.domain)) {
            dns.push({
              subdomain: asset.domain,
              status: asset.status || "resolved",
              ipv4: dnsx.a || [],
              ipv6: dnsx.aaaa || [],
              cname: dnsx.cname || [],
              resolved_at: dnsx.resolved_at,
            });
          }
        }
        if (asset.type === "takeover" || asset.metadata?.takeover || asset.metadata?.subzy) {
          const meta = asset.metadata || {};
          const subzy = meta.subzy || {};
          const host = asset.domain || asset.value;
          const existingIdx = takeovers.findIndex((r) => r.subdomain === host);
          const tItem: TakeoverRecord = {
            subdomain: host,
            provider: asset.service || meta.service || subzy.service || "unknown",
            status: (asset.status || meta.status || subzy.takeover_status || "Unknown") as any,
            confidence: asset.confidence || meta.confidence || (subzy.service ? "unconfirmed" : "unconfirmed"),
            tools_agreed: asset.tools_agreed || meta.tools_agreed || (subzy.service ? ["subzy"] : []),
            evidence: asset.evidence || meta.evidence || "",
            cname: asset.cname || meta.cname || "",
            last_checked: meta.last_checked || subzy.checked_at || Math.floor(Date.now() / 1000),
          };
          if (existingIdx >= 0) {
            takeovers[existingIdx] = { ...takeovers[existingIdx], ...tItem };
          } else {
            takeovers.push(tItem);
          }
        }
        if (asset.metadata?.url) {
          const urlVal = asset.metadata.url;
          if (!seenUrls.has(urlVal)) {
            seenUrls.add(urlVal);
            originalUrls.push({
              original_url: urlVal,
              normalized_url: urlVal,
              duplicate_removed: false,
              source: "httpx",
            });
          }
        }
        if (asset.metadata?.katana?.urls) {
          asset.metadata.katana.urls.forEach((url: string) => {
            if (!seenUrls.has(url)) {
              seenUrls.add(url);
              originalUrls.push({
                original_url: url,
                normalized_url: url,
                duplicate_removed: false,
                source: "katana",
              });
            }
          });
        }
      });

      // Also ensure any subdomain in subdomainList with dnsx/subzy is processed if not already
      (subdomainList || []).forEach((s: any) => {
        if (s.metadata?.dnsx && !dns.some((r) => r.subdomain === s.domain)) {
          const dnsx = s.metadata.dnsx;
          dns.push({
            subdomain: s.domain,
            status: s.status || "resolved",
            ipv4: dnsx.a || [],
            ipv6: dnsx.aaaa || [],
            cname: dnsx.cname || [],
            resolved_at: dnsx.resolved_at,
          });
        }
        if ((s.type === "takeover" || s.metadata?.takeover || s.metadata?.subzy) && !takeovers.some((r) => r.subdomain === (s.domain || s.value))) {
          const subzy = s.metadata?.subzy || {};
          const meta = s.metadata || {};
          const host = s.domain || s.value;
          takeovers.push({
            subdomain: host,
            provider: s.service || meta.service || subzy.service || "",
            status: (s.status || meta.status || subzy.takeover_status || "Unknown") as any,
            confidence: s.confidence || meta.confidence || "unconfirmed",
            tools_agreed: s.tools_agreed || meta.tools_agreed || (subzy.service ? ["subzy"] : []),
            evidence: s.evidence || meta.evidence || "",
            cname: s.cname || meta.cname || "",
            last_checked: meta.last_checked || subzy.checked_at,
          });
        }
      });

      const normalizedUrls: NormalizedUrlRecord[] = [];
      if (uroAssets.length > 0) {
        uroAssets.forEach((asset: any) => {
          const uro = asset.metadata?.uro || {};
          normalizedUrls.push({
            original_url: uro.original_url || asset.domain,
            normalized_url: uro.normalized_url || asset.domain,
            duplicate_removed: uro.duplicate_removed || false,
            source: "uro",
          });
        });
        
        const normSet = new Set(normalizedUrls.map(u => u.normalized_url));
        originalUrls.forEach((item) => {
          if (!normSet.has(item.normalized_url)) {
            normalizedUrls.push({
              original_url: item.original_url,
              normalized_url: item.normalized_url,
              duplicate_removed: true,
              source: item.source,
            });
          }
        });
      } else if (uro_normalised > 0) {
        originalUrls.forEach((item, idx) => {
          if (idx < uro_normalised) {
            normalizedUrls.push({
              original_url: item.original_url,
              normalized_url: item.normalized_url,
              duplicate_removed: false,
              source: "uro",
            });
          } else {
            normalizedUrls.push({
              original_url: item.original_url,
              normalized_url: item.normalized_url,
              duplicate_removed: true,
              source: item.source,
            });
          }
        });
      } else {
        originalUrls.forEach((item) => {
          normalizedUrls.push(item);
        });
      }

      const gf: GfUrlRecord[] = [];
      const seenGf = new Set<string>();
      
      if (gfAssets.length > 0) {
        gfAssets.forEach((asset: any) => {
          const gfData = asset.metadata?.gf || {};
          gf.push({
            url: gfData.url || asset.domain,
            categories: gfData.categories || [],
            source: "gf",
            classified_at: gfData.classified_at || Math.floor(Date.now() / 1000),
          });
        });
      } else {
        jobsList.forEach((job: any) => {
          if (Array.isArray(job.logs)) {
            job.logs.forEach((log: string) => {
              const match = log.match(/^\s*\[\+\]\s+(https?:\/\/\S+)\s+→\s+(.+)$/);
              if (match) {
                const url = match[1];
                const categories = match[2].split(",").map((c: string) => c.trim()).filter(Boolean);
                categories.forEach((cat) => {
                  const key = `${cat}:${url}`;
                  if (!seenGf.has(key)) {
                    seenGf.add(key);
                    const existing = gf.find((r) => r.url === url);
                    if (existing) {
                      if (!existing.categories.includes(cat)) {
                        existing.categories.push(cat);
                      }
                    } else {
                      gf.push({
                        url,
                        categories: [cat],
                        source: "gf",
                        classified_at: Math.floor(Date.now() / 1000),
                      });
                    }
                  }
                });
              }
            });
          }
        });
      }

      const uniqueDnsxIps = new Set<string>();
      dns.forEach((r) => {
        (r.ipv4 || []).forEach((ip) => uniqueDnsxIps.add(ip));
        (r.ipv6 || []).forEach((ip) => uniqueDnsxIps.add(ip));
      });

      const activeJobFromServer = jobsList.find((j: any) => ["running", "pending", "paused", "stopped"].includes(j.status)) ||
        [...jobsList].sort((a: any, b: any) => new Date(b.started_at || 0).getTime() - new Date(a.started_at || 0).getTime())[0] ||
        null;

      const completedJobs = jobsList
        .filter((j: any) => j.status === "completed" || j.status === "failed")
        .sort((a: any, b: any) => new Date(b.finished_at || 0).getTime() - new Date(a.finished_at || 0).getTime());
      const lastCompletedJobFromServer = completedJobs[0] || null;

      setScanState((prev) => {
        if (activeProjectRef.current?.id !== projectId) {
          return prev;
        }

        const isWsActive = prev.jobId && (Date.now() - prev.lastWsEventTime < 8000);
        
        const targetType = activeProjectRef.current?.target_type || "DOMAIN";
        const isLocalHost = (activeProjectRef.current?.seed_domains || []).includes("localhost");
        const isNewPath = targetType !== "DOMAIN" || isLocalHost;

        let nextStages = { ...prev.stages };
        let nextProviderStatus = { ...prev.providerStatus };
        
        // Initialize skipped stages for new paths
        if (isNewPath) {
          nextStages["discovery"] = "SKIPPED";
          nextStages["dnsx"] = "SKIPPED";
          nextStages["subzy"] = "SKIPPED";
          nextProviderStatus["discovery"] = "SKIPPED";
          nextProviderStatus["dnsx"] = "SKIPPED";
          nextProviderStatus["subzy"] = "SKIPPED";
          ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
            nextProviderStatus[sp] = "SKIPPED";
          });
        }

        let nextCurrentStage = prev.currentStage;

        if (!isWsActive && activeJobFromServer) {
          if (activeJobFromServer.status === "completed") {
            nextCurrentStage = "completed";
            const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei_host", "nuclei_endpoint", "nuclei"];
            PIPELINE_ORDER.forEach((stage) => {
              if (isNewPath && ["discovery", "dnsx", "subzy"].includes(stage)) {
                nextStages[stage] = "SKIPPED";
                nextProviderStatus[stage] = "SKIPPED";
              } else {
                nextStages[stage] = "COMPLETED";
                nextProviderStatus[stage] = "COMPLETED";
              }
            });
            if (isNewPath) {
              ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
                nextProviderStatus[sp] = "SKIPPED";
              });
            } else {
              ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
                nextProviderStatus[sp] = "COMPLETED";
              });
            }
          } else if (activeJobFromServer.status === "failed") {
            nextCurrentStage = "failed";
            const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei_host", "nuclei_endpoint", "nuclei"];
            const jobPhase = (activeJobFromServer.current_phase || "waiting").toLowerCase();
            const currentIdx = PIPELINE_ORDER.indexOf(jobPhase);
            PIPELINE_ORDER.forEach((stage, idx) => {
              if (isNewPath && ["discovery", "dnsx", "subzy"].includes(stage)) {
                nextStages[stage] = "SKIPPED";
                nextProviderStatus[stage] = "SKIPPED";
              } else if (idx < currentIdx) {
                nextStages[stage] = "COMPLETED";
                nextProviderStatus[stage] = "COMPLETED";
              } else if (idx === currentIdx) {
                nextStages[stage] = "FAILED";
                nextProviderStatus[stage] = "FAILED";
              } else {
                nextStages[stage] = "PENDING";
                nextProviderStatus[stage] = "PENDING";
              }
            });
            if (isNewPath) {
              ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
                nextProviderStatus[sp] = "SKIPPED";
              });
            } else {
              if (jobPhase === "discovery") {
                ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
                  nextProviderStatus[sp] = "FAILED";
                });
              } else {
                ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
                  nextProviderStatus[sp] = "COMPLETED";
                });
              }
            }
          } else {
            const jobPhase = activeJobFromServer.current_phase || "waiting";
            const transition = transitionToStage(nextStages, jobPhase);
            nextStages = transition.stages;
            nextCurrentStage = transition.currentStage;
            
            const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei"];
            const currentIdx = PIPELINE_ORDER.indexOf(jobPhase.toLowerCase());
            PIPELINE_ORDER.forEach((stage, idx) => {
              if (isNewPath && ["discovery", "dnsx", "subzy"].includes(stage)) {
                nextProviderStatus[stage] = "SKIPPED";
              } else if (idx < currentIdx) {
                nextProviderStatus[stage] = "COMPLETED";
              } else if (idx === currentIdx) {
                nextProviderStatus[stage] = activeJobFromServer.status === "paused" ? "RUNNING" : (activeJobFromServer.status === "stopped" ? "FAILED" : "RUNNING");
              } else {
                nextProviderStatus[stage] = "PENDING";
              }
            });
            if (!isNewPath && jobPhase.toLowerCase() === "discovery") {
              ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
                if (nextProviderStatus[sp] !== "COMPLETED" && nextProviderStatus[sp] !== "FAILED") {
                  nextProviderStatus[sp] = "RUNNING";
                }
              });
            }
          }
        } else if (!isWsActive && !activeJobFromServer) {
          nextCurrentStage = "waiting";
        }

        const nextProviderCounts = { ...prev.providerCounts, ...dashboardStats.provider_counts };

        const nucleiCountFromAssets = realAssets.reduce(
          (t: number, a: any) => t + (a.metadata?.nuclei?.findings?.length ?? 0), 0
        );
        if (nucleiCountFromAssets > 0) {
          nextProviderCounts["nuclei"] = nucleiCountFromAssets;
        }

        // Determine derived subzy safe and unknown counts strictly from persisted takeoverRecords
        const subzySafe = takeovers.filter((r) => r.status.toLowerCase() === "not vulnerable").length;
        const subzyUnkn = takeovers.filter((r) => r.status.toLowerCase() === "unknown").length;

        // Restore provider statuses from parsed logs
        completedFromLogs.forEach((p) => {
          if (nextProviderStatus[p] !== "FAILED") {
            nextProviderStatus[p] = "COMPLETED";
          }
        });
        skippedFromLogs.forEach((p) => {
          nextProviderStatus[p] = "SKIPPED";
        });

        // Force running to completed if pipeline complete message was in the logs of the active job
        let hasPipelineComplete = false;
        if (activeJobFromServer && Array.isArray(activeJobFromServer.logs)) {
          hasPipelineComplete = activeJobFromServer.logs.some((l: string) => 
            l.toLowerCase().includes("pipeline complete") || l.toLowerCase().includes("unified discovery pipeline finished")
          );
        }
        if (hasPipelineComplete || (activeJobFromServer && activeJobFromServer.status === "completed")) {
          Object.keys(nextProviderStatus).forEach((key) => {
            if (nextProviderStatus[key] === "RUNNING" || nextProviderStatus[key] === "PENDING") {
              nextProviderStatus[key] = "COMPLETED";
            }
          });
        }

        return {
          ...prev,
          jobId: activeJobFromServer && ["running", "pending", "paused", "stopped"].includes(activeJobFromServer.status) ? activeJobFromServer.id : null,
          activeJobObject: activeJobFromServer || null,
          lastCompletedJobObject: lastCompletedJobFromServer,
          assets: realAssets,
          subdomains: subdomainList,
          dnsRecords: dns,
          takeoverRecords: takeovers,
          normalizedUrlRecords: normalizedUrls,
          gfRecords: gf,
          contentPathRecords: (contentPathsRes?.items || []).length > 0
            ? contentPathsRes.items
            : realAssets.filter((a: any) => a.type === "content_path").map((a: any) => ({
                value: a.domain || a.metadata?.url || a.value || "",
                host: a.metadata?.host || a.domain || "",
                status_code: a.metadata?.status_code || a.status_code,
                content_length: a.metadata?.content_length || a.content_length || 0,
                words: a.metadata?.words || a.words || 0,
                lines: a.metadata?.lines || a.lines || 0,
                redirect_location: a.metadata?.redirect_location || a.redirect_location || "",
                calibration_used: a.metadata?.calibration_used ?? true,
                first_seen: a.created_at || a.first_seen,
                last_seen: a.updated_at || a.last_seen,
              })),
          stages: nextStages,
          currentStage: nextCurrentStage,
          providerStatus: nextProviderStatus,
          providerCounts: nextProviderCounts,
          dnsx_resolved: dns.length,
          dnsx_nxdomain: dnsx_nxdomain,
          dnsx_wildcards: dnsx_wildcards,
          dnsx_unique_ips: uniqueDnsxIps.size,
          subzy_vulnerable: takeovers.filter((r) => r.status.toLowerCase() === "vulnerable").length,
          subzy_not_vulnerable: subzySafe || subzy_not_vulnerable,
          subzy_unknown: subzyUnkn || subzy_unknown,
          uro_input: uro_input || originalUrls.length,
          uro_normalised: uro_normalised || normalizedUrls.filter(r => r.source === "uro").length,
          uro_removed: uro_removed || Math.max(0, (uro_input || originalUrls.length) - (uro_normalised || normalizedUrls.filter(r => r.source === "uro").length)),
          gf_total: gf.reduce((sum, r) => sum + r.categories.length, 0),
          gf_categories: (() => {
            const cats: Record<string, number> = {};
            gf.forEach((r) => {
              r.categories.forEach((cat) => {
                cats[cat] = (cats[cat] ?? 0) + 1;
              });
            });
            return cats;
          })(),
          riskScores: riskScores,
          pipelineHalted: pipelineHaltedObj,
          providerSkippedReasons: skippedReasonsMap,
        };
      });
    } catch (err) {
      console.error("Failed to load project details", err);
    }
  };

  useEffect(() => {
    fetchProjectDataRef.current = fetchProjectData;
  }, [fetchProjectData]);

  useEffect(() => {
    // Synchronously reset state and ref so stale-checks in fetchProjectData
    // immediately see the new project id — not the old one.
    activeProjectRef.current = activeProject;
    setScanState(initialScanState);
    setIsReconnect(false);
    setActiveTab("dashboard");
    setInitialInventoryTab("assets");
    setInitialSeverityFilter(null);
    if (activeProject) {
      fetchProjectData();
    }
  }, [activeProject]);

  const handleLaunchScan = async (providerName: string) => {
    if (!activeProject) return;
    try {
      const job = await apiCall(
        `/jobs/project/${activeProject.id}/provider/${encodeURIComponent(providerName)}?scan_mode=${scanMode}`,
        { method: "POST" }
      );
      setIsReconnect(false);
      setScanState((_prev) => {
        const targetType = activeProject?.target_type || "DOMAIN";
        const isLocalHost = (activeProject?.seed_domains || []).includes("localhost");
        const isNewPath = targetType !== "DOMAIN" || isLocalHost;

        let initialStages = { ...initialScanState.stages };
        let initialProviderStatus = { ...initialScanState.providerStatus };
        if (isNewPath) {
          initialStages["discovery"] = "SKIPPED";
          initialStages["dnsx"] = "SKIPPED";
          initialStages["subzy"] = "SKIPPED";
          initialProviderStatus["discovery"] = "SKIPPED";
          initialProviderStatus["dnsx"] = "SKIPPED";
          initialProviderStatus["subzy"] = "SKIPPED";
          ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
            initialProviderStatus[sp] = "SKIPPED";
          });
        }

        const startStage = (isNewPath && (targetType === "IP" || isLocalHost)) ? "naabu" : ((isNewPath) ? "httpx" : "discovery");
        const transition = transitionToStage(initialStages, startStage);
        
        let providerStatusUpdates = { ...initialProviderStatus };
        providerStatusUpdates[startStage] = "RUNNING";

        return {
          ...initialScanState,
          jobId: job.id,
          activeJobObject: job,
          stages: transition.stages,
          currentStage: transition.currentStage,
          providerStatus: providerStatusUpdates,
        };
      });
    } catch (err) {
      console.error("Failed to trigger scan", err);
      alert(`Scan launch error: ${err instanceof Error ? err.message : "Internal Server Error"}`);
    }
  };

  const handlePauseScan = async () => {
    if (!activeJob) return;
    try {
      await apiCall(`/jobs/${activeJob.id}/pause`, { method: "POST" });
      setScanState((prev) => ({
        ...prev,
        activeJobObject: prev.activeJobObject ? { ...prev.activeJobObject, status: "paused" } : null,
      }));
    } catch (err) {
      console.error("Failed to pause scan", err);
    }
  };

  const handleResumeScan = async () => {
    if (!activeJob) return;
    try {
      await apiCall(`/jobs/${activeJob.id}/resume`, { method: "POST" });
      setScanState((prev) => ({
        ...prev,
        activeJobObject: prev.activeJobObject ? { ...prev.activeJobObject, status: "running" } : null,
      }));
    } catch (err) {
      console.error("Failed to resume scan", err);
    }
  };

  const handleStopScan = async () => {
    if (!activeJob) return;
    try {
      await apiCall(`/jobs/${activeJob.id}/stop`, { method: "POST" });
      setScanState((prev) => ({
        ...prev,
        activeJobObject: prev.activeJobObject ? { ...prev.activeJobObject, status: "stopped" } : null,
        currentStage: "stopped",
      }));
      if (wsRef.current) {
        (wsRef.current as any).isCleanClose = true;
        wsRef.current.close();
        wsRef.current = null;
      }
    } catch (err) {
      console.error("Failed to stop scan", err);
    }
  };

  const handleResetScan = async () => {
    if (!activeJob) return;
    try {
      await apiCall(`/jobs/${activeJob.id}/reset`, { method: "POST" });
      setScanState(initialScanState);
      if (wsRef.current) {
        (wsRef.current as any).isCleanClose = true;
        wsRef.current.close();
        wsRef.current = null;
      }
    } catch (err) {
      console.error("Failed to reset scan", err);
    }
  };

  // Open a WebSocket only while the job is genuinely active.  The 800ms-delayed
  // fetchProjectData call in the status:completed handler covers the completion race
  // without needing to keep the socket alive for already-finished jobs.
  const jobId = activeJob && ["running", "pending", "paused", "stopped"].includes(activeJob.status)
    ? activeJob.id
    : null;

  useEffect(() => {
    if (!jobId || !activeProject) return;

    const currentProjectId = activeProject.id;
    const currentJobId = jobId;

    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;
    let reconnectDelay = 1000;
    const maxReconnectDelay = 30000;
    let isClosed = false;
    let isCleanClose = false;

    if (wsRef.current) {
      (wsRef.current as any).isCleanClose = true;
      wsRef.current.close();
      wsRef.current = null;
    }

    const connect = () => {
      if (isClosed || isCleanClose) return;

      const wsUrl = getWebSocketUrl(`/jobs/ws/${jobId}`);
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      
      wsCount++;
      console.log("WebSocket opened", { jobId, currentWebsocketCount: wsCount, isReconnect });
      console.log("Current websocket count:", wsCount);

      ws.onmessage = (event) => {
        if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
          console.log("Ignoring event: Project or Job changed");
          if (ws) {
            (ws as any).isCleanClose = true;
            ws.close();
          }
          return;
        }

        try {
          const rawData = JSON.parse(event.data);
          console.log("WebSocket event received", { jobId, rawData });

          const events = Array.isArray(rawData) ? rawData : [rawData];

          events.forEach((data) => {
            if (!data || !data.type) return;

            if (data.type === "asset_discovered" || data.type === "asset") {
              const incomingAsset = data.asset || data.data;
              if (incomingAsset && incomingAsset.domain) {
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }

                  const exists = prev.assets.some((a) => a.id === incomingAsset.id || a.domain === incomingAsset.domain);
                  let nextAssets = exists
                    ? prev.assets.map((a) => {
                        if (a.id === incomingAsset.id || a.domain === incomingAsset.domain) {
                          const mergedMetadata = {
                            ...(a.metadata || {}),
                            ...(incomingAsset.metadata || {}),
                            nuclei: {
                              ...(a.metadata?.nuclei || {}),
                              ...(incomingAsset.metadata?.nuclei || {}),
                              findings: (() => {
                                const existFindings = a.metadata?.nuclei?.findings || [];
                                const newFindings = incomingAsset.metadata?.nuclei?.findings || [];
                                const merged = [...existFindings];
                                newFindings.forEach((nf: any) => {
                                  const alreadyHas = merged.some((ef: any) => 
                                    (ef.template_id === nf.template_id || ef.template_name === nf.template_name) && 
                                    ef.matched_url === nf.matched_url
                                  );
                                  if (!alreadyHas) {
                                    merged.push(nf);
                                  }
                                });
                                return merged;
                              })()
                            }
                          };
                          return {
                            ...a,
                            ...incomingAsset,
                            metadata: mergedMetadata,
                            open_ports: Array.from(new Set([...(a.open_ports || []), ...(incomingAsset.open_ports || [])])),
                            sources: Array.from(new Set([...(a.sources || []), ...(incomingAsset.sources || [])]))
                          };
                        }
                        return a;
                      })
                    : [
                        ...prev.assets,
                        {
                          ...incomingAsset,
                          metadata: {
                            ...(incomingAsset.metadata || {}),
                            nuclei: incomingAsset.metadata?.nuclei
                              ? {
                                  ...(incomingAsset.metadata.nuclei || {}),
                                  findings: (() => {
                                    const merged: any[] = [];
                                    (incomingAsset.metadata.nuclei.findings || []).forEach((nf: any) => {
                                      const alreadyHas = merged.some((ef: any) => 
                                        (ef.template_id === nf.template_id || ef.template_name === nf.template_name) && 
                                        ef.matched_url === nf.matched_url
                                      );
                                      if (!alreadyHas) {
                                        merged.push(nf);
                                      }
                                    });
                                    return merged;
                                  })()
                                }
                              : undefined
                          }
                        }
                      ];

                  let nextSubdomains = prev.subdomains;
                  if (incomingAsset.type === "subdomain") {
                    const subExists = prev.subdomains.some((s) => s.id === incomingAsset.id || s.domain === incomingAsset.domain);
                    nextSubdomains = subExists
                      ? prev.subdomains.map((s) => (s.id === incomingAsset.id || s.domain === incomingAsset.domain ? incomingAsset : s))
                      : [...prev.subdomains, incomingAsset];
                  }

                  let nextDnsRecords = prev.dnsRecords;
                  if (incomingAsset.metadata?.dnsx) {
                    const dnsx = incomingAsset.metadata.dnsx;
                    if (!nextDnsRecords.some((r) => r.subdomain === incomingAsset.domain)) {
                      nextDnsRecords = [...nextDnsRecords, {
                        subdomain: incomingAsset.domain,
                        status: incomingAsset.status || "resolved",
                        ipv4: dnsx.a || [],
                        ipv6: dnsx.aaaa || [],
                        cname: dnsx.cname || [],
                        resolved_at: dnsx.resolved_at,
                      }];
                    }
                  }

                  let nextTakeoverRecords = prev.takeoverRecords;
                  if (incomingAsset.type === "takeover" || incomingAsset.metadata?.takeover || incomingAsset.metadata?.subzy) {
                    const meta = incomingAsset.metadata || {};
                    const subzy = meta.subzy || {};
                    const host = incomingAsset.domain || incomingAsset.value;
                    const existingIdx = nextTakeoverRecords.findIndex((r) => r.subdomain === host);
                    const tItem: TakeoverRecord = {
                      subdomain: host,
                      provider: incomingAsset.service || meta.service || subzy.service || "unknown",
                      status: (incomingAsset.status || meta.status || subzy.takeover_status || "Unknown") as any,
                      confidence: incomingAsset.confidence || meta.confidence || "unconfirmed",
                      tools_agreed: incomingAsset.tools_agreed || meta.tools_agreed || (subzy.service ? ["subzy"] : []),
                      evidence: incomingAsset.evidence || meta.evidence || "",
                      cname: incomingAsset.cname || meta.cname || "",
                      last_checked: meta.last_checked || subzy.checked_at || Math.floor(Date.now() / 1000),
                    };
                    if (existingIdx >= 0) {
                      const updated = [...nextTakeoverRecords];
                      updated[existingIdx] = { ...updated[existingIdx], ...tItem };
                      nextTakeoverRecords = updated;
                    } else {
                      nextTakeoverRecords = [...nextTakeoverRecords, tItem];
                    }
                  }

                  let nextNormalizedUrlRecords = prev.normalizedUrlRecords;
                  if (incomingAsset.metadata?.katana?.urls) {
                    const katanaUrls = incomingAsset.metadata.katana.urls;
                    let temp = [...nextNormalizedUrlRecords];
                    let changed = false;
                    katanaUrls.forEach((urlVal: string) => {
                      if (!temp.some((r) => r.normalized_url === urlVal && r.source === "katana")) {
                        temp.push({
                          original_url: urlVal,
                          normalized_url: urlVal,
                          duplicate_removed: false,
                          source: "katana",
                        });
                        changed = true;
                      }
                    });
                    if (changed) nextNormalizedUrlRecords = temp;
                  }

                  if (incomingAsset.metadata?.url) {
                    const urlVal = incomingAsset.metadata.url;
                    if (!nextNormalizedUrlRecords.some((r) => r.normalized_url === urlVal && r.source === "httpx")) {
                      nextNormalizedUrlRecords = [...nextNormalizedUrlRecords, {
                        original_url: urlVal,
                        normalized_url: urlVal,
                        duplicate_removed: false,
                        source: "httpx",
                      }];
                    }
                  }

                  let nextContentPathRecords = prev.contentPathRecords;
                  if (incomingAsset.type === "content_path") {
                    const cpUrl = incomingAsset.value || incomingAsset.metadata?.url || incomingAsset.domain;
                    if (!nextContentPathRecords.some((r) => r.value === cpUrl)) {
                      nextContentPathRecords = [{
                        value: cpUrl,
                        host: incomingAsset.metadata?.host || incomingAsset.domain || "",
                        status_code: incomingAsset.metadata?.status_code || incomingAsset.status_code,
                        content_length: incomingAsset.metadata?.content_length || incomingAsset.content_length || 0,
                        words: incomingAsset.metadata?.words || incomingAsset.words || 0,
                        lines: incomingAsset.metadata?.lines || incomingAsset.lines || 0,
                        redirect_location: incomingAsset.metadata?.redirect_location || incomingAsset.redirect_location || "",
                        calibration_used: incomingAsset.metadata?.calibration_used ?? true,
                        first_seen: incomingAsset.created_at || incomingAsset.first_seen || new Date().toISOString(),
                        last_seen: incomingAsset.updated_at || incomingAsset.last_seen || new Date().toISOString(),
                      }, ...nextContentPathRecords];
                    }
                  }

                  const uniqueIps = new Set<string>();
                  nextDnsRecords.forEach((r) => {
                    (r.ipv4 || []).forEach((ip) => uniqueIps.add(ip));
                    (r.ipv6 || []).forEach((ip) => uniqueIps.add(ip));
                  });

                  const vuln = nextTakeoverRecords.filter((r) => r.status.toLowerCase() === "vulnerable").length;
                  const safe = nextTakeoverRecords.filter((r) => r.status.toLowerCase() === "not vulnerable").length;
                  const unkn = nextTakeoverRecords.filter((r) => r.status.toLowerCase() === "unknown").length;

                  return {
                    ...prev,
                    assets: nextAssets,
                    subdomains: nextSubdomains,
                    dnsRecords: nextDnsRecords,
                    takeoverRecords: nextTakeoverRecords,
                    normalizedUrlRecords: nextNormalizedUrlRecords,
                    contentPathRecords: nextContentPathRecords,
                    dnsx_resolved: nextDnsRecords.length,
                    dnsx_unique_ips: uniqueIps.size,
                    subzy_vulnerable: nextTakeoverRecords.length > 0 ? vuln : prev.subzy_vulnerable,
                    subzy_not_vulnerable: nextTakeoverRecords.length > 0 ? safe : prev.subzy_not_vulnerable,
                    subzy_unknown: nextTakeoverRecords.length > 0 ? unkn : prev.subzy_unknown,
                    lastWsEventTime: Date.now(),
                  };
                });
              }
            } else if (data.type === "finding" || data.type === "finding_event" || (data.type === "scan_summary" && data.event === "FindingDetected")) {
              const finding = data.finding || data.data;
              if (finding) {
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  return {
                    ...prev,
                    assets: mergeFindingIntoAssets(prev.assets, finding),
                    lastWsEventTime: Date.now()
                  };
                });
              }
            } else if (data.type === "risk_score_event") {
              setScanState((prev) => {
                if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                  return prev;
                }
                const updatedScores = [...prev.riskScores];
                const scoreObj = {
                  asset: data.asset,
                  score: data.score,
                  level: data.level,
                  reasons: data.reasons,
                  exposure_factors: data.exposure_factors,
                  recommended_priority: data.recommended_priority,
                  importance_score: data.importance_score,
                  exposure_score: data.exposure_score,
                  updated_at: data.updated_at
                };
                const idx = updatedScores.findIndex(s => s.asset.toLowerCase() === data.asset.toLowerCase());
                if (idx !== -1) {
                  updatedScores[idx] = scoreObj;
                } else {
                  updatedScores.push(scoreObj);
                }

                const updatedAssets = prev.assets.map(asset => {
                  if (asset.domain.toLowerCase() === data.asset.toLowerCase()) {
                    return {
                      ...asset,
                      risk: scoreObj
                    };
                  }
                  return asset;
                });

                return {
                  ...prev,
                  riskScores: updatedScores,
                  assets: updatedAssets,
                  lastWsEventTime: Date.now()
                };
              });
            } else if (data.type === "scan_diff") {
              if (data.diff) {
                setLatestDiff(data.diff);
              }
            } else if (data.type === "content_path_event") {
              const item = data.data || data;
              if (item && (item.url || item.value)) {
                const urlVal = item.url || item.value;
                const rec: ContentPathRecord = {
                  value: urlVal,
                  host: item.host || item.domain || "",
                  status_code: item.status_code,
                  content_length: item.content_length ?? item.length ?? 0,
                  words: item.words ?? 0,
                  lines: item.lines ?? 0,
                  redirect_location: item.redirect_location || "",
                  calibration_used: item.calibration_used ?? true,
                  first_seen: item.first_seen || new Date().toISOString(),
                  last_seen: item.last_seen || new Date().toISOString(),
                };
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  if (prev.contentPathRecords.some((p) => p.value === rec.value)) {
                    return prev;
                  }
                  return {
                    ...prev,
                    contentPathRecords: [rec, ...prev.contentPathRecords],
                    lastWsEventTime: Date.now(),
                  };
                });
              }
            } else if (data.type === "provider_stat") {
              const { provider, count } = data;
              setScanState((prev) => {
                if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                  return prev;
                }
                const nextProviderStatus = updateProviderStatus(prev.providerStatus, provider, "RUNNING");
                return {
                  ...prev,
                  providerCounts: {
                    ...prev.providerCounts,
                    [provider]: count,
                  },
                  providerStatus: nextProviderStatus,
                  lastWsEventTime: Date.now(),
                };
              });
            } else if (data.type === "stage_skipped") {
              const tool = (data.tool || "").toLowerCase();
              if (tool) {
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  return {
                    ...prev,
                    providerStatus: { ...prev.providerStatus, [tool]: "SKIPPED" },
                    stages: { ...prev.stages, [tool]: "SKIPPED" },
                    providerSkippedReasons: {
                      ...prev.providerSkippedReasons,
                      [tool]: data.reason || "tool_missing",
                    },
                    lastWsEventTime: Date.now(),
                  };
                });
              }
            } else if (data.type === "scope_filtered") {
              console.log("[ReconForge Scope Filter]", data);
            } else if (data.type === "scope_warning") {
              console.warn("[ReconForge Scope Warning]", data.message);
            } else if (data.type === "scan_summary") {
              if (data.event === "PipelineHalted") {
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  return {
                    ...prev,
                    pipelineHalted: { reason: data.reason, message: data.message }
                  };
                });
              }
              if (data.provider) {
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  const providerName = data.provider.toLowerCase();
                  let nextStageData = { currentStage: prev.currentStage, stages: prev.stages };
                  let nextProviderStatus = { ...prev.providerStatus };
                  let nextProviderSkippedReasons = { ...prev.providerSkippedReasons };

                  if (data.skipped_reason) {
                    nextProviderSkippedReasons[providerName] = data.skipped_reason;
                  }
                  
                  if (data.status) {
                    nextProviderStatus[providerName] = data.status.toUpperCase();
                  } else {
                    nextProviderStatus = updateProviderStatus(prev.providerStatus, providerName, "COMPLETED");
                  }
                  
                  const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei_host", "nuclei_endpoint", "nuclei"];
                  const currentIdx = PIPELINE_ORDER.indexOf(providerName);
                  if (currentIdx !== -1) {
                    nextStageData = transitionToStage(prev.stages, providerName);
                    if (currentIdx < PIPELINE_ORDER.length - 1) {
                      const nextStageName = PIPELINE_ORDER[currentIdx + 1];
                      nextStageData = transitionToStage(nextStageData.stages, nextStageName);
                      nextProviderStatus = updateProviderStatus(nextProviderStatus, nextStageName, "RUNNING");
                    } else {
                      nextStageData = transitionToStage(nextStageData.stages, "completed");
                    }
                  }

                  let extraStats: Partial<ScanState> = {};
                  let nextProviderCounts = { ...prev.providerCounts };
                  if (data.count !== undefined) {
                    nextProviderCounts[providerName] = data.count;
                    if (providerName === "nuclei_host" || providerName === "nuclei_endpoint") {
                      nextProviderCounts.nuclei = (nextProviderCounts.nuclei_host ?? 0) + (nextProviderCounts.nuclei_endpoint ?? 0);
                    }
                    extraStats.providerCounts = nextProviderCounts;
                  }

                  const upperProvider = data.provider.toUpperCase();
                  if (upperProvider === "DNSX") {
                    extraStats = {
                      ...extraStats,
                      dnsx_resolved: data.resolved ?? prev.dnsx_resolved,
                      dnsx_nxdomain: data.nxdomain ?? prev.dnsx_nxdomain,
                      dnsx_wildcards: data.wildcards_filtered ?? prev.dnsx_wildcards,
                    };
                  } else if (upperProvider === "SUBZY") {
                    extraStats = {
                      ...extraStats,
                      subzy_vulnerable: data.vulnerable ?? prev.subzy_vulnerable,
                      subzy_not_vulnerable: data.not_vulnerable ?? prev.subzy_not_vulnerable,
                      subzy_unknown: data.unknown ?? prev.subzy_unknown,
                    };
                  } else if (upperProvider === "URO") {
                    extraStats = {
                      ...extraStats,
                      uro_input: data.input_urls ?? prev.uro_input,
                      uro_normalised: data.normalised_urls ?? prev.uro_normalised,
                      uro_removed: data.removed ?? prev.uro_removed,
                    };
                  } else if (upperProvider === "GF") {
                    extraStats = {
                      ...extraStats,
                      gf_total: data.urls_classified ?? prev.gf_total,
                      gf_categories: data.matches_by_category
                        ? { ...prev.gf_categories, ...data.matches_by_category }
                        : prev.gf_categories,
                    };
                  } else if (upperProvider === "NUCLEI HOST SCAN") {
                    const nucleiHostFindings = data.findings_found ?? 0;
                    nextProviderCounts.nuclei_host = nucleiHostFindings;
                    nextProviderCounts.nuclei = (nextProviderCounts.nuclei_host ?? 0) + (nextProviderCounts.nuclei_endpoint ?? 0);
                    extraStats.providerCounts = nextProviderCounts;
                  } else if (upperProvider === "NUCLEI ENDPOINT SCAN") {
                    const nucleiEndpointFindings = data.findings_found ?? 0;
                    nextProviderCounts.nuclei_endpoint = nucleiEndpointFindings;
                    nextProviderCounts.nuclei = (nextProviderCounts.nuclei_host ?? 0) + (nextProviderCounts.nuclei_endpoint ?? 0);
                    extraStats.providerCounts = nextProviderCounts;
                  } else if (upperProvider === "NUCLEI") {
                    const nucleiFindings = data.findings_found ?? 0;
                    nextProviderCounts.nuclei = nucleiFindings;
                    extraStats.providerCounts = nextProviderCounts;
                  }

                  return {
                    ...prev,
                    stages: nextStageData.stages,
                    currentStage: nextStageData.currentStage,
                    providerStatus: nextProviderStatus,
                    providerSkippedReasons: nextProviderSkippedReasons,
                    ...extraStats,
                    lastWsEventTime: Date.now(),
                  };
                });
              } else if (data.provider_counts || data.total_unique !== undefined) {
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  return {
                    ...prev,
                    dnsx_resolved: data.dnsx_resolved ?? prev.dnsx_resolved,
                    dnsx_nxdomain: data.dnsx_nxdomain ?? prev.dnsx_nxdomain,
                    dnsx_wildcards: data.dnsx_wildcards_filtered ?? prev.dnsx_wildcards,
                    subzy_vulnerable: data.subzy_vulnerable ?? prev.subzy_vulnerable,
                    uro_input: data.uro_normalised !== undefined ? (data.uro_normalised + (data.uro_removed ?? 0)) : prev.uro_input,
                    uro_normalised: data.uro_normalised ?? prev.uro_normalised,
                    uro_removed: data.uro_removed ?? prev.uro_removed,
                    gf_total: data.gf_classified ?? prev.gf_total,
                    lastWsEventTime: Date.now(),
                  };
                });
              }
            } else if (data.type === "status") {
              if (data.status === "idle") {
                setScanState(initialScanState);
                isCleanClose = true;
                if (ws) ws.close();
              } else {
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  let nextStageData = { currentStage: prev.currentStage, stages: prev.stages };
                  let nextProviderStatus = { ...prev.providerStatus };
                  
                  if (data.status === "completed" || data.status === "failed") {
                    nextStageData = transitionToStage(prev.stages, "completed");
                    Object.keys(nextProviderStatus).forEach((s) => {
                      if (nextProviderStatus[s] !== "SKIPPED" && nextProviderStatus[s] !== "FAILED" && nextProviderStatus[s] !== "COMPLETED") {
                        nextProviderStatus[s] = data.status === "completed" ? "COMPLETED" : "FAILED";
                      }
                    });
                    isCleanClose = true;
                    if (ws) ws.close();
                  } else if (data.status === "stopped") {
                    nextStageData = { currentStage: "stopped", stages: prev.stages };
                    Object.keys(nextProviderStatus).forEach((s) => {
                      if (nextProviderStatus[s] === "RUNNING" || nextProviderStatus[s] === "PENDING") {
                        nextProviderStatus[s] = "FAILED";
                      }
                    });
                    isCleanClose = true;
                    if (ws) ws.close();
                  }
                  
                  return {
                    ...prev,
                    activeJobObject: prev.activeJobObject
                      ? { ...prev.activeJobObject, status: data.status }
                      : null,
                    stages: nextStageData.stages,
                    currentStage: nextStageData.currentStage,
                    providerStatus: nextProviderStatus,
                    lastWsEventTime: Date.now(),
                  };
                });
                
                // Always perform a final REST sync on job completion/failure so the
                // dashboard reflects exactly what MongoDB has — regardless of WS latency.
                if (data.status === "completed" || data.status === "failed" || data.status === "stopped") {
                  setTimeout(() => {
                    if (fetchProjectDataRef.current) fetchProjectDataRef.current();
                  }, 800);
                }
              }
            } else if (data.type === "url_event") {
              const urlDataPayload = data.data;
              if (urlDataPayload) {
                const urlItems = Array.isArray(urlDataPayload) ? urlDataPayload : [urlDataPayload];
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  let nextList = [...prev.normalizedUrlRecords];
                  urlItems.forEach((item) => {
                    const urlVal = item.url || item.normalized_url;
                    if (urlVal) {
                      if (!nextList.some((r) => r.normalized_url === urlVal && r.source === "uro")) {
                        nextList.push({
                          original_url: item.original_url || urlVal,
                          normalized_url: urlVal,
                          duplicate_removed: false,
                          source: "uro",
                        });
                      }
                    }
                  });
                  return {
                    ...prev,
                    normalizedUrlRecords: nextList,
                    uro_normalised: nextList.filter(r => r.source === "uro").length,
                    lastWsEventTime: Date.now(),
                  };
                });
              }
            } else if (data.type === "gf_event") {
              const gfDataPayload = data.data;
              if (gfDataPayload) {
                const gfItems = Array.isArray(gfDataPayload) ? gfDataPayload : [gfDataPayload];
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  let nextList = [...prev.gfRecords];
                  gfItems.forEach((item) => {
                    const urlVal = item.url;
                    if (urlVal) {
                      const cats = Array.isArray(item.categories)
                        ? item.categories
                        : [item.category].filter(Boolean);
                      
                      cats.forEach((cat: string) => {
                        const existing = nextList.find((r) => r.url === urlVal);
                        if (existing) {
                          if (!existing.categories.includes(cat)) {
                            existing.categories = [...existing.categories, cat];
                          }
                        } else {
                          nextList.push({
                            url: urlVal,
                            categories: [cat],
                            source: item.source || "gf",
                            classified_at: item.classified_at || Math.floor(Date.now() / 1000),
                          });
                        }
                      });
                    }
                  });

                  const gfCats: Record<string, number> = {};
                  nextList.forEach((r) => {
                    r.categories.forEach((cat) => {
                      gfCats[cat] = (gfCats[cat] ?? 0) + 1;
                    });
                  });

                  return {
                    ...prev,
                    gfRecords: nextList,
                    gf_total: nextList.length,
                    gf_categories: gfCats,
                    lastWsEventTime: Date.now(),
                  };
                });
              }
            } else if (data.type === "log" && data.message) {
              const msg = data.message;
              const lowerMsg = msg.toLowerCase();
              
              setScanState((prev) => {
                if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                  return prev;
                }
                let nextStages = { ...prev.stages };
                let nextProviderStatus = { ...prev.providerStatus };
                let nextCurrentStage = prev.currentStage;
                
                const providersList = ["subfinder", "assetfinder", "amass", "chaos"];
                providersList.forEach((p) => {
                  if (lowerMsg.includes(p) && (lowerMsg.includes("completed") || lowerMsg.includes("finished"))) {
                    nextProviderStatus = updateProviderStatus(nextProviderStatus, p, "COMPLETED");
                  }
                });

                let detectedStage = "";
                if (lowerMsg.includes("launching dnsx") || lowerMsg.includes("dnsx resolution") || (lowerMsg.includes("resolving") && lowerMsg.includes("subdomains"))) {
                  detectedStage = "dnsx";
                } else if (lowerMsg.includes("launching subzy") || lowerMsg.includes("subzy takeover")) {
                  detectedStage = "subzy";
                } else if (lowerMsg.includes("starting httpx") || lowerMsg.includes("launching httpx") || lowerMsg.includes("httpx probing")) {
                  detectedStage = "httpx";
                } else if (lowerMsg.includes("starting naabu") || lowerMsg.includes("launching naabu") || lowerMsg.includes("naabu port scan")) {
                  detectedStage = "naabu";
                } else if (lowerMsg.includes("starting katana") || lowerMsg.includes("launching katana") || lowerMsg.includes("katana web crawl") || lowerMsg.includes("starting crawl session")) {
                  detectedStage = "katana";
                } else if (lowerMsg.includes("launching uro") || lowerMsg.includes("uro url normalisation") || lowerMsg.includes("uro completed")) {
                  detectedStage = "uro";
                } else if (lowerMsg.includes("gf pattern") || lowerMsg.includes("gf classification") || (lowerMsg.includes("classifying") && lowerMsg.includes("urls"))) {
                  detectedStage = "gf";
                } else if (lowerMsg.includes("nuclei host scan") || lowerMsg.includes("host scan") && lowerMsg.includes("nuclei")) {
                  detectedStage = "nuclei_host";
                } else if (lowerMsg.includes("nuclei endpoint scan") || (lowerMsg.includes("endpoint scan") && lowerMsg.includes("nuclei"))) {
                  detectedStage = "nuclei_endpoint";
                } else if (lowerMsg.includes("starting nuclei") || lowerMsg.includes("launching nuclei") || lowerMsg.includes("nuclei vuln scan")) {
                  detectedStage = "nuclei";
                }

                if (detectedStage) {
                  const transition = transitionToStage(nextStages, detectedStage);
                  nextStages = transition.stages;
                  nextCurrentStage = transition.currentStage;
                  nextProviderStatus = updateProviderStatus(nextProviderStatus, detectedStage, "RUNNING");
                }

                let extraStats: Partial<ScanState> = {};
                
                const dnsxMatch = msg.match(/DNSx completed\.\s+Resolved:\s*(\d+)\s*\|\s*NXDOMAIN:\s*(\d+)\s*\|\s*Wildcards filtered:\s*(\d+)/i);
                if (dnsxMatch) {
                  extraStats.dnsx_resolved = parseInt(dnsxMatch[1]);
                  extraStats.dnsx_nxdomain = parseInt(dnsxMatch[2]);
                  extraStats.dnsx_wildcards = parseInt(dnsxMatch[3]);
                  
                  const transition = transitionToStage(nextStages, "subzy");
                  nextStages = transition.stages;
                  nextCurrentStage = transition.currentStage;
                  nextProviderStatus = updateProviderStatus(nextProviderStatus, "dnsx", "COMPLETED");
                  nextProviderStatus = updateProviderStatus(nextProviderStatus, "subzy", "RUNNING");
                }

                const subzyMatch = msg.match(/Subzy completed\.\s+Vulnerable:\s*(\d+)\s*\|\s*Not Vulnerable:\s*(\d+)\s*\|\s*Unknown:\s*(\d+)/i);
                if (subzyMatch) {
                  extraStats.subzy_vulnerable = parseInt(subzyMatch[1]);
                  extraStats.subzy_not_vulnerable = parseInt(subzyMatch[2]);
                  extraStats.subzy_unknown = parseInt(subzyMatch[3]);
                  
                  const transition = transitionToStage(nextStages, "naabu");
                  nextStages = transition.stages;
                  nextCurrentStage = transition.currentStage;
                  nextProviderStatus = updateProviderStatus(nextProviderStatus, "subzy", "COMPLETED");
                  nextProviderStatus = updateProviderStatus(nextProviderStatus, "naabu", "RUNNING");
                }

                const uroMatch = msg.match(/Uro completed\.\s+Input:\s*(\d+)\s*\|\s*Normalised:\s*(\d+)\s*\|\s*Removed:\s*(\d+)/i);
                if (uroMatch) {
                  extraStats.uro_input = parseInt(uroMatch[1]);
                  extraStats.uro_normalised = parseInt(uroMatch[2]);
                  extraStats.uro_removed = parseInt(uroMatch[3]);
                  
                  const transition = transitionToStage(nextStages, "gf");
                  nextStages = transition.stages;
                  nextCurrentStage = transition.currentStage;
                  nextProviderStatus = updateProviderStatus(nextProviderStatus, "uro", "COMPLETED");
                  nextProviderStatus = updateProviderStatus(nextProviderStatus, "gf", "RUNNING");
                }

                if (lowerMsg.includes("wildcard filtered:")) {
                  extraStats.dnsx_wildcards = (prev.dnsx_wildcards ?? 0) + 1;
                }

                let nextTakeoverRecords = prev.takeoverRecords;
                const subzyLineMatch = msg.match(/^\s*\[([!+?])\]\s+(\S+)\s+→\s+(Vulnerable|Not\s+Vulnerable|Unknown)/i);
                if (subzyLineMatch) {
                  const subdomain = subzyLineMatch[2];
                  const takeover_status = subzyLineMatch[3].trim();
                  if (!nextTakeoverRecords.some((r) => r.subdomain === subdomain)) {
                    nextTakeoverRecords = [...nextTakeoverRecords, {
                      subdomain,
                      provider: "subzy",
                      status: takeover_status as any,
                      last_checked: Math.floor(Date.now() / 1000),
                    }];
                    extraStats.subzy_vulnerable = nextTakeoverRecords.filter((r) => r.status.toLowerCase() === "vulnerable").length;
                    extraStats.subzy_not_vulnerable = nextTakeoverRecords.filter((r) => r.status.toLowerCase() === "not vulnerable").length;
                    extraStats.subzy_unknown = nextTakeoverRecords.filter((r) => r.status.toLowerCase() === "unknown").length;
                  }
                }

                let nextGfRecords = prev.gfRecords;
                const gfMatch = msg.match(/^\s*\[\+\]\s+(https?:\/\/\S+)\s+→\s+(.+)$/);
                if (gfMatch) {
                  const urlVal = gfMatch[1];
                  const cats = gfMatch[2].split(",").map((c: string) => c.trim()).filter(Boolean);
                  let changed = false;
                  let temp = [...nextGfRecords];
                  cats.forEach((cat: string) => {
                    const existing = temp.find((r) => r.url === urlVal);
                    if (existing) {
                      if (!existing.categories.includes(cat)) {
                        existing.categories = [...existing.categories, cat];
                        changed = true;
                      }
                    } else {
                      temp.push({
                        url: urlVal,
                        categories: [cat],
                        source: "gf",
                        classified_at: Math.floor(Date.now() / 1000),
                      });
                      changed = true;
                    }
                  });
                  if (changed) {
                    nextGfRecords = temp;
                    const gfCats: Record<string, number> = {};
                    nextGfRecords.forEach((r) => {
                      r.categories.forEach((c) => {
                        gfCats[c] = (gfCats[c] ?? 0) + 1;
                      });
                    });
                    extraStats.gf_total = nextGfRecords.length;
                    extraStats.gf_categories = gfCats;
                  }
                }

                let nextNormalizedUrlRecords = prev.normalizedUrlRecords;
                const katanaMatch = msg.match(/^\s*\[\+\] Discovered URL on [^:]+:\s*(https?:\/\/\S+)/);
                if (katanaMatch) {
                  const urlVal = katanaMatch[1];
                  if (!nextNormalizedUrlRecords.some((r) => r.normalized_url === urlVal && r.source === "katana")) {
                    nextNormalizedUrlRecords = [...nextNormalizedUrlRecords, {
                      original_url: urlVal,
                      normalized_url: urlVal,
                      duplicate_removed: false,
                      source: "katana",
                    }];
                    const originalCount = nextNormalizedUrlRecords.filter(r => r.source === "katana" || r.source === "httpx").length;
                    extraStats.uro_input = originalCount;
                  }
                }

                return {
                  ...prev,
                  stages: nextStages,
                  providerStatus: nextProviderStatus,
                  currentStage: nextCurrentStage,
                  takeoverRecords: nextTakeoverRecords,
                  gfRecords: nextGfRecords,
                  normalizedUrlRecords: nextNormalizedUrlRecords,
                  ...extraStats,
                  lastWsEventTime: Date.now(),
                };
              });
            }
          });
        } catch (err) {
          console.error("Dashboard WS parse error", err);
        }
      };

      ws.onclose = () => {
        isClosed = true;
        wsCount--;
        console.log("WebSocket closed", { jobId, currentWebsocketCount: wsCount });
        console.log("Current websocket count:", wsCount);
        
        if (!isCleanClose) {
          console.log("WebSocket reconnect", { jobId, delay: reconnectDelay });
          reconnectTimeout = setTimeout(() => {
            reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay);
            isClosed = false;
            if (fetchProjectDataRef.current) {
              fetchProjectDataRef.current();
            }
            connect();
          }, reconnectDelay);
        }
      };

      ws.onerror = (err) => {
        console.error("WebSocket error", err);
      };
    };

    connect();

    const pingInterval = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send("ping");
      }
    }, 15000);

    return () => {
      isCleanClose = true;
      clearInterval(pingInterval);
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) {
        (ws as any).isCleanClose = true;
        ws.close();
      }
      if (!isClosed) {
        isClosed = true;
        wsCount--;
        console.log("WebSocket closed", { jobId, currentWebsocketCount: wsCount });
        console.log("Current websocket count:", wsCount);
      }
    };
  }, [jobId, activeProject?.id]);

  if (loading) {
    return (
      <div className="min-h-screen bg-dark-bg flex flex-col items-center justify-center space-y-4">
        <RefreshCw className="w-10 h-10 text-cyber-accent animate-spin" />
        <span className="font-mono text-xs text-slate-400 tracking-widest uppercase">Initializing Operator Terminal...</span>
      </div>
    );
  }

  const tabs: { id: TabId; label: string; icon: React.ReactNode }[] = [
    { id: "dashboard", label: "Dashboard Overview", icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: "diffs", label: "What's New", icon: <Sparkles className="w-4 h-4" /> },
    { id: "runs", label: "Run History", icon: <HistoryIcon className="w-4 h-4" /> },
    { id: "subdomains", label: "Subdomains", icon: <Globe2 className="w-4 h-4" /> },
    { id: "inventory", label: "Asset Inventory", icon: <Database className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-dark-bg text-dark-text flex flex-col">
      {isInMemoryDb && (
        <div className="bg-amber-500/20 border-b border-amber-500/50 text-amber-200 px-4 py-2 text-xs font-mono font-bold flex items-center justify-center gap-2 sticky top-0 z-50 backdrop-blur-md shadow-md">
          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
          <span>Running on in-memory DB, data will be lost</span>
        </div>
      )}
      <Navbar
        projects={projects}
        activeProject={activeProject}
        onSelectProject={setActiveProject}
        onRefreshProjects={fetchProjects}
        onOpenSettings={() => setShowSettingsModal(true)}
      />

      {activeProject ? (
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {/* Navigation Tabs */}
          <div className="flex items-center justify-between border-b border-dark-border pb-1">
            <div className="flex space-x-1.5">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => {
                    setActiveTab(tab.id);
                    if (tab.id === "inventory") {
                      setInitialInventoryTab("assets");
                      setInitialSeverityFilter(null);
                    }
                  }}
                  className={`flex items-center space-x-2 px-4 py-2.5 rounded-t-lg text-xs font-bold uppercase tracking-wider transition-all cursor-pointer ${
                    activeTab === tab.id
                      ? "bg-dark-card border-t border-x border-dark-border text-cyber-accent"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                  {tab.id === "subdomains" && subdomains.length > 0 && (
                    <span className="ml-1 px-1.5 py-0.5 bg-cyber-accent/20 border border-cyber-accent/40 text-cyber-accent rounded text-[9px] font-bold">
                      {subdomains.length}
                    </span>
                  )}
                </button>
              ))}
            </div>

            <div className="flex items-center space-x-2">
              <div className="flex items-center space-x-1 bg-dark-bg border border-dark-border rounded p-0.5 font-mono text-[10px]">
                <button
                  onClick={() => setScanMode("fast")}
                  className={`px-2 py-1 rounded transition-colors cursor-pointer uppercase font-bold ${
                    scanMode === "fast" 
                      ? "bg-cyber-accent text-dark-bg font-extrabold" 
                      : "text-slate-400 hover:text-slate-200 font-semibold"
                  }`}
                >
                  Fast Scan
                </button>
                <button
                  onClick={() => setScanMode("deep")}
                  className={`px-2 py-1 rounded transition-colors cursor-pointer uppercase font-bold ${
                    scanMode === "deep" 
                      ? "bg-red-500 text-white font-extrabold" 
                      : "text-slate-400 hover:text-slate-200 font-semibold"
                  }`}
                >
                  Deep Scan
                </button>
              </div>

              <button
                onClick={() => setShowSettingsModal(true)}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-dark-card hover:bg-dark-hover border border-dark-border text-cyber-accent rounded text-xs font-bold transition-all cursor-pointer"
                title="Configure Scope, Rate Limits, and WSL Tools"
              >
                <Sliders className="w-3.5 h-3.5" />
                <span>Scope & Settings</span>
                {(!activeProject.scope?.in_scope?.length && !activeProject.scope?.out_of_scope?.length) && (
                  <span className="w-2 h-2 rounded-full bg-cyber-warning animate-pulse" />
                )}
              </button>

              <button
                onClick={fetchProjectData}
                className="flex items-center space-x-1 px-3 py-1.5 bg-dark-card hover:bg-dark-hover border border-dark-border text-slate-400 hover:text-slate-200 rounded text-xs font-bold transition-all cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Sync Telemetry</span>
              </button>
            </div>
          </div>

          {/* Tab Panels */}
          <div className="animate-fadeIn">
            {activeTab === "dashboard" && (
              <OverviewDashboard
                stats={stats}
                assets={assets}
                activeProject={activeProject}
                onLaunchScan={handleLaunchScan}
                onRefresh={fetchProjectData}
                activeJob={activeJob}
                completedProviders={completedProviders}
                currentPhase={currentPhase}
                onPauseScan={handlePauseScan}
                onResumeScan={handleResumeScan}
                onStopScan={handleStopScan}
                onResetScan={handleResetScan}
                stages={stages}
                providerStatus={providerStatus}
                pipelineHalted={scanState.pipelineHalted}
                providerSkippedReasons={scanState.providerSkippedReasons}
                onOpenSettings={() => setShowSettingsModal(true)}
                onSelectSeverity={(severity: string) => {
                  setInitialInventoryTab("nuclei");
                  setInitialSeverityFilter(severity);
                  setActiveTab("inventory");
                }}
              />
            )}

            {activeTab === "diffs" && (
              <DiffTab
                projectId={activeProject.id}
                projectName={activeProject.name}
                latestDiffProp={latestDiff}
              />
            )}

            {activeTab === "runs" && (
              <RunHistoryTab projectId={activeProject.id} />
            )}

            {activeTab === "subdomains" && (
              <SubdomainsTab subdomains={subdomains} />
            )}

            {activeTab === "inventory" && (
              <AssetTable
                assets={assets}
                projectId={activeProject?.id}
                projectName={activeProject?.name}
                dnsRecords={dnsRecords}
                takeoverRecords={takeoverRecords}
                normalizedUrlRecords={normalizedUrlRecords}
                gfRecords={gfRecords}
                contentPathRecords={contentPathRecords}
                latestScanTime={stats?.last_scan_time || activeJob?.started_at}
                initialTab={initialInventoryTab}
                initialSeverityFilter={initialSeverityFilter}
              />
            )}
          </div>

          {/* Floating console overlay – receives shared state, owns NO WebSocket */}
          {activeJob && (
            <div className="mt-8 pt-4 border-t border-dark-border">
              <ConsoleView
                activeJob={activeJob}
                subdomainNames={subdomains.map((s: any) => (typeof s === "string" ? s : s?.domain)).filter(Boolean)}
                providerStats={stats.provider_counts as Record<string, number> ?? {}}
                completedProviders={completedProviders}
                onClose={() => setScanState((prev) => ({ ...prev, activeJobObject: null }))}
              />
            </div>
          )}

          {/* Project Settings & Tools Modal */}
          <ProjectSettingsModal
            isOpen={showSettingsModal}
            onClose={() => setShowSettingsModal(false)}
            project={activeProject}
            onProjectUpdated={handleProjectUpdated}
          />
        </main>
      ) : (
        <div className="flex-1 flex flex-col items-center justify-center p-6 space-y-6 text-center">
          <div className="bg-dark-card border border-dark-border p-8 rounded-xl max-w-md glass shadow-2xl space-y-4">
            <div className="mx-auto bg-cyber-primary/10 border border-cyber-primary/30 p-4 rounded-full w-16 h-16 flex items-center justify-center animate-pulse">
              <Sparkles className="w-8 h-8 text-cyber-accent" />
            </div>
            <h2 className="text-xl font-bold text-white uppercase tracking-wider">No Active Project Configured</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Before launching Discovery Pipelines, you must register a project and set authorized seed targets (domains) to audit.
            </p>
            <div className="pt-2">
              <span className="text-[10px] text-cyber-warning font-mono block mb-3 uppercase tracking-wider">Configure settings using navbar scope tools</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default function App() {
  return <MainDashboard />;
}
