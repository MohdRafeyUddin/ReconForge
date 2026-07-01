import React, { useState, useEffect, useRef } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { AuthPage } from "./components/Auth/AuthPage";
import { Navbar } from "./components/Common/Navbar";
import { OverviewDashboard } from "./components/Dashboard/OverviewDashboard";
import { AssetTable } from "./components/Inventory/AssetTable";
import type { DnsRecord } from "./components/Inventory/DnsTab";
import type { TakeoverRecord } from "./components/Inventory/TakeoverTab";
import type { NormalizedUrlRecord } from "./components/Inventory/NormalizedUrlTab";
import type { GfUrlRecord } from "./components/Inventory/GfTab";
import { RelationshipGraph } from "./components/AssetGraph/RelationshipGraph";
import { ConsoleView } from "./components/JobConsole/ConsoleView";
import { SubdomainsTab } from "./components/Subdomains/SubdomainsTab";
import { apiCall, getWebSocketUrl } from "./services/api";
import { LayoutDashboard, Database, Network, RefreshCw, Sparkles, Globe2 } from "lucide-react";

interface Project {
  id: string;
  name: string;
  description?: string;
  seed_domains: string[];
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
}



let wsCount = 0;

type TabId = "dashboard" | "subdomains" | "inventory" | "visualizer";

interface ScanState {
  jobId: string | null;
  scanStatus: string | null;
  currentStage: string;
  stages: Record<string, "PENDING" | "RUNNING" | "COMPLETED" | "FAILED">;
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
  completedProviders: Set<string>;
  activeJobObject: any | null;
  lastCompletedJobObject: any | null;
  providerStatus: Record<string, "PENDING" | "RUNNING" | "COMPLETED" | "FAILED">;
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
    nuclei: "PENDING",
  },
  lastWsEventTime: 0,
};

const transitionToStage = (
  currentStages: Record<string, "PENDING" | "RUNNING" | "COMPLETED" | "FAILED">,
  newStage: string
): {
  currentStage: string;
  stages: Record<string, "PENDING" | "RUNNING" | "COMPLETED" | "FAILED">;
} => {
  const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei"];
  const targetIdx = PIPELINE_ORDER.indexOf(newStage.toLowerCase());
  
  if (targetIdx === -1) {
    if (newStage.toLowerCase() === "completed") {
      const nextStages = { ...currentStages };
      PIPELINE_ORDER.forEach((s) => {
        nextStages[s] = "COMPLETED";
      });
      return { currentStage: "completed", stages: nextStages };
    }
    return { currentStage: newStage, stages: currentStages };
  }

  const nextStages = { ...currentStages };
  PIPELINE_ORDER.forEach((stage, idx) => {
    if (idx < targetIdx) {
      nextStages[stage] = "COMPLETED";
    } else if (idx === targetIdx) {
      nextStages[stage] = "RUNNING";
    } else {
      nextStages[stage] = "PENDING";
    }
  });

  return { currentStage: newStage.toLowerCase(), stages: nextStages };
};

const updateProviderStatus = (
  current: Record<string, "PENDING" | "RUNNING" | "COMPLETED" | "FAILED">,
  provider: string,
  newStatus: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED"
): Record<string, "PENDING" | "RUNNING" | "COMPLETED" | "FAILED"> => {
  const p = provider.toLowerCase();
  const currentStatus = current[p];
  if (currentStatus === "COMPLETED") {
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
  const { token } = useAuth();
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
  const [loading, setLoading] = useState(true);
  const [isReconnect, setIsReconnect] = useState(false);

  const [scanState, setScanState] = useState<ScanState>(initialScanState);

  const activeProjectRef = useRef<Project | null>(null);
  const jobIdRef = useRef<string | null>(null);

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
    provider_counts: scanState.providerCounts,
    
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
    if (token) fetchProjects();
  }, [token]);

  const fetchProjectData = async () => {
    if (!activeProject) return;
    const projectId = activeProject.id;
    try {
      const [assetList, subdomainList, dashboardStats, jobsList] = await Promise.all([
        apiCall(`/assets/project/${projectId}`),
        apiCall(`/assets/project/${projectId}/subdomains`),
        apiCall(`/assets/project/${projectId}/dashboard-stats`),
        apiCall(`/jobs/project/${projectId}`),
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

      jobsList.forEach((job: any) => {
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
          });
        }
      });

      const originalUrls: { original_url: string; normalized_url: string; duplicate_removed: boolean; source: string }[] = [];

      assetList.forEach((asset: any) => {
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
        if (asset.metadata?.subzy) {
          const subzy = asset.metadata.subzy;
          if (!takeovers.some((r) => r.subdomain === asset.domain)) {
            takeovers.push({
              subdomain: asset.domain,
              provider: subzy.service || "",
              status: subzy.takeover_status || "Unknown",
              last_checked: subzy.checked_at,
            });
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

      const normalizedUrls: NormalizedUrlRecord[] = [];
      if (uro_normalised > 0) {
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

        const isWsActive = prev.jobId && (Date.now() - prev.lastWsEventTime < 10000);
        
        let nextStages = isWsActive ? prev.stages : { ...prev.stages };
        let nextProviderStatus = isWsActive ? prev.providerStatus : { ...prev.providerStatus };
        let nextCurrentStage = isWsActive ? prev.currentStage : prev.currentStage;

        if (!isWsActive && activeJobFromServer) {
          if (activeJobFromServer.status === "completed") {
            nextCurrentStage = "completed";
            const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei"];
            PIPELINE_ORDER.forEach((stage) => {
              nextStages[stage] = "COMPLETED";
              nextProviderStatus[stage] = "COMPLETED";
            });
            ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
              nextProviderStatus[sp] = "COMPLETED";
            });
          } else if (activeJobFromServer.status === "failed") {
            nextCurrentStage = "failed";
            const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei"];
            const jobPhase = (activeJobFromServer.current_phase || "waiting").toLowerCase();
            const currentIdx = PIPELINE_ORDER.indexOf(jobPhase);
            PIPELINE_ORDER.forEach((stage, idx) => {
              if (idx < currentIdx) {
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
            if (jobPhase === "discovery") {
              ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
                nextProviderStatus[sp] = "FAILED";
              });
            } else {
              ["subfinder", "assetfinder", "chaos", "amass"].forEach((sp) => {
                nextProviderStatus[sp] = "COMPLETED";
              });
            }
          } else {
            const jobPhase = activeJobFromServer.current_phase || "waiting";
            const transition = transitionToStage(prev.stages, jobPhase);
            nextStages = transition.stages;
            nextCurrentStage = transition.currentStage;
            
            const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei"];
            const currentIdx = PIPELINE_ORDER.indexOf(jobPhase.toLowerCase());
            PIPELINE_ORDER.forEach((stage, idx) => {
              if (idx < currentIdx) {
                nextProviderStatus[stage] = "COMPLETED";
              } else if (idx === currentIdx) {
                nextProviderStatus[stage] = activeJobFromServer.status === "paused" ? "RUNNING" : (activeJobFromServer.status === "stopped" ? "FAILED" : "RUNNING");
              } else {
                nextProviderStatus[stage] = "PENDING";
              }
            });
            if (jobPhase.toLowerCase() === "discovery") {
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

        return {
          ...prev,
          jobId: activeJobFromServer && ["running", "pending", "paused", "stopped"].includes(activeJobFromServer.status) ? activeJobFromServer.id : null,
          activeJobObject: activeJobFromServer || null,
          lastCompletedJobObject: lastCompletedJobFromServer,
          assets: assetList,
          subdomains: subdomainList,
          dnsRecords: dns,
          takeoverRecords: takeovers,
          normalizedUrlRecords: normalizedUrls,
          gfRecords: gf,
          stages: nextStages,
          currentStage: nextCurrentStage,
          providerStatus: nextProviderStatus,
          providerCounts: nextProviderCounts,
          dnsx_resolved: dns.length,
          dnsx_nxdomain: dnsx_nxdomain,
          dnsx_wildcards: dnsx_wildcards,
          dnsx_unique_ips: uniqueDnsxIps.size,
          subzy_vulnerable: takeovers.filter((r) => r.status.toLowerCase() === "vulnerable").length,
          subzy_not_vulnerable: subzy_not_vulnerable,
          subzy_unknown: subzy_unknown,
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
    setScanState(initialScanState);
    setIsReconnect(false);
    setActiveTab("dashboard");
    if (activeProject) {
      fetchProjectData();
    }
  }, [activeProject]);

  const handleLaunchScan = async (providerName: string) => {
    if (!activeProject) return;
    try {
      const job = await apiCall(
        `/jobs/project/${activeProject.id}/provider/${encodeURIComponent(providerName)}`,
        { method: "POST" }
      );
      setIsReconnect(false);
      setScanState((_prev) => {
        const transition = transitionToStage(initialScanState.stages, "discovery");
        return {
          ...initialScanState,
          jobId: job.id,
          activeJobObject: job,
          stages: transition.stages,
          currentStage: transition.currentStage,
          providerStatus: {
            ...initialScanState.providerStatus,
            discovery: "RUNNING",
          },
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

  const jobId = activeJob && ["running", "pending", "paused", "stopped"].includes(activeJob.status) ? activeJob.id : null;

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
                  if (incomingAsset.metadata?.subzy) {
                    const subzy = incomingAsset.metadata.subzy;
                    if (!nextTakeoverRecords.some((r) => r.subdomain === incomingAsset.domain)) {
                      nextTakeoverRecords = [...nextTakeoverRecords, {
                        subdomain: incomingAsset.domain,
                        provider: subzy.service || "",
                        status: (subzy.takeover_status || "Unknown") as any,
                        last_checked: subzy.checked_at,
                      }];
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
            } else if (data.type === "scan_summary") {
              if (data.provider) {
                setScanState((prev) => {
                  if (!activeProjectRef.current || activeProjectRef.current.id !== currentProjectId || jobIdRef.current !== currentJobId) {
                    return prev;
                  }
                  const providerName = data.provider.toLowerCase();
                  let nextStageData = transitionToStage(prev.stages, providerName);
                  let nextProviderStatus = updateProviderStatus(prev.providerStatus, providerName, "COMPLETED");
                  
                  const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei"];
                  const currentIdx = PIPELINE_ORDER.indexOf(providerName);
                  if (currentIdx !== -1 && currentIdx < PIPELINE_ORDER.length - 1) {
                    const nextStageName = PIPELINE_ORDER[currentIdx + 1];
                    nextStageData = transitionToStage(nextStageData.stages, nextStageName);
                    nextProviderStatus = updateProviderStatus(nextProviderStatus, nextStageName, "RUNNING");
                  } else if (currentIdx === PIPELINE_ORDER.length - 1) {
                    nextStageData = transitionToStage(nextStageData.stages, "completed");
                  }

                  let extraStats: Partial<ScanState> = {};
                  if (data.provider === "DNSx") {
                    extraStats = {
                      dnsx_resolved: data.resolved ?? prev.dnsx_resolved,
                      dnsx_nxdomain: data.nxdomain ?? prev.dnsx_nxdomain,
                      dnsx_wildcards: data.wildcards_filtered ?? prev.dnsx_wildcards,
                    };
                  } else if (data.provider === "Subzy") {
                    extraStats = {
                      subzy_vulnerable: data.vulnerable ?? prev.subzy_vulnerable,
                      subzy_not_vulnerable: data.not_vulnerable ?? prev.subzy_not_vulnerable,
                      subzy_unknown: data.unknown ?? prev.subzy_unknown,
                    };
                  } else if (data.provider === "Uro") {
                    extraStats = {
                      uro_input: data.input_urls ?? prev.uro_input,
                      uro_normalised: data.normalised_urls ?? prev.uro_normalised,
                      uro_removed: data.removed ?? prev.uro_removed,
                    };
                  } else if (data.provider === "GF") {
                    extraStats = {
                      gf_total: data.urls_classified ?? prev.gf_total,
                      gf_categories: data.matches_by_category
                        ? { ...prev.gf_categories, ...data.matches_by_category }
                        : prev.gf_categories,
                    };
                  }

                  return {
                    ...prev,
                    stages: nextStageData.stages,
                    currentStage: nextStageData.currentStage,
                    providerStatus: nextProviderStatus,
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
                    const PIPELINE_ORDER = ["discovery", "dnsx", "subzy", "naabu", "httpx", "katana", "uro", "gf", "nuclei"];
                    PIPELINE_ORDER.forEach((s) => {
                      nextProviderStatus[s] = data.status === "completed" ? "COMPLETED" : "FAILED";
                    });
                    isCleanClose = true;
                    if (ws) ws.close();
                  } else if (data.status === "stopped") {
                    nextStageData = { currentStage: "stopped", stages: prev.stages };
                    isCleanClose = true;
                    if (ws) ws.close();
                  }
                  
                  return {
                    ...prev,
                    activeJobObject: prev.activeJobObject ? { ...prev.activeJobObject, status: data.status } : null,
                    stages: nextStageData.stages,
                    currentStage: nextStageData.currentStage,
                    providerStatus: nextProviderStatus,
                    lastWsEventTime: Date.now(),
                  };
                });
                
                if (fetchProjectDataRef.current) {
                  fetchProjectDataRef.current();
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
                const subzyLineMatch = msg.match(/^\s*\[([!+?])\]\s+(\S+)\s+→\s+(\w[\w\s]*)/);
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
    { id: "subdomains", label: "Subdomains", icon: <Globe2 className="w-4 h-4" /> },
    { id: "inventory", label: "Asset Inventory", icon: <Database className="w-4 h-4" /> },
    { id: "visualizer", label: "Topology Visualizer", icon: <Network className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-dark-bg text-dark-text flex flex-col">
      <Navbar
        projects={projects}
        activeProject={activeProject}
        onSelectProject={setActiveProject}
        onRefreshProjects={fetchProjects}
      />

      {activeProject ? (
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {/* Navigation Tabs */}
          <div className="flex items-center justify-between border-b border-dark-border pb-1">
            <div className="flex space-x-1.5">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
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

            <button
              onClick={fetchProjectData}
              className="flex items-center space-x-1 px-3 py-1.5 bg-dark-card hover:bg-dark-hover border border-dark-border text-slate-400 hover:text-slate-200 rounded text-xs font-bold transition-all cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Sync Telemetry</span>
            </button>
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
              />
            )}

            {activeTab === "subdomains" && (
              <SubdomainsTab subdomains={subdomains} />
            )}

            {activeTab === "inventory" && (
              <AssetTable
                assets={assets}
                projectName={activeProject?.name}
                dnsRecords={dnsRecords}
                takeoverRecords={takeoverRecords}
                normalizedUrlRecords={normalizedUrlRecords}
                gfRecords={gfRecords}
              />
            )}

            {activeTab === "visualizer" && (
              <RelationshipGraph
                assets={assets}
                seedDomains={activeProject.seed_domains}
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

const AppContent: React.FC = () => {
  const { token } = useAuth();
  return token ? <MainDashboard /> : <AuthPage />;
};

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
