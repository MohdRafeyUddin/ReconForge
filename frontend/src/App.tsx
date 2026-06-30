import React, { useState, useEffect, useRef } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { AuthPage } from "./components/Auth/AuthPage";
import { Navbar } from "./components/Common/Navbar";
import { OverviewDashboard } from "./components/Dashboard/OverviewDashboard";
import { AssetTable } from "./components/Inventory/AssetTable";
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
  ports_distribution: { port: number; count: number }[];
  sources_distribution: { name: string; value: number }[];
  provider_counts?: {
    subfinder?: number;
    assetfinder?: number;
    amass?: number;
    chaos?: number;
  };
}

const defaultStats: DashboardStats = {
  total_assets: 0,
  total_subdomains: 0,
  live_hosts: 0,
  open_ports_count: 0,
  last_scan_time: null,
  ports_distribution: [],
  sources_distribution: [],
  provider_counts: {},
};

const updateStatsFromAssets = (currentAssets: any[], currentSubdomains: any[], currentStats: DashboardStats): DashboardStats => {
  const total_assets = currentAssets.length;
  const total_subdomains = currentSubdomains.length;
  const live_hosts = currentAssets.filter(a => a.status === "live").length;
  
  // Recompute ports distribution
  const portCounts: Record<number, number> = {};
  currentAssets.forEach(a => {
    (a.open_ports || []).forEach((p: number) => {
      portCounts[p] = (portCounts[p] || 0) + 1;
    });
  });
  const ports_distribution = Object.entries(portCounts).map(([port, count]) => ({
    port: parseInt(port),
    count: count as number
  })).sort((a, b) => b.count - a.count);
  const open_ports_count = ports_distribution.length;

  // Recompute provider_counts from the sources array of each asset
  const providers = ["subfinder", "assetfinder", "amass", "chaos"];
  const provider_counts: Record<string, number> = {};
  providers.forEach(p => {
    provider_counts[p] = currentAssets.filter(a => (a.sources || []).includes(p)).length;
  });

  // Recompute sources_distribution
  const sourceGroups: Record<string, number> = {};
  currentAssets.forEach(a => {
    const src = a.discovered_by || "unknown";
    sourceGroups[src] = (sourceGroups[src] || 0) + 1;
  });
  const sources_distribution = Object.entries(sourceGroups).map(([name, value]) => ({
    name,
    value: value as number
  }));

  return {
    ...currentStats,
    total_assets,
    total_subdomains,
    live_hosts,
    open_ports_count,
    ports_distribution,
    sources_distribution,
    provider_counts
  };
};

let wsCount = 0;

type TabId = "dashboard" | "subdomains" | "inventory" | "visualizer";

const MainDashboard: React.FC = () => {
  const { token } = useAuth();
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [assets, setAssets] = useState<any[]>([]);
  const [subdomains, setSubdomains] = useState<any[]>([]);
  const [stats, setStats] = useState<DashboardStats>(defaultStats);
  const [activeJob, setActiveJob] = useState<any | null>(null);
  const [completedProviders, setCompletedProviders] = useState<Set<string>>(new Set());
  const [currentPhase, setCurrentPhase] = useState<string>("waiting");
  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
  const [loading, setLoading] = useState(true);
  const [isReconnect, setIsReconnect] = useState(false);

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
    try {
      const [assetList, subdomainList, dashboardStats, jobsList] = await Promise.all([
        apiCall(`/assets/project/${activeProject.id}`),
        apiCall(`/assets/project/${activeProject.id}/subdomains`),
        apiCall(`/assets/project/${activeProject.id}/dashboard-stats`),
        apiCall(`/jobs/project/${activeProject.id}`),
      ]);
      setAssets(assetList);
      setSubdomains(subdomainList);
      setStats(dashboardStats);

      if (!activeJob) {
        const runningJob = jobsList.find((j: any) => j.status === "running" || j.status === "pending");
        if (runningJob) {
          setIsReconnect(true);
          setActiveJob(runningJob);
          setCompletedProviders(new Set());
          setCurrentPhase(runningJob.status === "pending" ? "waiting" : "discovery");
        }
      }
    } catch (err) {
      console.error("Failed to load project details", err);
    }
  };

  useEffect(() => {
    fetchProjectDataRef.current = fetchProjectData;
  }, [fetchProjectData]);

  useEffect(() => {
    if (activeProject) {
      fetchProjectData();
    } else {
      setAssets([]);
      setSubdomains([]);
      setStats(defaultStats);
      setActiveJob(null);
      setCompletedProviders(new Set());
      setCurrentPhase("waiting");
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
      setCompletedProviders(new Set());
      setCurrentPhase(job.status === "pending" ? "waiting" : "discovery");
      setActiveJob(job);
    } catch (err) {
      console.error("Failed to trigger scan", err);
      alert(`Scan launch error: ${err instanceof Error ? err.message : "Internal Server Error"}`);
    }
  };

  const handlePauseScan = async () => {
    if (!activeJob) return;
    try {
      await apiCall(`/jobs/${activeJob.id}/pause`, { method: "POST" });
      setActiveJob((prev: any) => prev ? { ...prev, status: "paused" } : null);
    } catch (err) {
      console.error("Failed to pause scan", err);
    }
  };

  const handleResumeScan = async () => {
    if (!activeJob) return;
    try {
      await apiCall(`/jobs/${activeJob.id}/resume`, { method: "POST" });
      setActiveJob((prev: any) => prev ? { ...prev, status: "running" } : null);
    } catch (err) {
      console.error("Failed to resume scan", err);
    }
  };

  const handleStopScan = async () => {
    if (!activeJob) return;
    try {
      await apiCall(`/jobs/${activeJob.id}/stop`, { method: "POST" });
      setActiveJob((prev: any) => prev ? { ...prev, status: "stopped" } : null);
      setCurrentPhase("stopped");
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
      setActiveJob(null);
      setAssets([]);
      setSubdomains([]);
      setStats(defaultStats);
      setCompletedProviders(new Set());
      setCurrentPhase("waiting");
      if (wsRef.current) {
        (wsRef.current as any).isCleanClose = true;
        wsRef.current.close();
        wsRef.current = null;
      }
    } catch (err) {
      console.error("Failed to reset scan", err);
    }
  };

  const jobId = activeJob?.id;

  // Listen to WebSocket broadcasts for real-time asset updates
  useEffect(() => {
    if (!jobId) return;

    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;
    let reconnectDelay = 1000;
    const maxReconnectDelay = 30000;
    let isClosed = false;
    let isCleanClose = false;

    const connect = () => {
      if (isClosed || isCleanClose) return;

      const wsUrl = getWebSocketUrl(`/jobs/ws/${jobId}`);
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      
      wsCount++;
      console.log("WebSocket opened", { jobId, currentWebsocketCount: wsCount });
      console.log("Current websocket count:", wsCount);

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          console.log("WebSocket event received", { jobId, type: data.type });

          if (data.type === "asset_discovered" || data.type === "asset") {
            const incomingAsset = data.asset || data.data;
            if (incomingAsset && incomingAsset.domain) {
              setAssets((prevAssets) => {
                const exists = prevAssets.some(
                  (a) => a.id === incomingAsset.id || a.domain === incomingAsset.domain
                );
                let nextAssets;
                if (exists) {
                  nextAssets = prevAssets.map((a) =>
                    a.id === incomingAsset.id || a.domain === incomingAsset.domain ? incomingAsset : a
                  );
                } else {
                  nextAssets = [...prevAssets, incomingAsset];
                }

                // Also update subdomains and stats relative to the new assets list
                setSubdomains((prevSubs) => {
                  let nextSubs = prevSubs;
                  if (incomingAsset.type === "subdomain") {
                    const subExists = prevSubs.some(
                      (s) => s.id === incomingAsset.id || s.domain === incomingAsset.domain
                    );
                    if (subExists) {
                      nextSubs = prevSubs.map((s) =>
                        s.id === incomingAsset.id || s.domain === incomingAsset.domain ? incomingAsset : s
                      );
                    } else {
                      nextSubs = [...prevSubs, incomingAsset];
                    }
                  }
                  
                  // Update stats based on the updated lists
                  setStats((prevStats) => updateStatsFromAssets(nextAssets, nextSubs, prevStats));
                  return nextSubs;
                });

                return nextAssets;
              });
            }
          } else if (data.type === "provider_stat") {
            const { provider, count } = data;
            setCompletedProviders((prev) => {
              const next = new Set(prev);
              next.add(provider);
              return next;
            });
            setStats((prevStats) => ({
              ...prevStats,
              provider_counts: {
                ...prevStats.provider_counts,
                [provider]: count,
              },
            }));
          } else if (data.type === "scan_summary") {
            if (data.provider) {
              if (data.provider === "Httpx") {
                setCurrentPhase("naabu");
              } else if (data.provider === "Naabu") {
                setCurrentPhase("katana");
              } else if (data.provider === "Katana") {
                setCurrentPhase("nuclei");
              } else if (data.provider === "Nuclei") {
                setCurrentPhase("completed");
              }
            } else if (data.provider_counts || data.total_unique !== undefined) {
              setStats((prevStats) => ({
                ...prevStats,
                total_assets: data.total_unique !== undefined ? data.total_unique : prevStats.total_assets,
                total_subdomains: data.total_unique !== undefined ? data.total_unique : prevStats.total_subdomains,
                live_hosts: data.live_hosts !== undefined ? data.live_hosts : prevStats.live_hosts,
                provider_counts: data.provider_counts ? {
                  subfinder: data.provider_counts.subfinder,
                  assetfinder: data.provider_counts.assetfinder,
                  amass: data.provider_counts.amass,
                  chaos: data.provider_counts.chaos,
                } : prevStats.provider_counts,
              }));
            }
          } else if (data.type === "status") {
            if (data.status === "idle") {
              setActiveJob(null);
              setAssets([]);
              setSubdomains([]);
              setStats(defaultStats);
              setCompletedProviders(new Set());
              setCurrentPhase("waiting");
              isCleanClose = true;
              if (ws) ws.close();
            } else {
              setActiveJob((prev: any) => prev ? { ...prev, status: data.status } : null);
              if (data.status === "completed" || data.status === "failed") {
                setCurrentPhase("completed");
                isCleanClose = true;
                if (ws) ws.close();
              } else if (data.status === "stopped") {
                setCurrentPhase("stopped");
                isCleanClose = true;
                if (ws) ws.close();
              }
              if (fetchProjectDataRef.current) {
                fetchProjectDataRef.current();
              }
            }
          } else if (data.type === "log" && data.message) {
            const msg = data.message;
            const lowerMsg = msg.toLowerCase();
            
            // Reconstruct completed providers from logs
            const providersList = ["subfinder", "assetfinder", "amass", "chaos"];
            providersList.forEach((p) => {
              if (lowerMsg.includes(p) && (lowerMsg.includes("completed") || lowerMsg.includes("finished"))) {
                setCompletedProviders((prev) => {
                  const next = new Set(prev);
                  next.add(p);
                  return next;
                });
              }
            });

            // Determine phase progression from logs
            if (lowerMsg.includes("starting httpx") || lowerMsg.includes("launching httpx") || lowerMsg.includes("httpx probing")) {
              setCurrentPhase("httpx");
            } else if (lowerMsg.includes("starting naabu") || lowerMsg.includes("launching naabu") || lowerMsg.includes("naabu port scan")) {
              setCurrentPhase("naabu");
            } else if (lowerMsg.includes("starting katana") || lowerMsg.includes("launching katana") || lowerMsg.includes("katana web crawl") || lowerMsg.includes("starting crawl session")) {
              setCurrentPhase("katana");
            } else if (lowerMsg.includes("starting nuclei") || lowerMsg.includes("launching nuclei") || lowerMsg.includes("nuclei vuln scan")) {
              setCurrentPhase("nuclei");
            }
          }
        } catch (err) {
          console.error("Dashboard WS parse error", err);
        }
      };

      ws.onerror = (err) => {
        console.error("Dashboard WS connection error", err);
      };

      ws.onclose = (event) => {
        if (!isClosed) {
          isClosed = true;
          wsCount--;
          console.log("WebSocket closed", { jobId, currentWebsocketCount: wsCount });
          console.log("Current websocket count:", wsCount);
        }

        // Only reconnect if it's not a clean close (job ended / manual stop) or explicit request
        const wsInstCleanClose = (event.target as any).isCleanClose || isCleanClose;
        if (!wsInstCleanClose) {
          console.log("WebSocket reconnect", { jobId, delay: reconnectDelay });
          reconnectTimeout = setTimeout(() => {
            reconnectDelay = Math.min(reconnectDelay * 2, maxReconnectDelay);
            isClosed = false;
            // Fetch project data upon reconnecting to catch up on missed state changes
            if (fetchProjectDataRef.current) {
              fetchProjectDataRef.current();
            }
            connect();
          }, reconnectDelay);
        }
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
  }, [jobId]);

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
              />
            )}

            {activeTab === "subdomains" && (
              <SubdomainsTab subdomains={subdomains} />
            )}

            {activeTab === "inventory" && (
              <AssetTable assets={assets} projectName={activeProject?.name} />
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
                onClose={() => setActiveJob(null)}
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
