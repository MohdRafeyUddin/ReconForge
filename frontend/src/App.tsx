import React, { useState, useEffect } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { AuthPage } from "./components/Auth/AuthPage";
import { Navbar } from "./components/Common/Navbar";
import { OverviewDashboard } from "./components/Dashboard/OverviewDashboard";
import { AssetTable } from "./components/Inventory/AssetTable";
import { RelationshipGraph } from "./components/AssetGraph/RelationshipGraph";
import { ConsoleView } from "./components/JobConsole/ConsoleView";
import { SubdomainsTab } from "./components/Subdomains/SubdomainsTab";
import { apiCall } from "./services/api";
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

type TabId = "dashboard" | "subdomains" | "inventory" | "visualizer";

const MainDashboard: React.FC = () => {
  const { token } = useAuth();
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [assets, setAssets] = useState<any[]>([]);
  const [subdomains, setSubdomains] = useState<any[]>([]);
  const [stats, setStats] = useState<DashboardStats>(defaultStats);
  const [activeJob, setActiveJob] = useState<any | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("dashboard");
  const [loading, setLoading] = useState(true);

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
      const [assetList, subdomainList, dashboardStats] = await Promise.all([
        apiCall(`/assets/project/${activeProject.id}`),
        apiCall(`/assets/project/${activeProject.id}/subdomains`),
        apiCall(`/assets/project/${activeProject.id}/dashboard-stats`),
      ]);
      setAssets(assetList);
      setSubdomains(subdomainList);
      setStats(dashboardStats);
    } catch (err) {
      console.error("Failed to load project details", err);
    }
  };

  useEffect(() => {
    if (activeProject) {
      fetchProjectData();
    } else {
      setAssets([]);
      setSubdomains([]);
      setStats(defaultStats);
    }
  }, [activeProject]);

  const handleLaunchScan = async (providerName: string) => {
    if (!activeProject) return;
    try {
      const job = await apiCall(
        `/jobs/project/${activeProject.id}/provider/${encodeURIComponent(providerName)}`,
        { method: "POST" }
      );
      setActiveJob(job);
    } catch (err) {
      console.error("Failed to trigger scan", err);
      alert(`Scan launch error: ${err instanceof Error ? err.message : "Internal Server Error"}`);
    }
  };

  // Poll active job and refresh data on completion
  useEffect(() => {
    if (!activeJob) return;
    const interval = setInterval(async () => {
      try {
        const statusData = await apiCall(`/jobs/${activeJob.id}`);
        if (statusData.status === "completed" || statusData.status === "failed") {
          clearInterval(interval);
          fetchProjectData();
        }
      } catch (err) {
        console.error("Error checking scan job status", err);
      }
    }, 4000);
    return () => clearInterval(interval);
  }, [activeJob]);

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
                activeProject={activeProject}
                onLaunchScan={handleLaunchScan}
                onRefresh={fetchProjectData}
              />
            )}

            {activeTab === "subdomains" && (
              <SubdomainsTab subdomains={subdomains} />
            )}

            {activeTab === "inventory" && (
              <AssetTable assets={assets} />
            )}

            {activeTab === "visualizer" && (
              <RelationshipGraph
                assets={assets}
                seedDomains={activeProject.seed_domains}
              />
            )}
          </div>

          {/* Floating console overlay */}
          {activeJob && (
            <div className="mt-8 pt-4 border-t border-dark-border">
              <ConsoleView
                activeJob={activeJob}
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
