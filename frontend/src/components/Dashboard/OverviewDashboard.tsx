import React, { useEffect, useState } from "react";
import { StatCard } from "./StatCard";
import { Globe, Server, Radio, ShieldAlert, Play, RefreshCw, FileText } from "lucide-react";
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
}

interface Project {
  id: string;
  name: string;
  description?: string;
  seed_domains: string[];
}

interface OverviewDashboardProps {
  stats: DashboardStats;
  activeProject: Project;
  onLaunchScan: (providerName: string) => void;
  onRefresh: () => void;
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
  activeProject,
  onLaunchScan,
  onRefresh
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

  const pc = stats.provider_counts ?? {};
  const providerBreakdown = [
    { label: "Subfinder", count: pc.subfinder ?? 0, color: "#3B82F6" },
    { label: "Assetfinder", count: pc.assetfinder ?? 0, color: "#06B6D4" },
    { label: "Amass", count: pc.amass ?? 0, color: "#10B981" },
    { label: "Chaos", count: pc.chaos ?? 0, color: "#F59E0B" },
  ];

  return (
    <div className="space-y-6">
      {/* Upper stats row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard
          title="Total Domains/Assets"
          value={stats.total_assets}
          subtext="Total unique targets discovered"
          icon={<Globe className="w-6 h-6" />}
          colorClass="text-cyber-primary"
          glowClass="glow-blue"
        />
        <StatCard
          title="Discovered Subdomains"
          value={stats.total_subdomains}
          subtext="Target child hosts mapped"
          icon={<Server className="w-6 h-6" />}
          colorClass="text-cyber-accent"
          glowClass="glow-cyan"
        />
        <StatCard
          title="Live Probed Hosts"
          value={stats.live_hosts}
          subtext="Hosts responding to requests"
          icon={<Radio className="w-6 h-6 animate-pulse" />}
          colorClass="text-cyber-success"
          glowClass="glow-cyan"
        />
        <StatCard
          title="Exposed Open Ports"
          value={stats.open_ports_count}
          subtext="Unique ports with active services"
          icon={<ShieldAlert className="w-6 h-6" />}
          colorClass="text-cyber-danger"
          glowClass="glow-blue"
        />
      </div>

      {/* Provider Yield Breakdown */}
      {providerBreakdown.some(p => p.count > 0) && (
        <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
          <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4 border-b border-dark-border pb-2">
            Provider Yield Breakdown
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {providerBreakdown.map((p) => (
              <div key={p.label} className="bg-dark-bg border border-dark-border rounded-lg p-3 flex flex-col items-center text-center">
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1">{p.label}</span>
                <span className="text-2xl font-mono font-bold" style={{ color: p.color }}>{p.count}</span>
                <span className="text-[9px] text-slate-600 mt-1">subdomains found</span>
              </div>
            ))}
          </div>
        </div>
      )}

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
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block mb-1">LAST SCAN OPERATION</span>
                <span className="text-slate-300 text-xs font-mono">
                  {stats.last_scan_time ? new Date(stats.last_scan_time).toLocaleString() : "Never Scanned"}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-8 pt-4 border-t border-dark-border space-y-4">
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

            <button
              onClick={handleExportHTML}
              disabled={generatingReport}
              className="w-full bg-dark-bg border border-dark-border hover:border-cyber-accent/50 text-slate-300 hover:text-white py-2.5 rounded text-xs font-bold uppercase tracking-wider transition-all flex items-center justify-center space-x-2 cursor-pointer"
            >
              {generatingReport ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <FileText className="w-4 h-4" />
              )}
              <span>Export Audit Report</span>
            </button>
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
                {stats.ports_distribution.length === 0 ? (
                  <div className="h-full flex items-center justify-center text-xs text-slate-500 uppercase tracking-widest font-mono">
                    No Port Data Discovered
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={stats.ports_distribution}>
                      <XAxis dataKey="port" stroke="#6B7280" fontSize={11} tickLine={false} />
                      <YAxis stroke="#6B7280" fontSize={11} tickLine={false} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{ backgroundColor: "#111622", borderColor: "#1E2638", color: "#F3F4F6", borderRadius: "6px" }}
                        labelFormatter={(label) => `Port ${label}`}
                      />
                      <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]}>
                        {stats.ports_distribution.map((_, index) => (
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
                  {stats.sources_distribution.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-xs text-slate-500 uppercase tracking-widest font-mono">
                      No Yield Data Available
                    </div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={stats.sources_distribution}
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={70}
                          paddingAngle={5}
                          dataKey="value"
                        >
                          {stats.sources_distribution.map((_, index) => (
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
                  {stats.sources_distribution.map((entry, index) => (
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
