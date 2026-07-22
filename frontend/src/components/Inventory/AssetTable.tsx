import React, { useState } from "react";
import { Search, Filter, Copy, ChevronDown, ChevronUp } from "lucide-react";
import { DnsTab } from "./DnsTab";
import type { DnsRecord } from "./DnsTab";
import { TakeoverTab } from "./TakeoverTab";
import type { TakeoverRecord } from "./TakeoverTab";
import { NormalizedUrlTab } from "./NormalizedUrlTab";
import type { NormalizedUrlRecord } from "./NormalizedUrlTab";
import { GfTab } from "./GfTab";
import type { GfUrlRecord } from "./GfTab";
import { NucleiTab } from "./NucleiTab";

const getRootDomain = (domain: string): string => {
  const parts = domain.split(".");
  if (parts.length <= 2) return domain;
  return parts.slice(-2).join(".");
};

const escapeCSV = (val: any) => {
  if (val === null || val === undefined) return '""';
  let str = String(val);
  str = str.replace(/"/g, '""');
  return `"${str}"`;
};

interface Asset {
  id: string;
  domain: string;
  type: string;
  status: string;
  open_ports: number[];
  metadata: Record<string, any>;
  discovered_by: string;
  created_at: string;
  updated_at?: string;
  sources?: string[];
  risk?: any;
}

interface AssetTableProps {
  assets: Asset[];
  projectName?: string;
  dnsRecords?: DnsRecord[];
  takeoverRecords?: TakeoverRecord[];
  normalizedUrlRecords?: NormalizedUrlRecord[];
  gfRecords?: GfUrlRecord[];
  initialTab?: "assets" | "dns" | "takeovers" | "normalized_urls" | "gf" | "nuclei" | "historical_urls" | "js_files" | "screenshots";
  initialSeverityFilter?: string | null;
}

type InventoryTab = "assets" | "dns" | "takeovers" | "normalized_urls" | "gf" | "nuclei" | "historical_urls" | "js_files" | "screenshots";

export const AssetTable: React.FC<AssetTableProps> = ({
  assets,
  projectName = "project",
  dnsRecords = [],
  takeoverRecords = [],
  normalizedUrlRecords = [],
  gfRecords = [],
  initialTab,
  initialSeverityFilter = null,
}) => {
  const [activeInventoryTab, setActiveInventoryTab] = useState<InventoryTab>(initialTab || "assets");
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [activeTabs, setActiveTabs] = useState<Record<string, string>>({});
  const [showExportDropdown, setShowExportDropdown] = useState(false);

  React.useEffect(() => {
    if (initialTab) {
      setActiveInventoryTab(initialTab);
    }
  }, [initialTab]);

  const handleExportFullInventory = () => {
    const headers = [
      "Subdomain", "Root Domain", "Provider", "Status", "Live URL",
      "HTTP Status", "IP Address", "Technologies", "Title", "Open Ports",
      "Port Count", "Katana URLs", "JavaScript Files", "Forms", "Parameters",
      "Nuclei Findings", "Discovery Source", "Discovery Time", "Last Seen"
    ];

    const rows = assets.map(asset => {
      const subdomain = asset.domain;
      const rootDomain = getRootDomain(subdomain);
      const provider = asset.discovered_by || "unknown";
      const status = asset.status;
      const liveUrl = asset.metadata?.url || "";
      const httpStatus = asset.metadata?.status_code !== undefined ? asset.metadata.status_code : "";
      const ipAddress = asset.metadata?.ip_address || "";
      const technologies = (asset.metadata?.technologies || []).join("; ");
      const title = asset.metadata?.title || "";
      const openPorts = (asset.open_ports || []).join("; ");
      const portCount = asset.open_ports?.length ?? 0;
      const katanaUrls = (asset.metadata?.katana?.endpoints || []).join("; ");
      const jsFiles = (asset.metadata?.katana?.js_files || []).join("; ");
      const forms = (asset.metadata?.katana?.forms || []).map((f: any) => typeof f === "string" ? f : (f.action || "")).join("; ");
      const parameters = (asset.metadata?.katana?.forms || []).flatMap((f: any) => typeof f === "string" ? [] : (f.fields || []).map((fld: any) => fld.name)).join("; ");
      const nucleiFindings = (asset.metadata?.nuclei?.findings || []).map((f: any) => `[${f.severity}] ${f.name || f.template_id}`).join("; ");
      const discoverySource = (asset.sources || []).join("; ") || asset.discovered_by || "unknown";
      const discoveryTime = asset.created_at || (asset as any).first_seen || "";
      const lastSeen = (asset as any).last_seen || "";

      return [
        subdomain, rootDomain, provider, status, liveUrl,
        httpStatus, ipAddress, technologies, title, openPorts,
        portCount, katanaUrls, jsFiles, forms, parameters,
        nucleiFindings, discoverySource, discoveryTime, lastSeen
      ];
    });

    const csvContent = [headers, ...rows]
      .map(row => row.map(escapeCSV).join(","))
      .join("\r\n");

    const blob = new Blob(["\uFEFF" + csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reconforge_full_export_${projectName.toLowerCase()}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportSubdomainsAndUrls = () => {
    const headers = ["Subdomain", "URL"];
    const rows = assets.map(asset => {
      const subdomain = asset.domain;
      const liveUrl = asset.status === "live" ? (asset.metadata?.url || `http://${asset.domain}`) : "";
      return [subdomain, liveUrl];
    });

    const csvContent = [headers, ...rows]
      .map(row => row.map(escapeCSV).join(","))
      .join("\r\n");

    const blob = new Blob(["\uFEFF" + csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "subdomains_and_urls.csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const setAssetTab = (assetId: string, tab: string) => {
    setActiveTabs(prev => ({ ...prev, [assetId]: tab }));
  };

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const filteredAssets = assets.filter((asset) => {
    if (["js_file", "screenshot", "finding", "historical_url"].includes(asset.type)) {
      return false;
    }
    const matchesSearch = asset.domain.toLowerCase().includes(search.toLowerCase()) ||
      (asset.metadata && asset.metadata.ip_address && asset.metadata.ip_address.includes(search));
    const matchesType = filterType === "all" || asset.type === filterType;
    const matchesStatus = filterStatus === "all" || asset.status === filterStatus;
    
    return matchesSearch && matchesType && matchesStatus;
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const displayedNormalizedUrls = React.useMemo(() => {
    const uroUrls = normalizedUrlRecords.filter(r => r.source === "uro");
    if (uroUrls.length > 0) {
      return uroUrls;
    }
    return normalizedUrlRecords.filter(r => r.source === "katana" || r.source === "httpx");
  }, [normalizedUrlRecords]);

  const gfTotalCount = React.useMemo(() => {
    let total = 0;
    gfRecords.forEach((r) => {
      r.categories.forEach((cat) => {
        const lower = cat.toLowerCase();
        if (["xss", "sqli", "ssrf", "redirect", "lfi", "rce", "idor", "ssti", "debug", "upload", "aws", "graphql"].includes(lower)) {
          total++;
        }
      });
    });
    return total;
  }, [gfRecords]);

  const nucleiFindings = React.useMemo(() => {
    const findingsList: any[] = [];
    const seen = new Set<string>();
    assets.forEach((asset) => {
      const findings = asset.metadata?.nuclei?.findings || [];
      findings.forEach((f: any) => {
        const key = `${f.template_id || f.template || "unknown"}:${f.matched_url || f.endpoint || ""}`;
        if (!seen.has(key)) {
          seen.add(key);
          findingsList.push({
            ...f,
            severity: f.severity || "info",
            template: f.template || f.template_id || "unknown",
            template_id: f.template_id || f.template || "unknown",
            template_name: f.template_name || f.name || f.template || "unknown",
            matched_url: f.matched_url || f.endpoint || "",
            endpoint: f.endpoint || f.matched_url || "",
            host: f.host || asset.domain,
            tags: f.tags || [],
            cve: f.cve || "",
            timestamp: f.timestamp || asset.updated_at || new Date().toISOString(),
            pass_name: f.pass_name || "",
            source: f.source || "nuclei",
          });
        }
      });

      if (asset.type === "finding") {
        const meta = asset.metadata || {};
        const key = `flat:${meta.source || "unknown"}:${meta.matched_url || ""}`;
        if (!seen.has(key)) {
          seen.add(key);
          findingsList.push({
            severity: meta.severity || "info",
            template: (meta.source || "unknown").toUpperCase(),
            template_id: meta.source || "unknown",
            template_name: meta.source ? `${meta.source.toUpperCase()} Confirmed Finding` : "Vulnerability",
            matched_url: meta.matched_url || "",
            endpoint: meta.matched_url || "",
            host: meta.host || asset.domain,
            tags: meta.tags || [],
            cve: meta.cve || "",
            timestamp: meta.timestamp || asset.created_at || new Date().toISOString(),
            pass_name: "",
            source: meta.source || "unknown",
            payload: meta.payload || "",
            parameter: meta.parameter || "",
            evidence: meta.evidence || "",
            metadata: meta
          });
        }
      }
    });
    return findingsList;
  }, [assets]);

  const historicalUrls = React.useMemo(() => {
    return assets.filter(a => a.type === "historical_url").map(a => ({
      url: a.domain,
      source: a.metadata?.source || a.discovered_by || "unknown",
      sources: a.metadata?.sources || a.sources || [],
      has_params: a.metadata?.has_params || false,
      extension: a.metadata?.extension || "",
      timestamp: a.created_at || a.metadata?.discovered_at
    }));
  }, [assets]);

  const javascriptFiles = React.useMemo(() => {
    return assets.filter(a => a.type === "js_file").map(a => ({
      url: a.domain,
      host: a.metadata?.host || "",
      size: a.metadata?.size || "unknown",
      source: a.metadata?.source || a.discovered_by || "subjs"
    }));
  }, [assets]);

  const screenshotsList = React.useMemo(() => {
    return assets.filter(a => a.type === "screenshot").map(a => ({
      url: a.domain,
      title: a.metadata?.title || "",
      screenshot_path: a.metadata?.screenshot_path || "",
      timestamp: a.metadata?.timestamp || a.created_at,
      source: a.metadata?.source || "gowitness"
    }));
  }, [assets]);

  const inventoryTabs: { id: InventoryTab; label: string; count?: number }[] = [
    { id: "assets", label: "Assets", count: filteredAssets.length },
    { id: "dns", label: "DNS", count: dnsRecords.length },
    { id: "takeovers", label: "Takeovers", count: takeoverRecords.length },
    { id: "normalized_urls", label: "Normalized URLs", count: displayedNormalizedUrls.length },
    { id: "gf", label: "Interesting URLs", count: gfTotalCount },
    { id: "nuclei", label: "Security Findings", count: nucleiFindings.length },
    { id: "historical_urls", label: "Historical URLs", count: historicalUrls.length },
    { id: "js_files", label: "JS Files", count: javascriptFiles.length },
    { id: "screenshots", label: "Screenshots", count: screenshotsList.length },
  ];

  return (
    <div className="space-y-4">
      {/* Sub-tab navigation */}
      <div className="flex items-center gap-1.5 border-b border-dark-border pb-1 overflow-x-auto">
        {inventoryTabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveInventoryTab(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-t text-xs font-bold uppercase tracking-wider transition-all cursor-pointer whitespace-nowrap ${
              activeInventoryTab === tab.id
                ? "bg-dark-card border-t border-x border-dark-border text-cyber-accent"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className="px-1.5 py-0.5 bg-cyber-accent/20 border border-cyber-accent/40 text-cyber-accent rounded text-[9px] font-bold">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* DNS Tab */}
      {activeInventoryTab === "dns" && (
        <DnsTab records={dnsRecords} projectName={projectName} />
      )}

      {/* Takeovers Tab */}
      {activeInventoryTab === "takeovers" && (
        <TakeoverTab records={takeoverRecords} projectName={projectName} />
      )}

      {/* Normalized URLs Tab */}
      {activeInventoryTab === "normalized_urls" && (
        <NormalizedUrlTab records={displayedNormalizedUrls} projectName={projectName} />
      )}

      {/* GF Interesting URLs Tab */}
      {activeInventoryTab === "gf" && (
        <GfTab records={gfRecords} projectName={projectName} />
      )}

      {/* Security Findings Tab */}
      {activeInventoryTab === "nuclei" && (
        <NucleiTab
          findings={nucleiFindings}
          projectName={projectName}
          initialSeverityFilter={initialSeverityFilter}
        />
      )}

      {/* Historical URLs Tab */}
      {activeInventoryTab === "historical_urls" && (
        <div className="bg-dark-card border border-dark-border rounded-xl glass p-4">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-cyber-accent">Historical URL Inventory</h3>
            <span className="text-[10px] font-mono text-slate-500">{historicalUrls.length} total entries</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="p-3">URL</th>
                  <th className="p-3">Parameters</th>
                  <th className="p-3">Extension</th>
                  <th className="p-3">Sources</th>
                </tr>
              </thead>
              <tbody>
                {historicalUrls.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-6 text-center text-slate-500 uppercase tracking-widest font-mono text-[10px]">
                      No historical URLs discovered yet.
                    </td>
                  </tr>
                ) : (
                  historicalUrls.map((urlObj, idx) => (
                    <tr key={idx} className="border-b border-dark-border/50 hover:bg-dark-hover/30 transition-colors font-mono text-[11px]">
                      <td className="p-3 break-all select-all text-slate-300">{urlObj.url}</td>
                      <td className="p-3">
                        {urlObj.has_params ? (
                          <span className="px-1.5 py-0.5 bg-yellow-500/20 border border-yellow-500/40 text-yellow-400 rounded text-[9px] font-bold">
                            YES
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 bg-slate-500/10 border border-slate-500/25 text-slate-500 rounded text-[9px]">
                            NO
                          </span>
                        )}
                      </td>
                      <td className="p-3">
                        {urlObj.extension ? (
                          <span className="px-1.5 py-0.5 bg-cyber-accent/20 border border-cyber-accent/40 text-cyber-accent rounded text-[9px] font-bold uppercase">
                            {urlObj.extension}
                          </span>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {urlObj.sources.map((src: string) => (
                            <span key={src} className="px-1.5 py-0.5 bg-blue-500/15 border border-blue-500/35 text-blue-400 rounded text-[9px] uppercase font-semibold">
                              {src}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* JavaScript Files Tab */}
      {activeInventoryTab === "js_files" && (
        <div className="bg-dark-card border border-dark-border rounded-xl glass p-4">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-cyber-accent">JavaScript File Inventory</h3>
            <span className="text-[10px] font-mono text-slate-500">{javascriptFiles.length} total files</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="p-3">JS File URL</th>
                  <th className="p-3">Target Host</th>
                  <th className="p-3">Source</th>
                </tr>
              </thead>
              <tbody>
                {javascriptFiles.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="p-6 text-center text-slate-500 uppercase tracking-widest font-mono text-[10px]">
                      No JavaScript files discovered yet.
                    </td>
                  </tr>
                ) : (
                  javascriptFiles.map((jsObj, idx) => (
                    <tr key={idx} className="border-b border-dark-border/50 hover:bg-dark-hover/30 transition-colors font-mono text-[11px]">
                      <td className="p-3 break-all select-all text-slate-300">
                        <a href={jsObj.url} target="_blank" rel="noopener noreferrer" className="text-cyber-accent hover:underline">
                          {jsObj.url}
                        </a>
                      </td>
                      <td className="p-3 text-slate-400">{jsObj.host}</td>
                      <td className="p-3">
                        <span className="px-1.5 py-0.5 bg-blue-500/15 border border-blue-500/35 text-blue-400 rounded text-[9px] uppercase font-semibold">
                          {jsObj.source}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Screenshots Tab */}
      {activeInventoryTab === "screenshots" && (
        <div className="bg-dark-card border border-dark-border rounded-xl glass p-4">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-cyber-accent">Captured Screenshots</h3>
            <span className="text-[10px] font-mono text-slate-500">{screenshotsList.length} screenshots</span>
          </div>
          {screenshotsList.length === 0 ? (
            <div className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono text-[10px]">
              No screenshots captured yet. Run scan in deep mode.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
              {screenshotsList.map((screen, idx) => {
                const imgUrl = screen.screenshot_path.startsWith("http") 
                  ? screen.screenshot_path 
                  : `http://127.0.0.1:8000${screen.screenshot_path}`;
                  
                return (
                  <div key={idx} className="bg-dark-bg border border-dark-border rounded-lg overflow-hidden flex flex-col group hover:border-cyber-accent/60 transition-all">
                    <div className="relative aspect-video bg-slate-900 border-b border-dark-border overflow-hidden">
                      <img 
                        src={imgUrl} 
                        alt={screen.title} 
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                        onError={(e) => {
                          (e.target as HTMLElement).style.display = 'none';
                        }}
                      />
                    </div>
                    <div className="p-3 flex flex-col justify-between flex-grow font-mono text-[10px]">
                      <div className="mb-2">
                        <a href={screen.url} target="_blank" rel="noopener noreferrer" className="text-cyber-accent hover:underline break-all font-bold block mb-1">
                          {screen.url}
                        </a>
                        <span className="text-slate-400 block text-[9px]">{screen.title}</span>
                      </div>
                      <div className="flex justify-between items-center text-[9px] text-slate-500 border-t border-dark-border/40 pt-2">
                        <span>{screen.timestamp ? new Date(screen.timestamp).toLocaleDateString() : "-"}</span>
                        <span className="px-1 py-0.2 bg-blue-500/10 border border-blue-500/30 text-blue-400 rounded uppercase font-semibold">
                          {screen.source}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Existing Assets Tab */}
      {activeInventoryTab === "assets" && (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      {/* Filtering Toolbar */}
      <div className="p-4 border-b border-dark-border flex flex-col md:flex-row space-y-3 md:space-y-0 md:space-x-4 items-center justify-between bg-dark-bg/50">
        <div className="relative w-full md:max-w-xs">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
            <Search className="w-4 h-4" />
          </span>
          <input
            type="text"
            placeholder="Search assets or IPs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent"
          />
        </div>

        <div className="flex flex-wrap space-x-3 w-full md:w-auto justify-end">
          <div className="flex items-center space-x-1">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent"
            >
              <option value="all">All Types</option>
              <option value="domain">Domains</option>
              <option value="subdomain">Subdomains</option>
            </select>
          </div>

          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent"
          >
            <option value="all">All Statuses</option>
            <option value="live">Live Hosts</option>
            <option value="unknown">Unknown</option>
            <option value="inactive">Inactive</option>
          </select>

          <div className="relative">
            <button
              onClick={() => setShowExportDropdown(!showExportDropdown)}
              className="bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 hover:text-white transition-all flex items-center gap-1.5 cursor-pointer font-semibold animate-pulse"
            >
              Export ▼
            </button>
            {showExportDropdown && (
              <div className="absolute right-0 mt-1 bg-dark-card border border-dark-border rounded-lg shadow-xl z-50 overflow-hidden text-xs w-48">
                <button
                  onClick={() => {
                    setShowExportDropdown(false);
                    handleExportFullInventory();
                  }}
                  className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border"
                >
                  • Full Inventory CSV
                </button>
                <button
                  onClick={() => {
                    setShowExportDropdown(false);
                    handleExportSubdomainsAndUrls();
                  }}
                  className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer"
                >
                  • Subdomains & URLs CSV
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Grid Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider">
              <th className="p-4 w-10"></th>
              <th className="p-4">Asset / Subdomain</th>
              <th className="p-4">Type</th>
              <th className="p-4">Status</th>
              <th className="p-4">Risk</th>
              <th className="p-4">Exposure</th>
              <th className="p-4">Priority</th>
              <th className="p-4">IP Address</th>
              <th className="p-4">Open Ports</th>
              <th className="p-4">Discovered By</th>
            </tr>
          </thead>
          <tbody>
            {filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={10} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono">
                  No assets match current criteria
                </td>
              </tr>
            ) : (
              filteredAssets.map((asset) => {
                const isExpanded = expandedId === asset.id;
                const ip = asset.metadata.ip_address || "N/A";
                const hasExposedPorts = asset.open_ports.some(p => [22, 21, 23, 3389].includes(p));

                return (
                  <React.Fragment key={asset.id}>
                    <tr className={`border-b border-dark-border hover:bg-dark-hover/30 transition-colors duration-150 ${hasExposedPorts ? "bg-cyber-danger/[0.02]" : ""}`}>
                      <td className="p-4">
                        <button
                          onClick={() => toggleExpand(asset.id)}
                          className="text-slate-400 hover:text-white transition-colors cursor-pointer"
                        >
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                      </td>
                      <td className="p-4 font-bold text-slate-200">
                        <div className="flex items-center space-x-2">
                          <span>{asset.domain}</span>
                          <button
                            onClick={() => handleCopy(asset.domain)}
                            className="text-slate-500 hover:text-cyber-accent transition-colors"
                            title="Copy Domain"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                      <td className="p-4">
                        <span className="px-2 py-0.5 rounded-full bg-dark-bg border border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                          {asset.type}
                        </span>
                      </td>
                      <td className="p-4">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                          asset.status === "live"
                            ? "bg-cyber-success/10 border border-cyber-success/30 text-cyber-success"
                            : asset.status === "unknown"
                            ? "bg-slate-500/10 border border-slate-500/30 text-slate-400"
                            : "bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger"
                        }`}>
                          {asset.status}
                        </span>
                      </td>
                      <td className="p-4">
                        {(() => {
                          const score = (asset as any).risk?.score;
                          const level = (asset as any).risk?.level;
                          if (score === undefined || score === null) {
                            return (
                              <span className="px-2 py-0.5 rounded-full bg-slate-500/10 border border-slate-500/25 text-slate-500 text-[10px] font-medium font-mono">
                                Not scored
                              </span>
                            );
                          }
                          let badgeColor = "bg-slate-500/10 border-slate-500/30 text-slate-400";
                          if (score >= 90) badgeColor = "bg-red-500/10 border-red-500/30 text-red-500 font-bold";
                          else if (score >= 70) badgeColor = "bg-orange-500/10 border-orange-500/30 text-orange-500 font-bold";
                          else if (score >= 40) badgeColor = "bg-yellow-500/10 border-yellow-500/30 text-yellow-400";
                          else if (score >= 1) badgeColor = "bg-blue-500/10 border-blue-500/30 text-blue-400";
                          
                          return (
                            <button
                              onClick={() => toggleExpand(asset.id)}
                              className={`px-2 py-0.5 rounded border text-[10px] font-mono cursor-pointer transition-all hover:scale-105 ${badgeColor}`}
                            >
                              {score} ({level})
                            </button>
                          );
                        })()}
                      </td>
                      <td className="p-4">
                        {(() => {
                          const risk = (asset as any).risk;
                          if (!risk) return <span className="text-slate-600 font-mono">-</span>;
                          const isExposed = risk.exposure_factors?.includes("Internet Exposed");
                          return isExposed ? (
                            <span className="px-1.5 py-0.5 rounded bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary text-[10px] font-mono uppercase tracking-wider font-bold">
                              Exposed
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded bg-slate-500/10 border border-slate-500/25 text-slate-500 text-[10px] font-mono uppercase tracking-wider">
                              Internal
                            </span>
                          );
                        })()}
                      </td>
                      <td className="p-4">
                        {(() => {
                          const risk = (asset as any).risk;
                          if (!risk) return <span className="text-slate-600 font-mono">-</span>;
                          const prio = risk.recommended_priority || "";
                          let color = "text-slate-400";
                          if (prio.includes("Immediate")) color = "text-red-500 font-bold";
                          else if (prio.includes("High")) color = "text-orange-500";
                          else if (prio.includes("Medium")) color = "text-yellow-400";
                          else if (prio.includes("Low")) color = "text-blue-400";
                          
                          return (
                            <span className={`text-[10px] font-mono ${color}`}>
                              {prio.replace(" remediation required", "").replace(" remediation", "")}
                            </span>
                          );
                        })()}
                      </td>
                      <td className="p-4 font-mono text-slate-300">{ip}</td>
                      <td className="p-4 font-mono">
                        <div className="flex flex-wrap gap-1">
                          {asset.open_ports.length === 0 ? (
                            <span className="text-slate-500 font-sans">-</span>
                          ) : (
                            asset.open_ports.map((port) => (
                              <span
                                key={port}
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  [22, 21, 23, 3389].includes(port)
                                    ? "bg-cyber-danger/25 border border-cyber-danger/50 text-cyber-danger animate-pulse"
                                    : "bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary"
                                }`}
                              >
                                {port}
                              </span>
                            ))
                          )}
                        </div>
                      </td>
                      <td className="p-4 text-slate-400 font-mono">{asset.discovered_by}</td>
                    </tr>

                    {/* Expandable Details Row */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={10} className="bg-dark-bg/30 p-4 border-b border-dark-border">
                          <div className={`grid grid-cols-1 ${asset.risk ? "md:grid-cols-3" : "md:grid-cols-2"} gap-6 p-2 font-mono text-xs`}>
                            {/* Left Side: DNS/IP Meta */}
                            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
                              <h5 className="font-bold text-cyber-accent border-b border-dark-border pb-1.5 mb-2.5 uppercase tracking-wider text-[10px]">
                                DNS & Network Infrastructure
                              </h5>
                              <div className="space-y-1.5">
                                <div>
                                  <span className="text-slate-500">A RECORD:</span>{" "}
                                  <span className="text-slate-200">{ip}</span>
                                </div>
                                {asset.metadata.dns_records && (
                                  <>
                                    {asset.metadata.dns_records.MX?.length > 0 && (
                                      <div>
                                        <span className="text-slate-500">MX RECORDS:</span>{" "}
                                        <span className="text-slate-300">
                                          {asset.metadata.dns_records.MX.join(", ")}
                                        </span>
                                      </div>
                                    )}
                                    {asset.metadata.dns_records.TXT?.length > 0 && (
                                      <div>
                                        <span className="text-slate-500">TXT RECORDS:</span>{" "}
                                        <span className="text-slate-300">
                                          {asset.metadata.dns_records.TXT.join(", ")}
                                        </span>
                                      </div>
                                    )}
                                  </>
                                )}
                                {asset.metadata.cloud_metadata && (
                                  <>
                                    <div>
                                      <span className="text-slate-500">CLOUD INTEGRATION:</span>{" "}
                                      <span className="text-cyber-warning">{asset.metadata.cloud_metadata.provider}</span>
                                    </div>
                                    <div>
                                      <span className="text-slate-500">CLOUD REGION:</span>{" "}
                                      <span className="text-slate-300">{asset.metadata.cloud_metadata.region}</span>
                                    </div>
                                    <div>
                                      <span className="text-slate-500">ACCOUNT ID:</span>{" "}
                                      <span className="text-slate-300">{asset.metadata.cloud_metadata.account_id}</span>
                                    </div>
                                  </>
                                )}
                              </div>
                            </div>

                            {/* Right Side: HTTPX / SSL Meta */}
                            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
                              <h5 className="font-bold text-cyber-accent border-b border-dark-border pb-1.5 mb-2.5 uppercase tracking-wider text-[10px]">
                                HTTPX Probe Results
                              </h5>
                              <div className="space-y-1.5">
                                {asset.metadata.url && (
                                  <div>
                                    <span className="text-slate-500">URL:</span>{" "}
                                    <span className="text-slate-200 break-all">{asset.metadata.url}</span>
                                  </div>
                                )}
                                {asset.metadata.status_code !== undefined && (
                                  <div>
                                    <span className="text-slate-500">STATUS CODE:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.status_code}</span>
                                  </div>
                                )}
                                {asset.metadata.title && (
                                  <div>
                                    <span className="text-slate-500">TITLE:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.title}</span>
                                  </div>
                                )}
                                {asset.metadata.technologies?.length > 0 && (
                                  <div>
                                    <span className="text-slate-500">TECHNOLOGIES:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.technologies.join(", ")}</span>
                                  </div>
                                )}
                                {(asset.metadata.server || asset.metadata.web_server) && (
                                  <div>
                                    <span className="text-slate-500">WEB SERVER:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.server || asset.metadata.web_server}</span>
                                  </div>
                                )}
                                {(asset.metadata.ip || asset.metadata.ip_address) && (
                                  <div>
                                    <span className="text-slate-500">IP ADDRESS:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.ip || asset.metadata.ip_address}</span>
                                  </div>
                                )}
                                {asset.metadata.response_time !== undefined && (
                                  <div>
                                    <span className="text-slate-500">RESPONSE TIME:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.response_time} ms</span>
                                  </div>
                                )}
                                {asset.metadata.content_length !== undefined && (
                                  <div>
                                    <span className="text-slate-500">CONTENT LENGTH:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.content_length}</span>
                                  </div>
                                )}
                                {asset.metadata.redirect_location && (
                                  <div>
                                    <span className="text-slate-500">REDIRECT:</span>{" "}
                                    <span className="text-slate-300 break-all">{asset.metadata.redirect_location}</span>
                                  </div>
                                )}
                                {(asset.metadata.tls_info || asset.metadata.ssl_info) && (
                                  <div>
                                    <span className="text-slate-500">TLS:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.tls_info?.issuer || asset.metadata.ssl_info?.issuer || "Available"}</span>
                                  </div>
                                )}
                                {!asset.metadata.url && asset.metadata.status_code === undefined && !asset.metadata.title && !asset.metadata.technologies?.length && !asset.metadata.server && !asset.metadata.web_server && !(asset.metadata.ip || asset.metadata.ip_address) && asset.metadata.response_time === undefined && asset.metadata.content_length === undefined && !asset.metadata.redirect_location && !(asset.metadata.tls_info || asset.metadata.ssl_info) && (
                                  <div className="text-slate-500 italic py-2">
                                    No HTTPX metadata available for this asset yet.
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* Risk Assessment & Exposure Breakdown */}
                            {asset.risk ? (
                              <div className="bg-dark-card border border-dark-border rounded-lg p-4">
                                <h5 className="font-bold text-cyber-danger border-b border-dark-border pb-1.5 mb-2.5 uppercase tracking-wider text-[10px] flex justify-between items-center">
                                  <span>Risk Breakdown ({asset.risk.level})</span>
                                  <span className="text-[10px] text-slate-300 font-bold">{asset.risk.score}/100</span>
                                </h5>
                                <div className="space-y-2.5 font-mono text-[11px]">
                                  <div>
                                    <span className="text-slate-500">PRIORITY:</span>{" "}
                                    <span className="text-white font-bold">{asset.risk.recommended_priority}</span>
                                  </div>
                                  <div>
                                    <span className="text-slate-500 font-bold block mb-1">CONTRIBUTORS:</span>
                                    <ul className="space-y-1 pl-1">
                                      {asset.risk.reasons && asset.risk.reasons.length > 0 ? (
                                        asset.risk.reasons.map((r: string, idx: number) => (
                                          <li key={idx} className="text-slate-300 flex items-start gap-1">
                                            <span className="text-cyber-danger">✓</span>
                                            <span>{r}</span>
                                          </li>
                                        ))
                                      ) : (
                                        <li className="text-slate-500 italic">No specific risk contributors found.</li>
                                      )}
                                    </ul>
                                  </div>
                                  {asset.risk.exposure_factors && asset.risk.exposure_factors.length > 0 && (
                                    <div className="mt-2.5 pt-2 border-t border-dark-border/40">
                                      <span className="text-slate-500 font-bold block mb-1">EXPOSURE FACTORS:</span>
                                      <div className="flex flex-wrap gap-1 mt-1">
                                        {asset.risk.exposure_factors.map((f: string, idx: number) => (
                                          <span key={idx} className="px-1.5 py-0.5 bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary rounded text-[9px] uppercase font-bold">
                                            {f}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            ) : (
                              <div className="bg-dark-card border border-dark-border rounded-lg p-4 flex flex-col justify-center items-center text-center">
                                <span className="text-slate-500 font-mono text-xs italic">Asset not yet scored. Run Unified Discovery to evaluate risk.</span>
                              </div>
                            )}

                            {/* Katana Crawl Results */}
                            {asset.metadata.katana && (
                              <div className={`col-span-1 ${asset.risk ? "md:col-span-3" : "md:col-span-2"} bg-dark-card border border-dark-border rounded-lg p-4 mt-2`}>
                                <h5 className="font-bold text-cyber-accent border-b border-dark-border pb-1.5 mb-2.5 uppercase tracking-wider text-[10px] flex items-center justify-between">
                                  <span>Katana Crawl Results</span>
                                  <span className="text-[9px] text-slate-500 font-mono font-normal normal-case">
                                    Scanned at: {new Date(asset.metadata.katana.scanned_at * 1000).toLocaleString()}
                                  </span>
                                </h5>
                                
                                {/* Tabs Header */}
                                <div className="flex border-b border-dark-border/60 mb-4 overflow-x-auto font-sans">
                                  {[
                                    { id: "endpoints", label: "Endpoints", count: asset.metadata.katana.endpoints?.length || 0 },
                                    { id: "js", label: "JS Files", count: asset.metadata.katana.js_files?.length || 0 },
                                    { id: "forms", label: "Forms", count: asset.metadata.katana.forms?.length || 0 },
                                    { id: "third_party", label: "Third-Party URLs", count: asset.metadata.katana.third_party_urls?.length || 0 }
                                  ].map(tab => {
                                    const activeTab = activeTabs[asset.id] || "endpoints";
                                    const isActive = activeTab === tab.id;
                                    return (
                                      <button
                                        key={tab.id}
                                        onClick={() => setAssetTab(asset.id, tab.id)}
                                        className={`px-4 py-2 text-[10px] font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                                          isActive
                                            ? "border-cyber-accent text-cyber-accent bg-cyber-accent/[0.03]"
                                            : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-dark-hover/20"
                                        }`}
                                      >
                                        {tab.label} ({tab.count})
                                      </button>
                                    );
                                  })}
                                </div>

                                {/* Tab Contents */}
                                {(() => {
                                  const activeTab = activeTabs[asset.id] || "endpoints";
                                  
                                  if (activeTab === "endpoints") {
                                    const hasClassified = asset.metadata.katana.classified_endpoints && 
                                      Object.keys(asset.metadata.katana.classified_endpoints).length > 0;
                                    
                                    return (
                                      <div className="space-y-3">
                                        {hasClassified ? (
                                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-60 overflow-y-auto pr-1">
                                            {Object.entries(asset.metadata.katana.classified_endpoints).map(([category, urls]: [string, any]) => {
                                              if (!urls || urls.length === 0) return null;
                                              return (
                                                <div key={category} className="bg-dark-bg border border-dark-border rounded p-2.5 space-y-1.5 font-mono">
                                                  <div className="flex justify-between items-center border-b border-dark-border pb-1 mb-1">
                                                    <span className="text-cyber-accent font-bold text-[9px] uppercase tracking-widest">{category}</span>
                                                    <span className="text-[9px] px-1.5 py-0.25 bg-dark-card border border-dark-border rounded text-slate-400">{urls.length}</span>
                                                  </div>
                                                  <div className="space-y-1 text-[10px]">
                                                    {urls.map((url: string, idx: number) => (
                                                      <div key={idx} className="text-slate-300 break-all select-all hover:text-white py-0.5 border-b border-dark-border/10 last:border-0">{url}</div>
                                                    ))}
                                                  </div>
                                                </div>
                                              );
                                            })}
                                          </div>
                                        ) : (
                                          <div className="max-h-48 overflow-y-auto bg-dark-bg border border-dark-border rounded p-2 text-[10px] space-y-1 font-mono">
                                            {asset.metadata.katana.endpoints?.length > 0 ? (
                                              asset.metadata.katana.endpoints.map((ep: string, idx: number) => (
                                                <div key={idx} className="text-slate-300 break-all select-all hover:text-white py-0.5 border-b border-dark-border/20 last:border-0">{ep}</div>
                                              ))
                                            ) : (
                                              <div className="text-slate-500 italic p-1">No endpoints discovered.</div>
                                            )}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  }

                                  if (activeTab === "js") {
                                    return (
                                      <div className="max-h-48 overflow-y-auto bg-dark-bg border border-dark-border rounded p-2 text-[10px] space-y-1 font-mono">
                                        {asset.metadata.katana.js_files?.length > 0 ? (
                                          asset.metadata.katana.js_files.map((js: string, idx: number) => (
                                            <div key={idx} className="text-slate-300 break-all select-all hover:text-white py-0.5 border-b border-dark-border/20 last:border-0">{js}</div>
                                          ))
                                        ) : (
                                          <div className="text-slate-500 italic p-1">No JavaScript files discovered.</div>
                                        )}
                                      </div>
                                    );
                                  }

                                  if (activeTab === "forms") {
                                    return (
                                      <div className="max-h-48 overflow-y-auto bg-dark-bg border border-dark-border rounded p-2 text-[10px] space-y-1.5 font-mono">
                                        {asset.metadata.katana.forms?.length > 0 ? (
                                          asset.metadata.katana.forms.map((f: any, idx: number) => {
                                            if (typeof f === "string") {
                                              return (
                                                <div key={idx} className="text-slate-300 break-all p-1 hover:text-white border-b border-dark-border/20 last:border-0">
                                                  {f}
                                                </div>
                                              );
                                            }
                                            const fields = f.fields
                                              ? f.fields.map((fld: any) => `${fld.name || "unnamed"} (${fld.type || "text"})`).join(", ")
                                              : null;
                                            return (
                                              <div key={idx} className="border border-dark-border/50 bg-dark-card/45 rounded p-2 space-y-0.5 text-slate-300">
                                                <div className="flex items-center space-x-2">
                                                  <span className="px-1.5 py-0.25 bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent rounded text-[8px] font-bold uppercase">
                                                    {f.method || "GET"}
                                                  </span>
                                                  <span className="text-slate-400">Action:</span>
                                                  <span className="text-slate-200 select-all font-semibold break-all">{f.action || "/"}</span>
                                                </div>
                                                {fields && (
                                                  <div className="text-slate-500 text-[9px] mt-0.5">
                                                    Fields: <span className="text-slate-400">{fields}</span>
                                                  </div>
                                                )}
                                              </div>
                                            );
                                          })
                                        ) : (
                                          <div className="text-slate-500 italic p-1">No forms discovered.</div>
                                        )}
                                      </div>
                                    );
                                  }

                                  if (activeTab === "third_party") {
                                    return (
                                      <div className="max-h-48 overflow-y-auto bg-dark-bg border border-dark-border rounded p-2 text-[10px] space-y-1 font-mono">
                                        {asset.metadata.katana.third_party_urls?.length > 0 ? (
                                          asset.metadata.katana.third_party_urls.map((tp: string, idx: number) => (
                                            <div key={idx} className="text-slate-400 break-all select-all hover:text-white py-0.5 border-b border-dark-border/20 last:border-0">{tp}</div>
                                          ))
                                        ) : (
                                          <div className="text-slate-500 italic p-1">No third-party URLs discovered.</div>
                                        )}
                                      </div>
                                    );
                                  }

                                  return null;
                                })()}
                              </div>
                            )}

                            {/* Nuclei Scan Results */}
                            {asset.metadata.nuclei && asset.metadata.nuclei.findings && asset.metadata.nuclei.findings.length > 0 && (
                              <div className="col-span-1 md:col-span-2 bg-dark-card border border-dark-border rounded-lg p-4 mt-2">
                                <h5 className="font-bold text-cyber-danger border-b border-dark-border pb-1.5 mb-2.5 uppercase tracking-wider text-[10px] flex items-center justify-between">
                                  <span>Nuclei Vulnerability Scan Findings</span>
                                  <span className="text-[9px] text-slate-500 font-mono font-normal normal-case">
                                    Scanned at: {asset.metadata.nuclei.scanned_at ? new Date(asset.metadata.nuclei.scanned_at * 1000).toLocaleString() : "Recently"}
                                  </span>
                                </h5>
                                <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
                                  {asset.metadata.nuclei.findings.map((f: any, idx: number) => {
                                    const sev = (f.severity || "info").toLowerCase();
                                    const sevColor = 
                                      sev === "critical" ? "bg-cyber-danger/25 border-cyber-danger/50 text-cyber-danger font-extrabold animate-pulse" :
                                      sev === "high" ? "bg-orange-500/25 border-orange-500/50 text-orange-400 font-bold" :
                                      sev === "medium" ? "bg-cyber-warning/20 border-cyber-warning/50 text-cyber-warning" :
                                      sev === "low" ? "bg-cyber-accent/20 border-cyber-accent/50 text-cyber-accent" :
                                      "bg-slate-500/20 border-slate-500/50 text-slate-400";
                                    
                                    return (
                                      <div key={idx} className="bg-dark-bg border border-dark-border rounded p-3 space-y-2 font-mono text-[10px]">
                                        <div className="flex flex-wrap items-center gap-2 border-b border-dark-border/50 pb-1.5">
                                          <span className={`px-2 py-0.5 border rounded text-[9px] uppercase tracking-wide ${sevColor}`}>
                                            {sev}
                                          </span>
                                          <span className="text-slate-200 font-bold text-[11px]">{f.name || f.template_id}</span>
                                          {f.cve && (
                                            <span className="px-1.5 py-0.25 bg-red-950/40 border border-red-900/50 text-red-300 rounded text-[9px]">
                                              {f.cve}
                                            </span>
                                          )}
                                          <span className="text-slate-600 text-[9px] ml-auto">ID: {f.template_id}</span>
                                        </div>

                                        {f.description && (
                                          <div className="text-slate-400 text-[9px] leading-relaxed">
                                            <span className="text-slate-500">Description:</span> {f.description}
                                          </div>
                                        )}

                                        <div className="space-y-1">
                                          <div className="text-slate-300 break-all select-all">
                                            <span className="text-slate-500">Matched URL:</span> <a href={f.matched_url} target="_blank" rel="noopener noreferrer" className="text-cyber-accent hover:underline">{f.matched_url}</a>
                                          </div>

                                          {f.tags && f.tags.length > 0 && (
                                            <div className="flex flex-wrap gap-1 items-center mt-1">
                                              <span className="text-slate-500 mr-1">Tags:</span>
                                              {f.tags.map((tag: string, tagIdx: number) => (
                                                <span key={tagIdx} className="px-1 py-0.1 bg-dark-card border border-dark-border/80 rounded text-slate-400 text-[8px]">
                                                  {tag}
                                                </span>
                                              ))}
                                            </div>
                                          )}

                                          {f.reference_urls && f.reference_urls.length > 0 && (
                                            <div className="mt-1">
                                              <span className="text-slate-500 block mb-0.5">References:</span>
                                              <div className="space-y-0.5 pl-2 border-l border-dark-border/60">
                                                {f.reference_urls.map((ref: string, refIdx: number) => (
                                                  <a key={refIdx} href={ref} target="_blank" rel="noopener noreferrer" className="block text-slate-400 hover:text-white break-all hover:underline text-[9px]">{ref}</a>
                                                ))}
                                              </div>
                                            </div>
                                          )}
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
      )}
    </div>
  );
};
