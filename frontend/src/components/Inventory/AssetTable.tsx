import React, { useState } from "react";
import { Search, Filter, Copy, ChevronDown, ChevronUp } from "lucide-react";

interface Asset {
  id: string;
  domain: string;
  type: string;
  status: string;
  open_ports: number[];
  metadata: Record<string, any>;
  discovered_by: string;
  created_at: string;
}

interface AssetTableProps {
  assets: Asset[];
}

export const AssetTable: React.FC<AssetTableProps> = ({ assets }) => {
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const filteredAssets = assets.filter((asset) => {
    const matchesSearch = asset.domain.toLowerCase().includes(search.toLowerCase()) ||
      (asset.metadata.ip_address && asset.metadata.ip_address.includes(search));
    const matchesType = filterType === "all" || asset.type === filterType;
    const matchesStatus = filterStatus === "all" || asset.status === filterStatus;
    
    return matchesSearch && matchesType && matchesStatus;
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
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
              <th className="p-4">IP Address</th>
              <th className="p-4">Open Ports</th>
              <th className="p-4">Discovered By</th>
            </tr>
          </thead>
          <tbody>
            {filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono">
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
                        <td colSpan={7} className="bg-dark-bg/30 p-4 border-b border-dark-border">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 p-2 font-mono text-xs">
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
  );
};
