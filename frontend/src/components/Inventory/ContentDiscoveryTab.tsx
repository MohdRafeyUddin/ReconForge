import React, { useState, useMemo } from "react";
import { Search, Download, Copy, Check, ArrowUpDown } from "lucide-react";

export interface ContentPathRecord {
  value: string;
  host: string;
  status_code?: number;
  content_length?: number;
  words?: number;
  lines?: number;
  redirect_location?: string;
  calibration_used?: boolean;
  first_seen?: string;
  last_seen?: string;
}

interface ContentDiscoveryTabProps {
  records: ContentPathRecord[];
  projectName?: string;
  latestScanTime?: string | null;
}

const escapeCSV = (val: any): string => {
  if (val === null || val === undefined) return '""';
  const str = String(val).replace(/"/g, '""');
  return `"${str}"`;
};

const download = (content: string, filename: string) => {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

export const ContentDiscoveryTab: React.FC<ContentDiscoveryTabProps> = ({
  records,
  projectName = "project",
  latestScanTime,
}) => {
  const [search, setSearch] = useState("");
  const [selectedHost, setSelectedHost] = useState<string>("all");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"first_seen" | "status">("first_seen");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const [showExport, setShowExport] = useState(false);

  // Extract unique hosts and status codes for filter dropdowns
  const uniqueHosts = useMemo(() => {
    const hosts = new Set<string>();
    records.forEach((r) => {
      if (r.host) hosts.add(r.host);
    });
    return Array.from(hosts).sort();
  }, [records]);

  const uniqueStatusCodes = useMemo(() => {
    const codes = new Set<number>();
    records.forEach((r) => {
      if (r.status_code) codes.add(r.status_code);
    });
    return Array.from(codes).sort((a, b) => a - b);
  }, [records]);

  const latestScanDate = useMemo(() => {
    if (!latestScanTime) return null;
    const d = new Date(latestScanTime);
    return isNaN(d.getTime()) ? null : d;
  }, [latestScanTime]);

  const handleCopy = (url: string) => {
    navigator.clipboard.writeText(url);
    setCopiedUrl(url);
    setTimeout(() => {
      setCopiedUrl(null);
    }, 1500);
  };

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return records.filter((r) => {
      // Search filter
      if (q) {
        const matchesUrl = r.value.toLowerCase().includes(q);
        const matchesHost = r.host.toLowerCase().includes(q);
        const matchesRedirect = (r.redirect_location || "").toLowerCase().includes(q);
        const matchesStatus = String(r.status_code || "").includes(q);
        const matchesLength = String(r.content_length || "").includes(q);
        const matchesWords = String(r.words || "").includes(q);
        const matchesLines = String(r.lines || "").includes(q);
        if (!matchesUrl && !matchesHost && !matchesRedirect && !matchesStatus && !matchesLength && !matchesWords && !matchesLines) return false;
      }

      // Host filter
      if (selectedHost !== "all" && r.host.toLowerCase() !== selectedHost.toLowerCase()) {
        return false;
      }

      // Status filter
      if (selectedStatus !== "all") {
        if (selectedStatus === "2xx" && !(r.status_code && r.status_code >= 200 && r.status_code < 300)) return false;
        if (selectedStatus === "3xx" && !(r.status_code && r.status_code >= 300 && r.status_code < 400)) return false;
        if (selectedStatus === "4xx" && !(r.status_code && r.status_code >= 400 && r.status_code < 500)) return false;
        if (selectedStatus === "401_403" && !(r.status_code === 401 || r.status_code === 403)) return false;
        if (selectedStatus === "5xx" && !(r.status_code && r.status_code >= 500 && r.status_code < 600)) return false;
        if (selectedStatus.startsWith("exact:") && r.status_code !== parseInt(selectedStatus.replace("exact:", ""))) return false;
      }

      return true;
    }).sort((a, b) => {
      if (sortBy === "status") {
        const aStatus = a.status_code ?? 0;
        const bStatus = b.status_code ?? 0;
        return sortOrder === "asc" ? aStatus - bStatus : bStatus - aStatus;
      } else {
        // first_seen sort
        const aDate = a.first_seen ? new Date(a.first_seen).getTime() : 0;
        const bDate = b.first_seen ? new Date(b.first_seen).getTime() : 0;
        return sortOrder === "asc" ? aDate - bDate : bDate - aDate;
      }
    });
  }, [records, search, selectedHost, selectedStatus, sortBy, sortOrder]);

  const isNewInLatestScan = (firstSeenStr?: string): boolean => {
    if (!firstSeenStr) return false;
    const fs = new Date(firstSeenStr);
    if (isNaN(fs.getTime())) return false;
    if (latestScanDate) {
      return fs >= latestScanDate;
    }
    // Fallback: if within the last 15 minutes
    return Date.now() - fs.getTime() < 15 * 60 * 1000;
  };

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      {/* Control / Filter Bar */}
      <div className="p-4 border-b border-dark-border flex flex-col md:flex-row gap-3 items-center justify-between bg-dark-bg/50">
        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          {/* Search box */}
          <div className="relative w-full sm:w-60">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search content URLs, hosts..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent font-mono"
            />
          </div>

          {/* Host Filter */}
          <div className="flex items-center space-x-1">
            <span className="text-[10px] font-mono text-slate-400 uppercase">Host:</span>
            <select
              value={selectedHost}
              onChange={(e) => setSelectedHost(e.target.value)}
              className="bg-dark-input border border-dark-border rounded px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyber-accent font-mono max-w-[140px] truncate"
            >
              <option value="all">All Hosts ({uniqueHosts.length})</option>
              {uniqueHosts.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center space-x-1">
            <span className="text-[10px] font-mono text-slate-400 uppercase">Status:</span>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-dark-input border border-dark-border rounded px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyber-accent font-mono"
            >
              <option value="all">All Statuses</option>
              <option value="2xx">2xx Success</option>
              <option value="3xx">3xx Redirects</option>
              <option value="401_403">401 / 403 Restricted</option>
              <option value="4xx">4xx Client Errors</option>
              <option value="5xx">5xx Server Errors</option>
              {uniqueStatusCodes.map((sc) => (
                <option key={sc} value={`exact:${sc}`}>
                  HTTP {sc}
                </option>
              ))}
            </select>
          </div>

          {/* Sort By Toggle */}
          <button
            onClick={() => {
              if (sortBy === "first_seen") {
                setSortBy("status");
                setSortOrder("desc");
              } else {
                setSortBy("first_seen");
                setSortOrder("desc");
              }
            }}
            className="flex items-center gap-1 bg-dark-input hover:bg-dark-hover border border-dark-border rounded px-2.5 py-1.5 text-xs text-slate-300 font-mono transition-colors cursor-pointer"
            title="Toggle sort criteria"
          >
            <ArrowUpDown className="w-3.5 h-3.5 text-cyber-accent" />
            <span>Sort: {sortBy === "first_seen" ? "First Seen" : "Status"}</span>
          </button>
        </div>

        {/* Export Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowExport((v) => !v)}
            className="bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 hover:text-white flex items-center gap-1.5 cursor-pointer font-semibold"
          >
            <Download className="w-3.5 h-3.5" /> Export ▼
          </button>
          {showExport && (
            <div className="absolute right-0 mt-1 bg-dark-card border border-dark-border rounded-lg shadow-xl z-50 overflow-hidden text-xs w-48">
              <button
                onClick={() => {
                  const headers = ["URL", "Host", "Status", "Length", "Words", "Lines", "Redirect", "First Seen"];
                  const rows = filtered.map((r) => [
                    r.value,
                    r.host,
                    r.status_code || "",
                    r.content_length || 0,
                    r.words || 0,
                    r.lines || 0,
                    r.redirect_location || "",
                    r.first_seen || "",
                  ]);
                  download(
                    `\uFEFF${[headers, ...rows].map((row) => row.map(escapeCSV).join(",")).join("\r\n")}`,
                    `content_discovery_full_${projectName}.csv`
                  );
                  setShowExport(false);
                }}
                className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border"
              >
                • Full Details CSV
              </button>
              <button
                onClick={() => {
                  download(
                    `\uFEFF"URL"\r\n${filtered.map((r) => escapeCSV(r.value)).join("\r\n")}`,
                    `content_urls_${projectName}.csv`
                  );
                  setShowExport(false);
                }}
                className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer"
              >
                • URLs Only
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Table Area */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[11px]">
              <th className="p-3.5">URL</th>
              <th className="p-3.5">Host</th>
              <th className="p-3.5">Status</th>
              <th className="p-3.5">Length</th>
              <th className="p-3.5">Words</th>
              <th className="p-3.5">Redirect</th>
              <th className="p-3.5">First Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono">
                  {records.length === 0
                    ? "No content paths discovered yet — run a scan with FFUF / Feroxbuster enabled"
                    : "No content paths match search/filters"}
                </td>
              </tr>
            ) : (
              filtered.map((r, idx) => {
                const sc = r.status_code || 200;
                const isNew = isNewInLatestScan(r.first_seen);
                return (
                  <tr
                    key={idx}
                    className="border-b border-dark-border hover:bg-dark-hover/30 transition-colors font-mono"
                  >
                    {/* URL: Copyable, plain text, no auto-open / auto-fetch */}
                    <td className="p-3.5 text-slate-200 break-all max-w-sm">
                      <div className="flex items-start gap-2">
                        <button
                          onClick={() => handleCopy(r.value)}
                          className="mt-0.5 text-slate-500 hover:text-cyber-accent transition-colors p-1 rounded hover:bg-dark-hover cursor-pointer shrink-0"
                          title="Copy URL"
                        >
                          {copiedUrl === r.value ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <a
                          href={r.value}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="select-all break-all text-slate-200 hover:text-cyber-accent hover:underline transition-colors"
                        >
                          {r.value}
                        </a>
                        {isNew && (
                          <span className="shrink-0 px-1.5 py-0.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 rounded text-[9px] font-bold uppercase tracking-wider">
                            New
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Host */}
                    <td className="p-3.5 text-slate-400 whitespace-nowrap">
                      <a
                        href={`https://${r.host}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:text-cyber-accent hover:underline transition-colors"
                      >
                        {r.host}
                      </a>
                    </td>

                    {/* Status Code */}
                    <td className="p-3.5 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          sc >= 200 && sc < 300
                            ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                            : sc >= 300 && sc < 400
                            ? "bg-blue-500/20 text-blue-400 border border-blue-500/40"
                            : sc === 401 || sc === 403
                            ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                            : sc >= 400 && sc < 500
                            ? "bg-orange-500/20 text-orange-400 border border-orange-500/40"
                            : "bg-red-500/20 text-red-400 border border-red-500/40"
                        }`}
                      >
                        {sc}
                      </span>
                    </td>

                    {/* Length */}
                    <td className="p-3.5 text-slate-400 whitespace-nowrap">
                      {r.content_length !== undefined ? `${r.content_length} B` : "—"}
                    </td>

                    {/* Words */}
                    <td className="p-3.5 text-slate-400 whitespace-nowrap">{r.words ?? "—"}</td>

                    {/* Redirect */}
                    <td className="p-3.5 text-slate-400 max-w-xs break-all">
                      {r.redirect_location ? (
                        <a
                          href={r.redirect_location.startsWith("http") ? r.redirect_location : `https://${r.host}${r.redirect_location.startsWith("/") ? "" : "/"}${r.redirect_location}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyber-accent hover:underline"
                        >
                          {r.redirect_location}
                        </a>
                      ) : "—"}
                    </td>

                    {/* First Seen */}
                    <td className="p-3.5 text-slate-500 whitespace-nowrap">
                      {r.first_seen ? (
                        <span>
                          {new Date(r.first_seen).toLocaleDateString()}{" "}
                          {new Date(r.first_seen).toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Summary Footer */}
      <div className="p-3 border-t border-dark-border bg-dark-bg/40 flex justify-between items-center text-[11px] font-mono text-slate-500">
        <span>
          Showing {filtered.length} of {records.length} content path entries
        </span>
        {records.length > 0 && (
          <span>
            {uniqueHosts.length} hosts probed • {uniqueStatusCodes.length} status codes observed
          </span>
        )}
      </div>
    </div>
  );
};
