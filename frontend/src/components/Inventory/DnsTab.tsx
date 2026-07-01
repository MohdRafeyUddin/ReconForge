import React, { useState, useMemo } from "react";
import { Search, Download } from "lucide-react";

export interface DnsRecord {
  subdomain: string;
  status: string;
  ipv4: string[];
  ipv6: string[];
  cname: string[];
  resolved_at?: number;
}

interface DnsTabProps {
  records: DnsRecord[];
  projectName?: string;
}

const escapeCSV = (val: any): string => {
  if (val === null || val === undefined) return '""';
  let str = String(val);
  str = str.replace(/"/g, '""');
  return `"${str}"`;
};

type SortKey = keyof DnsRecord | "";
type SortDir = "asc" | "desc";

export const DnsTab: React.FC<DnsTabProps> = ({
  records,
  projectName = "project",
}) => {
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("subdomain");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [showExport, setShowExport] = useState(false);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return records.filter(
      (r) =>
        r.subdomain.toLowerCase().includes(q) ||
        r.ipv4.some((ip) => ip.includes(q)) ||
        r.ipv6.some((ip) => ip.includes(q)) ||
        r.cname.some((c) => c.toLowerCase().includes(q))
    );
  }, [records, search]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    return [...filtered].sort((a, b) => {
      const av = Array.isArray(a[sortKey])
        ? (a[sortKey] as string[]).join(",")
        : String(a[sortKey] ?? "");
      const bv = Array.isArray(b[sortKey])
        ? (b[sortKey] as string[]).join(",")
        : String(b[sortKey] ?? "");
      const cmp = av.localeCompare(bv);
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [filtered, sortKey, sortDir]);

  const exportFullCSV = () => {
    const headers = ["Subdomain", "Status", "IPv4", "IPv6", "CNAME", "Resolved At"];
    const rows = sorted.map((r) => [
      r.subdomain,
      r.status,
      r.ipv4.join("; "),
      r.ipv6.join("; "),
      r.cname.join("; "),
      r.resolved_at ? new Date(r.resolved_at * 1000).toLocaleString() : "",
    ]);
    const csv = [headers, ...rows].map((row) => row.map(escapeCSV).join(",")).join("\r\n");
    downloadCSV(`\uFEFF${csv}`, `dns_full_${projectName}.csv`);
    setShowExport(false);
  };

  const exportSimpleCSV = () => {
    const rows = sorted.map((r) => `${r.subdomain},${r.ipv4[0] || ""}`);
    const csv = `"Subdomain","IP"\r\n${rows.join("\r\n")}`;
    downloadCSV(`\uFEFF${csv}`, `dns_simple_${projectName}.csv`);
    setShowExport(false);
  };

  const downloadCSV = (content: string, filename: string) => {
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

  const SortIcon = ({ col }: { col: SortKey }) =>
    sortKey === col ? (
      <span className="ml-1 text-cyber-accent">{sortDir === "asc" ? "↑" : "↓"}</span>
    ) : (
      <span className="ml-1 text-slate-700">↕</span>
    );

  const statusClass = (status: string) => {
    if (status === "resolved" || status === "live")
      return "bg-cyber-success/10 border border-cyber-success/30 text-cyber-success";
    if (status === "nxdomain")
      return "bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger";
    return "bg-slate-500/10 border border-slate-500/30 text-slate-400";
  };

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      {/* Toolbar */}
      <div className="p-4 border-b border-dark-border flex flex-col md:flex-row gap-3 items-center justify-between bg-dark-bg/50">
        <div className="relative w-full md:max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search DNS records..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent"
          />
        </div>
        <div className="relative">
          <button
            onClick={() => setShowExport((v) => !v)}
            className="bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 hover:text-white flex items-center gap-1.5 cursor-pointer font-semibold animate-pulse"
          >
            <Download className="w-3.5 h-3.5" />
            Export ▼
          </button>
          {showExport && (
            <div className="absolute right-0 mt-1 bg-dark-card border border-dark-border rounded-lg shadow-xl z-50 overflow-hidden text-xs w-44">
              <button
                onClick={exportFullCSV}
                className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border"
              >
                • Full Details CSV
              </button>
              <button
                onClick={exportSimpleCSV}
                className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer"
              >
                • Simple (Subdomain + IP)
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider">
              {[
                { key: "subdomain" as SortKey, label: "Subdomain" },
                { key: "status" as SortKey, label: "Status" },
                { key: "ipv4" as SortKey, label: "IPv4" },
                { key: "ipv6" as SortKey, label: "IPv6" },
                { key: "cname" as SortKey, label: "CNAME" },
                { key: "resolved_at" as SortKey, label: "Resolved At" },
              ].map((col) => (
                <th
                  key={col.key}
                  className="p-4 cursor-pointer select-none hover:text-slate-200 transition-colors"
                  onClick={() => handleSort(col.key)}
                >
                  {col.label}
                  <SortIcon col={col.key} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono"
                >
                  {records.length === 0
                    ? "No DNS records yet — run a scan with DNSx enabled"
                    : "No records match search"}
                </td>
              </tr>
            ) : (
              sorted.map((r, idx) => (
                <tr
                  key={`${r.subdomain}-${idx}`}
                  className="border-b border-dark-border hover:bg-dark-hover/30 transition-colors"
                >
                  <td className="p-4 font-bold text-slate-200 font-mono">{r.subdomain}</td>
                  <td className="p-4">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${statusClass(r.status)}`}>
                      {r.status || "unknown"}
                    </span>
                  </td>
                  <td className="p-4 font-mono text-slate-300">
                    {r.ipv4.length > 0 ? r.ipv4.join(", ") : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="p-4 font-mono text-slate-400">
                    {r.ipv6.length > 0 ? r.ipv6.join(", ") : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="p-4 font-mono text-slate-400">
                    {r.cname.length > 0 ? (
                      <span className="text-cyber-accent">{r.cname.join(", ")}</span>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="p-4 text-slate-500 font-mono">
                    {r.resolved_at
                      ? new Date(r.resolved_at * 1000).toLocaleString()
                      : <span className="text-slate-600">—</span>}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="px-4 py-2 border-t border-dark-border bg-dark-bg/30 text-[10px] font-mono text-slate-600">
        {sorted.length} / {records.length} records
      </div>
    </div>
  );
};
