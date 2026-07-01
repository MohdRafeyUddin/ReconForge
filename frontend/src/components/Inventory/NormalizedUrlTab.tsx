import React, { useState, useMemo } from "react";
import { Search, Download } from "lucide-react";

export interface NormalizedUrlRecord {
  original_url: string;
  normalized_url: string;
  duplicate_removed?: boolean;
  source?: string;
}

interface NormalizedUrlTabProps {
  records: NormalizedUrlRecord[];
  projectName?: string;
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

export const NormalizedUrlTab: React.FC<NormalizedUrlTabProps> = ({ records, projectName = "project" }) => {
  const [search, setSearch] = useState("");
  const [showExport, setShowExport] = useState(false);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return records.filter(
      (r) =>
        r.normalized_url.toLowerCase().includes(q) ||
        r.original_url.toLowerCase().includes(q) ||
        (r.source || "").toLowerCase().includes(q)
    );
  }, [records, search]);

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      <div className="p-4 border-b border-dark-border flex flex-col md:flex-row gap-3 items-center justify-between bg-dark-bg/50">
        <div className="relative w-full md:max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input type="text" placeholder="Search normalized URLs..." value={search} onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent" />
        </div>
        <div className="relative">
          <button onClick={() => setShowExport((v) => !v)}
            className="bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 hover:text-white flex items-center gap-1.5 cursor-pointer font-semibold animate-pulse">
            <Download className="w-3.5 h-3.5" /> Export ▼
          </button>
          {showExport && (
            <div className="absolute right-0 mt-1 bg-dark-card border border-dark-border rounded-lg shadow-xl z-50 overflow-hidden text-xs w-48">
              <button onClick={() => {
                const headers = ["Original URL", "Normalized URL", "Duplicate Removed", "Source"];
                const rows = filtered.map((r) => [r.original_url, r.normalized_url, r.duplicate_removed ? "Yes" : "No", r.source || ""]);
                download(`\uFEFF${[headers, ...rows].map((row) => row.map(escapeCSV).join(",")).join("\r\n")}`, `normalized_urls_full_${projectName}.csv`);
                setShowExport(false);
              }} className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border">
                • Full Details CSV
              </button>
              <button onClick={() => {
                download(`\uFEFF"Normalized URL"\r\n${filtered.map((r) => escapeCSV(r.normalized_url)).join("\r\n")}`, `normalized_urls_simple_${projectName}.csv`);
                setShowExport(false);
              }} className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer">
                • Normalized URLs Only
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider">
              <th className="p-4">Original URL</th>
              <th className="p-4">Normalized URL</th>
              <th className="p-4">Duplicate Removed</th>
              <th className="p-4">Source</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={4} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono">
                {records.length === 0 ? "No normalized URLs yet — run a scan with Uro enabled" : "No results match search"}
              </td></tr>
            ) : filtered.map((r, idx) => (
              <tr key={idx} className="border-b border-dark-border hover:bg-dark-hover/30 transition-colors">
                <td className="p-4 font-mono text-slate-400 break-all max-w-xs">{r.original_url}</td>
                <td className="p-4 font-mono text-cyber-accent break-all max-w-xs">{r.normalized_url}</td>
                <td className="p-4">
                  {r.duplicate_removed ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] bg-slate-500/10 border border-slate-500/30 text-slate-400 uppercase">Removed</span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-full text-[10px] bg-cyber-success/10 border border-cyber-success/30 text-cyber-success uppercase">Kept</span>
                  )}
                </td>
                <td className="p-4 text-slate-500 font-mono">{r.source || "uro"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-4 py-2 border-t border-dark-border bg-dark-bg/30 text-[10px] font-mono text-slate-600">
        {filtered.length} / {records.length} records
      </div>
    </div>
  );
};
