import React, { useState, useMemo } from "react";
import { Search, Download, ShieldAlert } from "lucide-react";
import { HighlightText, ExactMatchBadge } from "../Common/HighlightText";
import { Pagination, usePagination } from "../Common/Pagination";

export interface TakeoverRecord {
  subdomain: string;
  provider: string;
  status: "Vulnerable" | "Not Vulnerable" | "Unknown" | "Unconfirmed";
  confidence?: string;
  tools_agreed?: string[];
  evidence?: string;
  cname?: string;
  last_checked?: number;
}

interface TakeoverTabProps {
  records: TakeoverRecord[];
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

export const TakeoverTab: React.FC<TakeoverTabProps> = ({ records, projectName = "project" }) => {
  const [search, setSearch] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");
  const [showExport, setShowExport] = useState(false);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return records.filter((r) => {
      const matchSearch = !q ? true : (
        r.subdomain.toLowerCase().includes(q) ||
        (r.provider && r.provider.toLowerCase().includes(q)) ||
        (r.status && r.status.toLowerCase().includes(q)) ||
        (r.confidence && r.confidence.toLowerCase().includes(q))
      );
      const matchStatus = filterStatus === "all" || r.status === filterStatus;
      return matchSearch && matchStatus;
    });
  }, [records, search, filterStatus]);

  const { page, setPage, pageSize, setPageSize, pageItems, total } =
    usePagination(filtered, 20, `${search}|${filterStatus}`);

  const vulnCount = records.filter((r) => r.status === "Vulnerable").length;
  const safeCount = records.filter((r) => r.status === "Not Vulnerable").length;
  const unknownCount = records.filter((r) => r.status === "Unknown").length;

  const statusClass = (status: string) => {
    if (status === "Vulnerable") return "bg-cyber-danger/20 border border-cyber-danger/50 text-cyber-danger font-bold animate-pulse";
    if (status === "Unconfirmed") return "bg-amber-500/20 border border-amber-500/50 text-amber-300 font-semibold";
    if (status === "Not Vulnerable") return "bg-cyber-success/10 border border-cyber-success/30 text-cyber-success";
    return "bg-cyber-warning/10 border border-cyber-warning/30 text-cyber-warning";
  };

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      {vulnCount > 0 && (
        <div className="p-3 bg-cyber-danger/10 border-b border-cyber-danger/30 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyber-danger animate-pulse" />
          <span className="text-xs font-mono text-cyber-danger font-bold uppercase tracking-wider">
            {vulnCount} Vulnerable Subdomain{vulnCount !== 1 ? "s" : ""} Detected
          </span>
          <span className="ml-auto text-[10px] font-mono text-slate-500">{safeCount} safe · {unknownCount} unknown</span>
        </div>
      )}
      <div className="p-4 border-b border-dark-border flex flex-col md:flex-row gap-3 items-center justify-between bg-dark-bg/50">
        <div className="relative w-full md:max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input type="text" placeholder="Search takeover results..." value={search} onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent" />
        </div>
        <div className="flex gap-3 items-center">
          <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent">
            <option value="all">All Statuses</option>
            <option value="Vulnerable">Vulnerable</option>
            <option value="Not Vulnerable">Not Vulnerable</option>
            <option value="Unknown">Unknown</option>
          </select>
          <div className="relative">
            <button onClick={() => setShowExport((v) => !v)}
              className="bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 hover:text-white flex items-center gap-1.5 cursor-pointer font-semibold animate-pulse">
              <Download className="w-3.5 h-3.5" /> Export ▼
            </button>
            {showExport && (
              <div className="absolute right-0 mt-1 bg-dark-card border border-dark-border rounded-lg shadow-xl z-50 overflow-hidden text-xs w-44">
                <button onClick={() => { download(`\uFEFF${[["Subdomain","Provider","Status","Confidence","Last Checked"], ...filtered.map(r => [r.subdomain, r.provider, r.status, r.confidence||"", r.last_checked ? new Date(r.last_checked*1000).toLocaleString() : ""])].map(row => row.map(escapeCSV).join(",")).join("\r\n")}`, `takeovers_full_${projectName}.csv`); setShowExport(false); }}
                  className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border">
                  • Full Details CSV
                </button>
                <button onClick={() => { download(`\uFEFF"Subdomain","Status"\r\n${filtered.map(r => `"${r.subdomain}","${r.status}"`).join("\r\n")}`, `takeovers_simple_${projectName}.csv`); setShowExport(false); }}
                  className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer">
                  • Simple (Subdomain + Status)
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider">
              <th className="p-4">Subdomain</th>
              <th className="p-4">Provider / Service</th>
              <th className="p-4">Status</th>
              <th className="p-4">Confidence & Cross-Check</th>
              <th className="p-4">Last Checked</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={5} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono">
                {records.length === 0 ? "No takeover data — run a scan with Subzy enabled" : "No records match filter"}
              </td></tr>
            ) : pageItems.map((r, idx) => {
              const exactMatch = Boolean(
                search.trim() &&
                (r.subdomain.toLowerCase() === search.trim().toLowerCase() ||
                 (r.provider && r.provider.toLowerCase() === search.trim().toLowerCase()) ||
                 r.status.toLowerCase() === search.trim().toLowerCase() ||
                 (r.confidence && r.confidence.toLowerCase() === search.trim().toLowerCase()))
              );

              return (
                <tr key={`${r.subdomain}-${idx}`} className={`border-b border-dark-border hover:bg-dark-hover/30 transition-colors ${r.status === "Vulnerable" ? "bg-cyber-danger/[0.03]" : ""}`}>
                  <td className="p-4 font-bold text-slate-200 font-mono">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <a
                        href={`https://${r.subdomain}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:text-cyber-accent hover:underline"
                      >
                        <HighlightText text={r.subdomain} highlight={search} />
                      </a>
                      {exactMatch && <ExactMatchBadge />}
                    </div>
                  </td>
                  <td className="p-4 text-slate-400 font-mono">
                    <div>
                      <HighlightText text={r.provider || "—"} highlight={search} />
                      {r.cname && (
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5 truncate max-w-xs" title={r.cname}>
                          CNAME:{" "}
                          <a
                            href={`https://${r.cname}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyber-accent hover:underline"
                          >
                            {r.cname}
                          </a>
                        </div>
                      )}
                    </div>
                  </td>
                  <td className="p-4">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] uppercase ${statusClass(r.status)}`}>
                      <HighlightText text={r.status} highlight={search} />
                    </span>
                  </td>
                  <td className="p-4 font-mono">
                    <div className="flex flex-col gap-1">
                      {r.confidence?.toLowerCase() === "confirmed" ? (
                        <span className="inline-flex items-center w-fit px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-emerald-500/20 border border-emerald-500/40 text-emerald-400">
                          CONFIRMED (multi-tool)
                        </span>
                      ) : (
                        <span className="inline-flex items-center w-fit px-2 py-0.5 rounded text-[10px] uppercase font-medium bg-amber-500/20 border border-amber-500/30 text-amber-300">
                          UNCONFIRMED (single-tool)
                        </span>
                      )}
                      {r.tools_agreed && r.tools_agreed.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-0.5">
                          {r.tools_agreed.map((tool) => (
                            <span key={tool} className="px-1.5 py-0.2 rounded text-[9px] bg-dark-bg border border-dark-border text-slate-300 font-mono">
                              {tool}
                            </span>
                          ))}
                        </div>
                      )}
                      {r.evidence && (
                        <span className="text-[9px] text-slate-500 truncate max-w-xs" title={r.evidence}>
                          {r.evidence}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="p-4 text-slate-500 font-mono">{r.last_checked ? new Date(r.last_checked * 1000).toLocaleString() : "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <Pagination
        page={page}
        pageSize={pageSize}
        total={total}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        itemLabel="takeover record(s)"
      />
    </div>
  );
};
