import React, { useState, useMemo } from "react";
import { Search, Copy, ChevronUp, ChevronDown, Download } from "lucide-react";

interface SubdomainAsset {
  id: string;
  domain: string;
  type: string;
  status: string;
  sources: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  discovered_by: string;
}

interface SubdomainsTabProps {
  subdomains: SubdomainAsset[];
}

const SOURCE_COLORS: Record<string, string> = {
  subfinder: "bg-blue-500/15 border-blue-500/40 text-blue-400",
  assetfinder: "bg-cyan-500/15 border-cyan-500/40 text-cyan-400",
  amass: "bg-emerald-500/15 border-emerald-500/40 text-emerald-400",
  chaos: "bg-amber-500/15 border-amber-500/40 text-amber-400",
};

const sourceChip = (src: string) => {
  const cls = SOURCE_COLORS[src.toLowerCase()] ?? "bg-slate-500/15 border-slate-500/40 text-slate-400";
  return (
    <span
      key={src}
      className={`inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-mono font-bold uppercase ${cls}`}
    >
      {src}
    </span>
  );
};

type SortKey = "domain" | "first_seen" | "last_seen";

export const SubdomainsTab: React.FC<SubdomainsTabProps> = ({ subdomains }) => {
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("domain");
  const [sortAsc, setSortAsc] = useState(true);
  const [page, setPage] = useState(1);
  const pageSize = 50;

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortAsc((v) => !v);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
    setPage(1);
  };

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return subdomains.filter(
      (s) =>
        s.domain.toLowerCase().includes(q) ||
        s.sources.some((src) => src.toLowerCase().includes(q))
    );
  }, [subdomains, search]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let av = "";
      let bv = "";
      if (sortKey === "domain") {
        av = a.domain;
        bv = b.domain;
      } else if (sortKey === "first_seen") {
        av = a.first_seen ?? "";
        bv = b.first_seen ?? "";
      } else {
        av = a.last_seen ?? "";
        bv = b.last_seen ?? "";
      }
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
  }, [filtered, sortKey, sortAsc]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const paginated = sorted.slice((page - 1) * pageSize, page * pageSize);

  const handleCopy = (text: string) => navigator.clipboard.writeText(text);

  const handleExportCSV = () => {
    const header = "Subdomain,Sources,First Seen,Last Seen\n";
    const rows = sorted
      .map(
        (s) =>
          `"${s.domain}","${s.sources.join("|")}","${s.first_seen ?? ""}","${s.last_seen ?? ""}"`
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "subdomains.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  const SortIcon = ({ k }: { k: SortKey }) =>
    sortKey === k ? (
      sortAsc ? (
        <ChevronUp className="w-3 h-3 inline ml-1" />
      ) : (
        <ChevronDown className="w-3 h-3 inline ml-1" />
      )
    ) : null;

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      {/* Toolbar */}
      <div className="p-4 border-b border-dark-border flex flex-col md:flex-row gap-3 items-center justify-between bg-dark-bg/50">
        <div className="relative w-full md:max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search subdomains or sources..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent"
          />
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
          <span>{filtered.length} subdomains</span>
          <button
            onClick={handleExportCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-bg border border-dark-border hover:border-cyber-accent/50 text-slate-300 hover:text-white rounded transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider">
              <th
                className="p-4 cursor-pointer hover:text-white select-none"
                onClick={() => toggleSort("domain")}
              >
                Subdomain <SortIcon k="domain" />
              </th>
              <th className="p-4">Sources</th>
              <th
                className="p-4 cursor-pointer hover:text-white select-none whitespace-nowrap"
                onClick={() => toggleSort("first_seen")}
              >
                First Seen <SortIcon k="first_seen" />
              </th>
              <th
                className="p-4 cursor-pointer hover:text-white select-none whitespace-nowrap"
                onClick={() => toggleSort("last_seen")}
              >
                Last Seen <SortIcon k="last_seen" />
              </th>
              <th className="p-4 w-10"></th>
            </tr>
          </thead>
          <tbody>
            {paginated.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-10 text-center text-slate-500 uppercase tracking-widest font-mono">
                  {search ? "No matches found" : "No subdomains discovered yet"}
                </td>
              </tr>
            ) : (
              paginated.map((asset) => (
                <tr
                  key={asset.id}
                  className="border-b border-dark-border hover:bg-dark-hover/30 transition-colors duration-150"
                >
                  <td className="p-4 font-bold text-slate-200 font-mono">
                    {asset.domain}
                  </td>
                  <td className="p-4">
                    <div className="flex flex-wrap gap-1">
                      {asset.sources && asset.sources.length > 0
                        ? asset.sources.map((src) => sourceChip(src))
                        : sourceChip(asset.discovered_by)}
                    </div>
                  </td>
                  <td className="p-4 text-slate-400 font-mono whitespace-nowrap">
                    {asset.first_seen
                      ? new Date(asset.first_seen).toLocaleString()
                      : "—"}
                  </td>
                  <td className="p-4 text-slate-400 font-mono whitespace-nowrap">
                    {asset.last_seen
                      ? new Date(asset.last_seen).toLocaleString()
                      : "—"}
                  </td>
                  <td className="p-4">
                    <button
                      onClick={() => handleCopy(asset.domain)}
                      className="text-slate-500 hover:text-cyber-accent transition-colors cursor-pointer"
                      title="Copy subdomain"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="p-4 border-t border-dark-border flex items-center justify-between text-xs font-mono text-slate-400">
          <span>
            Page {page} of {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 bg-dark-bg border border-dark-border rounded hover:border-cyber-accent/50 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-all"
            >
              ← Prev
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="px-3 py-1 bg-dark-bg border border-dark-border rounded hover:border-cyber-accent/50 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-all"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
