import React, { useState, useMemo } from "react";
import { Search, Download, ChevronDown, ChevronRight } from "lucide-react";

export interface GfUrlRecord {
  url: string;
  categories: string[];
  source?: string;
  classified_at?: number;
}

interface GfTabProps {
  records: GfUrlRecord[];
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

const CATEGORY_COLORS: Record<string, string> = {
  xss:      "bg-cyber-danger/20 border-cyber-danger/50 text-cyber-danger",
  sqli:     "bg-orange-500/20 border-orange-500/50 text-orange-400",
  ssrf:     "bg-cyber-warning/20 border-cyber-warning/50 text-cyber-warning",
  redirect: "bg-cyber-accent/20 border-cyber-accent/50 text-cyber-accent",
  lfi:      "bg-purple-500/20 border-purple-500/50 text-purple-400",
  rce:      "bg-red-600/20 border-red-600/50 text-red-400",
  idor:     "bg-pink-500/20 border-pink-500/50 text-pink-400",
  ssti:     "bg-indigo-500/20 border-indigo-500/50 text-indigo-400",
  debug:    "bg-slate-500/20 border-slate-500/50 text-slate-400",
  upload:   "bg-teal-500/20 border-teal-500/50 text-teal-400",
  aws:      "bg-yellow-500/20 border-yellow-500/50 text-yellow-400",
  graphql:  "bg-cyber-primary/20 border-cyber-primary/50 text-cyber-primary",
};

const categoryColor = (cat: string) =>
  CATEGORY_COLORS[cat.toLowerCase()] || "bg-slate-500/20 border-slate-500/50 text-slate-400";

export const GfTab: React.FC<GfTabProps> = ({ records, projectName = "project" }) => {
  const [search, setSearch] = useState("");
  const [filterCat, setFilterCat] = useState("all");
  const [showExport, setShowExport] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  // Collect all unique categories across all records
  const allCategories = useMemo(() => {
    const cats = new Set<string>();
    records.forEach((r) => r.categories.forEach((c) => cats.add(c)));
    return Array.from(cats).sort();
  }, [records]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return records.filter((r) => {
      const matchSearch = r.url.toLowerCase().includes(q);
      const matchCat = filterCat === "all" || r.categories.includes(filterCat);
      return matchSearch && matchCat;
    });
  }, [records, search, filterCat]);

  // Group by category for display
  const grouped = useMemo(() => {
    const map: Record<string, string[]> = {};
    filtered.forEach((r) => {
      r.categories.forEach((cat) => {
        if (!map[cat]) map[cat] = [];
        if (!map[cat].includes(r.url)) map[cat].push(r.url);
      });
    });
    return map;
  }, [filtered]);

  const toggleCollapse = (cat: string) =>
    setCollapsed((prev) => ({ ...prev, [cat]: !prev[cat] }));

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      {/* Toolbar */}
      <div className="p-4 border-b border-dark-border flex flex-col md:flex-row gap-3 items-center justify-between bg-dark-bg/50">
        <div className="relative w-full md:max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input type="text" placeholder="Search GF URLs..." value={search} onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent" />
        </div>
        <div className="flex gap-3 items-center">
          <select value={filterCat} onChange={(e) => setFilterCat(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent">
            <option value="all">All Categories</option>
            {allCategories.map((c) => (
              <option key={c} value={c}>{c.toUpperCase()}</option>
            ))}
          </select>
          <div className="relative">
            <button onClick={() => setShowExport((v) => !v)}
              className="bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 hover:text-white flex items-center gap-1.5 cursor-pointer font-semibold animate-pulse">
              <Download className="w-3.5 h-3.5" /> Export ▼
            </button>
            {showExport && (
              <div className="absolute right-0 mt-1 bg-dark-card border border-dark-border rounded-lg shadow-xl z-50 overflow-hidden text-xs w-48">
                <button onClick={() => {
                  const headers = ["URL", "Categories", "Source", "Classified At"];
                  const rows = filtered.map((r) => [
                    r.url,
                    r.categories.join("; "),
                    r.source || "gf",
                    r.classified_at ? new Date(r.classified_at * 1000).toLocaleString() : "",
                  ]);
                  download(`\uFEFF${[headers, ...rows].map((row) => row.map(escapeCSV).join(",")).join("\r\n")}`, `gf_full_${projectName}.csv`);
                  setShowExport(false);
                }} className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border">
                  • Full Details CSV
                </button>
                <button onClick={() => {
                  // Category + URL pairs
                  const rows: string[][] = [];
                  Object.entries(grouped).forEach(([cat, urls]) => {
                    urls.forEach((u) => rows.push([cat, u]));
                  });
                  download(`\uFEFF"Category","URL"\r\n${rows.map((r) => r.map(escapeCSV).join(",")).join("\r\n")}`, `gf_category_url_${projectName}.csv`);
                  setShowExport(false);
                }} className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer">
                  • Category + URL CSV
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Grouped by category */}
      <div className="p-4 space-y-4">
        {Object.keys(grouped).length === 0 ? (
          <div className="text-center text-slate-500 uppercase tracking-widest font-mono py-8 text-xs">
            {records.length === 0 ? "No GF data — run a scan with GF enabled" : "No results match current filter"}
          </div>
        ) : (
          Object.entries(grouped)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([cat, urls]) => {
              const isCollapsed = collapsed[cat];
              return (
                <div key={cat} className="bg-dark-bg border border-dark-border rounded-lg overflow-hidden">
                  <button
                    onClick={() => toggleCollapse(cat)}
                    className="w-full flex items-center justify-between p-3 hover:bg-dark-hover/30 transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-2">
                      {isCollapsed ? (
                        <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
                      )}
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase font-mono ${categoryColor(cat)}`}>
                        {cat}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 border border-dark-border px-1.5 py-0.5 rounded">
                      {urls.length} URL{urls.length !== 1 ? "s" : ""}
                    </span>
                  </button>
                  {!isCollapsed && (
                    <div className="border-t border-dark-border max-h-60 overflow-y-auto">
                      {urls.map((url, idx) => (
                        <div key={idx} className="px-4 py-2 font-mono text-[11px] text-slate-300 break-all hover:text-white hover:bg-dark-hover/20 transition-colors border-b border-dark-border/40 last:border-0 select-all">
                          {url}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })
        )}
      </div>

      <div className="px-4 py-2 border-t border-dark-border bg-dark-bg/30 text-[10px] font-mono text-slate-600">
        {filtered.length} / {records.length} classified URLs · {Object.keys(grouped).length} categories
      </div>
    </div>
  );
};
