import React, { useState, useMemo, useEffect } from "react";
import { Search, Download, ChevronDown, ChevronRight, Copy, AlertCircle } from "lucide-react";
import { HighlightText, ExactMatchBadge } from "../Common/HighlightText";

export interface NucleiFindingRecord {
  template_id?: string;
  template_name?: string;
  template?: string;
  finding?: string;
  severity: string;
  matched_url: string;
  endpoint?: string;
  host: string;
  ip?: string;
  port?: string;
  protocol?: string;
  tags?: string[];
  classification?: any;
  cve?: string;
  cwe?: string;
  cvss?: string;
  description?: string;
  reference_urls?: string[];
  timestamp: string;
  pass_name?: string;
  source?: string;
  curl_command?: string;
  request?: string;
  response?: string;
  matcher_name?: string;
  extracted_results?: string[];
  metadata?: any;
  parameter?: string;
  payload?: string;
  evidence?: string;
}

interface NucleiTabProps {
  findings: NucleiFindingRecord[];
  projectName?: string;
  initialSeverityFilter?: string | null;
}

const escapeCSV = (val: any): string => {
  if (val === null || val === undefined) return '""';
  const str = String(val).replace(/"/g, '""');
  return `"${str}"`;
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-cyber-danger/25 border-cyber-danger/50 text-cyber-danger font-extrabold animate-pulse",
  high: "bg-orange-500/25 border-orange-500/50 text-orange-400 font-bold",
  medium: "bg-cyber-warning/20 border-cyber-warning/50 text-cyber-warning",
  low: "bg-cyber-accent/20 border-cyber-accent/50 text-cyber-accent",
  info: "bg-slate-500/20 border-slate-500/50 text-slate-400",
};

const getSeverityClass = (sev: string) =>
  SEVERITY_COLORS[sev.toLowerCase()] || "bg-slate-500/20 border-slate-500/50 text-slate-400";

export const NucleiTab: React.FC<NucleiTabProps> = ({
  findings,
  projectName = "project",
  initialSeverityFilter = null,
}) => {
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterHost, setFilterHost] = useState("all");
  const [filterTemplate, setFilterTemplate] = useState("all");
  const [filterTag, setFilterTag] = useState("all");
  const [filterPass, setFilterPass] = useState("all");
  const [showExport, setShowExport] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filterSource, setFilterSource] = useState("all");

  // Sync initialSeverityFilter prop (e.g. from clicking dashboard severity card)
  useEffect(() => {
    if (initialSeverityFilter) {
      setFilterSeverity(initialSeverityFilter.toLowerCase());
    }
  }, [initialSeverityFilter]);

  // Compute unique values for filters
  const uniqueHosts = useMemo(() => {
    return Array.from(new Set(findings.map((f) => f.host).filter(Boolean))).sort();
  }, [findings]);

  const uniqueTemplates = useMemo(() => {
    return Array.from(new Set(findings.map((f) => f.template || f.template_id).filter(Boolean))).sort();
  }, [findings]);

  const uniqueTags = useMemo(() => {
    const tagsSet = new Set<string>();
    findings.forEach((f) => {
      (f.tags || []).forEach((t: string) => tagsSet.add(t));
    });
    return Array.from(tagsSet).sort();
  }, [findings]);

  const uniquePasses = useMemo(() => {
    return Array.from(new Set(findings.map((f) => f.pass_name).filter(Boolean))).sort();
  }, [findings]);

  // Filtered findings list
  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return findings.filter((f) => {
      // 1. Search filter
      const matchesSearch = !q ? true : (
        (f.host || "").toLowerCase().includes(q) ||
        (f.template || f.template_id || "").toLowerCase().includes(q) ||
        (f.template_name || "").toLowerCase().includes(q) ||
        (f.matched_url || f.endpoint || "").toLowerCase().includes(q) ||
        (f.severity || "").toLowerCase().includes(q) ||
        (f.description || "").toLowerCase().includes(q) ||
        (f.source || f.metadata?.source || "").toLowerCase().includes(q) ||
        (f.curl_command || "").toLowerCase().includes(q) ||
        (f.ip || "").toLowerCase().includes(q) ||
        (f.tags || []).some((t: string) => t.toLowerCase().includes(q)) ||
        (f.cve || "").toLowerCase().includes(q)
      );

      // 2. Dropdown filters
      const matchesSeverity = filterSeverity === "all" || (f.severity || "").toLowerCase() === filterSeverity;
      const matchesHost = filterHost === "all" || f.host === filterHost;
      const matchesTemplate = filterTemplate === "all" || (f.template || f.template_id) === filterTemplate;
      const matchesTag = filterTag === "all" || (f.tags || []).includes(filterTag);
      const matchesPass = filterPass === "all" || f.pass_name === filterPass;
      const matchesSource = filterSource === "all" || (f.source || f.metadata?.source || "").toLowerCase() === filterSource.toLowerCase();

      return matchesSearch && matchesSeverity && matchesHost && matchesTemplate && matchesTag && matchesPass && matchesSource;
    });
  }, [findings, search, filterSeverity, filterHost, filterTemplate, filterTag, filterPass, filterSource]);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const downloadFile = (content: string, filename: string, contentType: string) => {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportCSV = () => {
    const headers = [
      "Severity", "Template ID", "Template Name", "Matched URL", 
      "Host", "IP", "Port", "Protocol", "Tags", "CVE", "CWE", "CVSS", 
      "Description", "Timestamp", "Pass Name", "Source", "Curl Command"
    ];

    const rows = filtered.map(f => [
      f.severity,
      f.template_id || f.template || "",
      f.template_name || "",
      f.matched_url || f.endpoint || "",
      f.host,
      f.ip || "",
      f.port || "",
      f.protocol || "",
      (f.tags || []).join("; "),
      f.cve || "",
      f.cwe || "",
      f.cvss || "",
      f.description || "",
      f.timestamp,
      f.pass_name || "",
      f.source || "",
      f.curl_command || ""
    ]);

    const csvContent = [headers, ...rows]
      .map(row => row.map(escapeCSV).join(","))
      .join("\r\n");

    downloadFile("\uFEFF" + csvContent, `nuclei_findings_${projectName.toLowerCase()}.csv`, "text/csv;charset=utf-8;");
    setShowExport(false);
  };

  const handleExportJSON = () => {
    const jsonContent = JSON.stringify(filtered, null, 2);
    downloadFile(jsonContent, `nuclei_findings_${projectName.toLowerCase()}.json`, "application/json;charset=utf-8;");
    setShowExport(false);
  };

  if (findings.length === 0) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-xl glass p-8 text-center text-slate-500 uppercase tracking-widest font-mono text-xs flex flex-col items-center justify-center gap-2">
        <AlertCircle className="w-8 h-8 text-slate-600 animate-pulse" />
        No Security findings detected.
      </div>
    );
  }

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      {/* Filtering Toolbar */}
      <div className="p-4 border-b border-dark-border flex flex-col md:flex-row gap-3 items-center justify-between bg-dark-bg/50">
        <div className="relative w-full md:max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search Host, Template, ID, URL, Tags, CVE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent font-mono"
          />
        </div>

        <div className="flex flex-wrap gap-2 w-full md:w-auto justify-end">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent font-mono cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select
            value={filterSource}
            onChange={(e) => setFilterSource(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent font-mono cursor-pointer"
          >
            <option value="all">All Sources</option>
            <option value="nuclei">Nuclei</option>
            <option value="dalfox">Dalfox</option>
            <option value="openredirex">OpenRedirex</option>
          </select>

          <select
            value={filterHost}
            onChange={(e) => setFilterHost(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent font-mono cursor-pointer max-w-[150px]"
          >
            <option value="all">All Hosts</option>
            {uniqueHosts.map((h) => (
              <option key={h} value={h}>{h}</option>
            ))}
          </select>

          <select
            value={filterTemplate}
            onChange={(e) => setFilterTemplate(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent font-mono cursor-pointer max-w-[150px]"
          >
            <option value="all">All Templates</option>
            {uniqueTemplates.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>

          <select
            value={filterTag}
            onChange={(e) => setFilterTag(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent font-mono cursor-pointer max-w-[150px]"
          >
            <option value="all">All Tags</option>
            {uniqueTags.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>

          <select
            value={filterPass}
            onChange={(e) => setFilterPass(e.target.value)}
            className="bg-dark-input border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyber-accent font-mono cursor-pointer max-w-[150px]"
          >
            <option value="all">All Passes</option>
            {uniquePasses.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>

          <div className="relative">
            <button
              onClick={() => setShowExport((v) => !v)}
              className="bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-xs px-2.5 py-1.5 text-slate-300 hover:text-white flex items-center gap-1.5 cursor-pointer font-semibold animate-pulse"
            >
              <Download className="w-3.5 h-3.5" /> Export ▼
            </button>
            {showExport && (
              <div className="absolute right-0 mt-1 bg-dark-card border border-dark-border rounded-lg shadow-xl z-50 overflow-hidden text-xs w-48">
                <button
                  onClick={handleExportCSV}
                  className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer border-b border-dark-border"
                >
                  • Export Filtered CSV
                </button>
                <button
                  onClick={handleExportJSON}
                  className="w-full text-left px-4 py-2 hover:bg-dark-hover text-slate-300 hover:text-white transition-colors cursor-pointer"
                >
                  • Export Filtered JSON
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
              <th className="p-4">Severity</th>
              <th className="p-4">Template</th>
              <th className="p-4">Matched URL</th>
              <th className="p-4">Host</th>
              <th className="p-4">Tags</th>
              <th className="p-4">CVE</th>
              <th className="p-4">Time</th>
              <th className="p-4">Pass</th>
              <th className="p-4">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={10} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono">
                  No findings match current criteria
                </td>
              </tr>
            ) : (
              filtered.map((f, idx) => {
                const uniqueId = `${f.template_id || f.template || "unknown"}-${f.matched_url || f.endpoint || ""}-${idx}`;
                const isExpanded = expandedId === uniqueId;

                const exactMatch = Boolean(
                  search.trim() &&
                  ((f.host && f.host.toLowerCase() === search.trim().toLowerCase()) ||
                   (f.template_id && f.template_id.toLowerCase() === search.trim().toLowerCase()) ||
                   (f.template && f.template.toLowerCase() === search.trim().toLowerCase()) ||
                   (f.matched_url && f.matched_url.toLowerCase() === search.trim().toLowerCase()) ||
                   (f.endpoint && f.endpoint.toLowerCase() === search.trim().toLowerCase()) ||
                   (f.cve && f.cve.toLowerCase() === search.trim().toLowerCase()) ||
                   (f.severity && f.severity.toLowerCase() === search.trim().toLowerCase()) ||
                   (f.tags && f.tags.some((t: string) => t.toLowerCase() === search.trim().toLowerCase())))
                );

                return (
                  <React.Fragment key={uniqueId}>
                    <tr
                      className={`border-b border-dark-border/50 hover:bg-dark-hover/30 transition-colors font-mono text-[11px] ${
                        isExpanded ? "bg-dark-hover/10" : ""
                      }`}
                    >
                      <td className="p-4 text-center">
                        <button
                          onClick={() => setExpandedId(isExpanded ? null : uniqueId)}
                          className="text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </button>
                      </td>
                      <td className="p-4">
                        <span className={`px-2 py-0.5 border rounded text-[9px] uppercase tracking-wide font-bold ${getSeverityClass(f.severity)}`}>
                          <HighlightText text={f.severity} highlight={search} />
                        </span>
                      </td>
                      <td className="p-4 font-bold text-slate-200">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <HighlightText
                            text={f.template_id || f.template || (f.source || f.metadata?.source || "unknown").toUpperCase()}
                            highlight={search}
                          />
                          {exactMatch && <ExactMatchBadge />}
                        </div>
                      </td>
                      <td className="p-4 max-w-xs truncate text-slate-300" title={f.matched_url || f.endpoint || ""}>
                        {f.matched_url || f.endpoint ? (
                          <a
                            href={f.matched_url || f.endpoint}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyber-accent hover:underline"
                          >
                            <HighlightText text={f.matched_url || f.endpoint} highlight={search} />
                          </a>
                        ) : ""}
                      </td>
                      <td className="p-4 text-slate-300">
                        {f.host ? (
                          <a
                            href={`https://${f.host}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="hover:text-cyber-accent hover:underline"
                          >
                            <HighlightText text={f.host} highlight={search} />
                          </a>
                        ) : "-"}
                      </td>
                      <td className="p-4 max-w-xs truncate text-slate-400">
                        {(f.tags || []).map((t: string, tIdx: number) => (
                          <React.Fragment key={tIdx}>
                            {tIdx > 0 && ", "}
                            <HighlightText text={t} highlight={search} />
                          </React.Fragment>
                        ))}
                      </td>
                      <td className="p-4">
                        {f.cve ? (
                          <span className="px-1.5 py-0.25 bg-red-950/40 border border-red-900/50 text-red-300 rounded text-[9px]">
                            <HighlightText text={f.cve} highlight={search} />
                          </span>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>
                      <td className="p-4 text-slate-400">
                        {f.timestamp ? new Date(f.timestamp).toLocaleTimeString() : "-"}
                      </td>
                      <td className="p-4 text-slate-400">{f.pass_name || "-"}</td>
                      <td className="p-4 text-cyber-success font-semibold">Active</td>
                    </tr>

                    {/* Expandable Details Area */}
                    {isExpanded && (
                      <tr className="bg-dark-bg/40 border-b border-dark-border/40">
                        <td colSpan={10} className="p-6">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-[10px] font-mono text-slate-300">
                            {/* General Details */}
                            <div className="space-y-2.5">
                              <h5 className="text-[11px] font-bold text-cyber-accent uppercase tracking-wider border-b border-dark-border pb-1.5 mb-2 flex items-center justify-between">
                                <span>Finding Analysis</span>
                                <span className="text-[9px] text-slate-500 font-normal normal-case">
                                  Source: {f.source || "nuclei"}
                                </span>
                              </h5>

                              {f.template_name && (
                                <div>
                                  <span className="text-slate-500">Template Name:</span>{" "}
                                  <span className="text-slate-200 font-bold">{f.template_name}</span>
                                </div>
                              )}
                              {(f.source || f.metadata?.source) && (
                                <div>
                                  <span className="text-slate-500">Source:</span>{" "}
                                  <span className="text-slate-300 uppercase font-semibold">{f.source || f.metadata?.source}</span>
                                </div>
                              )}
                              {(f.parameter || f.metadata?.parameter) && (
                                <div>
                                  <span className="text-slate-500">Parameter:</span>{" "}
                                  <span className="text-cyber-warning font-semibold">{f.parameter || f.metadata?.parameter}</span>
                                </div>
                              )}
                              {(f.payload || f.metadata?.payload) && (
                                <div>
                                  <span className="text-slate-500">Payload:</span>{" "}
                                  <span className="text-red-400 select-all break-all">{f.payload || f.metadata?.payload}</span>
                                </div>
                              )}
                              {(f.evidence || f.metadata?.evidence) && (
                                <div>
                                  <span className="text-slate-500">Evidence:</span>{" "}
                                  <pre className="text-slate-400 text-[9px] bg-dark-bg p-2.5 rounded border border-dark-border/50 mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap">
                                    {f.evidence || f.metadata?.evidence}
                                  </pre>
                                </div>
                              )}
                              {f.template_id && (
                                <div>
                                  <span className="text-slate-500">Template ID:</span>{" "}
                                  <span className="text-slate-300">{f.template_id}</span>
                                </div>
                              )}
                              <div>
                                <span className="text-slate-500">Matched URL:</span>{" "}
                                <a
                                  href={f.matched_url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-cyber-accent hover:underline break-all select-all"
                                >
                                  {f.matched_url}
                                </a>
                              </div>
                              <div>
                                <span className="text-slate-500">Target Host:</span>{" "}
                                <a
                                  href={`https://${f.host}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-slate-300 hover:text-cyber-accent hover:underline"
                                >
                                  {f.host}
                                </a>
                              </div>
                              {f.ip && (
                                <div>
                                  <span className="text-slate-500">Resolved IP:</span>{" "}
                                  <span className="text-slate-300">{f.ip}</span>
                                </div>
                              )}
                              {(f.port || f.protocol) && (
                                <div>
                                  <span className="text-slate-500">Port / Protocol:</span>{" "}
                                  <span className="text-slate-300">
                                    {f.port || "-"}/{f.protocol || "-"}
                                  </span>
                                </div>
                              )}
                              {f.tags && f.tags.length > 0 && (
                                <div>
                                  <span className="text-slate-500">Associated Tags:</span>{" "}
                                  <span className="text-slate-400">{(f.tags || []).join(", ")}</span>
                                </div>
                              )}
                              {f.description && (
                                <div>
                                  <span className="text-slate-500">Description:</span>{" "}
                                  <p className="text-slate-400 leading-relaxed mt-1 bg-dark-bg p-2.5 rounded border border-dark-border/50">
                                    {f.description}
                                  </p>
                                </div>
                              )}
                            </div>

                            {/* Vulnerability Metadata & Payloads */}
                            <div className="space-y-2.5">
                              <h5 className="text-[11px] font-bold text-cyber-accent uppercase tracking-wider border-b border-dark-border pb-1.5 mb-2">
                                Vulnerability Classification
                              </h5>

                              {f.cve && (
                                <div>
                                  <span className="text-slate-500">CVE ID:</span>{" "}
                                  <span className="px-1.5 py-0.5 bg-red-950/40 border border-red-900/50 text-red-300 rounded">
                                    {f.cve}
                                  </span>
                                </div>
                              )}
                              {f.cwe && (
                                <div>
                                  <span className="text-slate-500">CWE ID:</span>{" "}
                                  <span className="text-slate-300">{f.cwe}</span>
                                </div>
                              )}
                              {f.cvss && (
                                <div>
                                  <span className="text-slate-500">CVSS Score:</span>{" "}
                                  <span className="text-slate-200 font-bold">{f.cvss}</span>
                                </div>
                              )}
                              {f.pass_name && (
                                <div>
                                  <span className="text-slate-500">Pipeline Pass:</span>{" "}
                                  <span className="text-slate-400">{f.pass_name}</span>
                                </div>
                              )}
                              {f.matcher_name && (
                                <div>
                                  <span className="text-slate-500">Matcher Rule:</span>{" "}
                                  <span className="text-cyber-warning">{f.matcher_name}</span>
                                </div>
                              )}
                              {f.extracted_results && f.extracted_results.length > 0 && (
                                <div>
                                  <span className="text-slate-500">Extracted Matches:</span>{" "}
                                  <span className="text-cyber-success">{(f.extracted_results || []).join(", ")}</span>
                                </div>
                              )}
                              {f.timestamp && (
                                <div>
                                  <span className="text-slate-500">Detected At:</span>{" "}
                                  <span className="text-slate-400">{new Date(f.timestamp).toLocaleString()}</span>
                                </div>
                              )}
                              {f.classification && Object.keys(f.classification).length > 0 && (
                                <div>
                                  <span className="text-slate-500">Classification Object:</span>{" "}
                                  <pre className="text-slate-400 text-[9px] bg-dark-bg p-2 rounded border border-dark-border/40 mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap">
                                    {JSON.stringify(f.classification, null, 2)}
                                  </pre>
                                </div>
                              )}
                              {f.metadata && Object.keys(f.metadata).length > 0 && (
                                <div>
                                  <span className="text-slate-500">Findings Metadata:</span>{" "}
                                  <pre className="text-slate-400 text-[9px] bg-dark-bg p-2 rounded border border-dark-border/40 mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap">
                                    {JSON.stringify(f.metadata, null, 2)}
                                  </pre>
                                </div>
                              )}
                              {f.reference_urls && f.reference_urls.length > 0 && (
                                <div>
                                  <span className="text-slate-500">References:</span>
                                  <ul className="list-disc pl-4 space-y-1 mt-1 text-slate-400 select-all">
                                    {f.reference_urls.map((ref, rIdx) => (
                                      <li key={rIdx}>
                                        <a href={ref} target="_blank" rel="noopener noreferrer" className="text-cyber-accent hover:underline break-all">
                                          {ref}
                                        </a>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>

                            {/* Curl Command & HTTP Request/Response (Full-width) */}
                            {(f.curl_command || f.request || f.response) && (
                              <div className="col-span-1 md:col-span-2 space-y-3.5 mt-3 pt-4 border-t border-dark-border">
                                {f.curl_command && (
                                  <div>
                                    <div className="flex items-center justify-between mb-1">
                                      <span className="text-slate-500 font-bold uppercase tracking-wider text-[9px]">Reproduction cURL Command:</span>
                                      <button
                                        onClick={() => handleCopy(f.curl_command!)}
                                        className="px-2 py-0.5 bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-[9px] text-slate-400 hover:text-white transition-all flex items-center gap-1 cursor-pointer"
                                      >
                                        <Copy className="w-2.5 h-2.5" /> Copy cURL
                                      </button>
                                    </div>
                                    <pre className="bg-dark-bg p-3 rounded border border-dark-border/50 text-slate-300 text-[9px] overflow-x-auto whitespace-pre select-all max-h-24">
                                      {f.curl_command}
                                    </pre>
                                  </div>
                                )}

                                {f.request && (
                                  <div>
                                    <div className="flex items-center justify-between mb-1">
                                      <span className="text-slate-500 font-bold uppercase tracking-wider text-[9px]">HTTP Request Payload:</span>
                                      <button
                                        onClick={() => handleCopy(f.request!)}
                                        className="px-2 py-0.5 bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-[9px] text-slate-400 hover:text-white transition-all flex items-center gap-1 cursor-pointer"
                                      >
                                        <Copy className="w-2.5 h-2.5" /> Copy Request
                                      </button>
                                    </div>
                                    <pre className="bg-dark-bg p-3 rounded border border-dark-border/50 text-slate-300 text-[9px] overflow-x-auto whitespace-pre-wrap select-all max-h-48 overflow-y-auto">
                                      {f.request}
                                    </pre>
                                  </div>
                                )}

                                {f.response && (
                                  <div>
                                    <div className="flex items-center justify-between mb-1">
                                      <span className="text-slate-500 font-bold uppercase tracking-wider text-[9px]">HTTP Response Content:</span>
                                      <button
                                        onClick={() => handleCopy(f.response!)}
                                        className="px-2 py-0.5 bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-[9px] text-slate-400 hover:text-white transition-all flex items-center gap-1 cursor-pointer"
                                      >
                                        <Copy className="w-2.5 h-2.5" /> Copy Response
                                      </button>
                                    </div>
                                    <pre className="bg-dark-bg p-3 rounded border border-dark-border/50 text-slate-300 text-[9px] overflow-x-auto whitespace-pre-wrap select-all max-h-60 overflow-y-auto">
                                      {f.response}
                                    </pre>
                                  </div>
                                )}
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
  );
};
