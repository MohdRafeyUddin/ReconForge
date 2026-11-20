import React, { useState } from "react";
import { Search, Filter, Copy, ChevronDown, ChevronUp, FileText, X, Shield, Layers } from "lucide-react";
import { DnsTab } from "./DnsTab";
import type { DnsRecord } from "./DnsTab";
import { TakeoverTab } from "./TakeoverTab";
import type { TakeoverRecord } from "./TakeoverTab";
import { NormalizedUrlTab } from "./NormalizedUrlTab";
import type { NormalizedUrlRecord } from "./NormalizedUrlTab";
import { GfTab } from "./GfTab";
import type { GfUrlRecord } from "./GfTab";
import { ContentDiscoveryTab } from "./ContentDiscoveryTab";
import type { ContentPathRecord } from "./ContentDiscoveryTab";
import { APITab } from "./APITab";
import { CloudTab } from "./CloudTab";
import { DiscoveredActionPanel } from "./DiscoveredActionPanel";
import { FetchBodyButton } from "./FetchBodyButton";
import { ScreenshotsTab } from "./ScreenshotsTab";
import { NucleiTab } from "./NucleiTab";
import { apiCall, API_BASE_URL } from "../../services/api";
import { HighlightText, ExactMatchBadge, getExactMatchFields } from "../Common/HighlightText";
import { Pagination, usePagination } from "../Common/Pagination";

const getRootDomain = (domain: string): string => {
  if (!domain || typeof domain !== "string") return "";
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
  project_id?: string;
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
  hunt_priority?: number;
  hunt_reasons?: string[];
  status_class?: string;
  is_interesting?: boolean;
  cdn_waf?: {
    is_cdn?: boolean;
    is_waf?: boolean;
    cdn_provider?: string;
    waf_provider?: string;
    exclusion_reason?: string;
  };
  exclusion_reason?: string;
  is_cluster_representative?: boolean;
  is_cluster_member?: boolean;
  cluster_id?: string;
  cluster_size?: number;
  cluster_skip_reason?: string;
  response_body_path?: string;
  services?: any[];
  first_seen?: string;
  last_seen?: string;
}

interface AssetTableProps {
  assets: Asset[];
  projectId?: string;
  projectName?: string;
  dnsRecords?: DnsRecord[];
  takeoverRecords?: TakeoverRecord[];
  normalizedUrlRecords?: NormalizedUrlRecord[];
  gfRecords?: GfUrlRecord[];
  contentPathRecords?: ContentPathRecord[];
  latestScanTime?: string | null;
  initialTab?: InventoryTabId;
  initialSeverityFilter?: string | null;
  onRefresh?: () => void;
}

type InventoryTabId = "assets" | "dns" | "takeovers" | "normalized_urls" | "gf" | "nuclei" | "content_discovery" | "api_endpoints" | "historical_urls" | "js_files" | "screenshots" | "secrets" | "cloud_buckets" | "recon_info";

type InventoryTab = InventoryTabId;

export const AssetTable: React.FC<AssetTableProps> = ({
  assets,
  projectId,
  projectName = "project",
  dnsRecords = [],
  takeoverRecords = [],
  normalizedUrlRecords = [],
  gfRecords = [],
  contentPathRecords = [],
  latestScanTime = null,
  initialTab,
  initialSeverityFilter = null,
  onRefresh,
}) => {
  const [activeInventoryTab, setActiveInventoryTab] = useState<InventoryTab>(initialTab || "assets");
  const [search, setSearch] = useState("");
  const [historicalSearch, setHistoricalSearch] = useState("");
  const [jsSearch, setJsSearch] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [assetPage, setAssetPage] = useState(1);
  const [assetPageSize, setAssetPageSize] = useState(20);
  const [expandedBodies, setExpandedBodies] = useState<Record<string, { loading: boolean; error: string | null; content: string | null }>>({});
  const [screenshotModal, setScreenshotModal] = useState<{ src: string; title: string; url: string } | null>(null);
  const [screenshotsRefreshNonce, setScreenshotsRefreshNonce] = useState(0);
  const [activeTabs, setActiveTabs] = useState<Record<string, string>>({});
  const [showExportDropdown, setShowExportDropdown] = useState(false);
  const [sortField, setSortField] = useState<string | null>("status");
  const [sortAsc, setSortAsc] = useState<boolean>(false);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const handleCopyTopHosts = (count: number = 10) => {
    const sorted = [...assets]
      .filter(a => {
        const type = (a.type || "").toLowerCase();
        const metadata = (a.metadata || {}) as any;
        const statusCode = metadata.status_code ?? (a as any).status_code;
        const isPassive = ["candidate", "passive_candidate"].includes((a.status || "").toLowerCase()) || Boolean(metadata.passive_candidate);
        return (
          Boolean(a.domain) &&
          ["subdomain", "host"].includes(type) &&
          a.status === "live" &&
          statusCode !== undefined && statusCode !== null &&
          !isPassive
        );
      })
      .sort((a, b) => ((b.hunt_priority ?? 0) - (a.hunt_priority ?? 0)))
      .slice(0, count);
    const text = sorted.map(a => a.domain).join("\n");
    navigator.clipboard.writeText(text);
    alert(`Copied top ${sorted.length} hunt target hosts to clipboard!`);
  };

  const [responseBodyModal, setResponseBodyModal] = useState<{
    asset: Asset;
    content: string | null;
    loading: boolean;
    error: string | null;
  } | null>(null);

  const handleOpenResponseBody = async (asset: Asset) => {
    const pId = projectId || asset.project_id || (asset as any).projectId;
    if (!pId) {
      setResponseBodyModal({
        asset,
        content: null,
        loading: false,
        error: "Missing project ID to retrieve response body.",
      });
      return;
    }
    setResponseBodyModal({
      asset,
      content: null,
      loading: true,
      error: null,
    });
    try {
      const data = await apiCall(`/assets/project/${pId}/asset/${asset.id}/response-body`);
      setResponseBodyModal({
        asset,
        content: data.content ?? "(Empty response body)",
        loading: false,
        error: null,
      });
    } catch (err: any) {
      setResponseBodyModal({
        asset,
        content: null,
        loading: false,
        error: err.message || "Failed to load response body",
      });
    }
  };

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

  const loadExpandedBody = async (asset: Asset) => {
    const pId = projectId || asset.project_id;
    const hasBody = asset.metadata?.response_body_path || asset.response_body_path;
    if (!pId || !hasBody) return;
    let alreadyLoaded = false;
    setExpandedBodies((prev) => {
      alreadyLoaded = Boolean(prev[asset.id]);
      if (alreadyLoaded) return prev;
      return { ...prev, [asset.id]: { loading: true, error: null, content: null } };
    });
    if (alreadyLoaded) return;
    try {
      const data = await apiCall(`/assets/project/${pId}/asset/${asset.id}/response-body`);
      setExpandedBodies((prev) => ({
        ...prev,
        [asset.id]: { loading: false, error: null, content: data.content ?? "(Empty response body)" },
      }));
    } catch (err: any) {
      setExpandedBodies((prev) => ({
        ...prev,
        [asset.id]: { loading: false, error: err.message || "Failed to load response body", content: null },
      }));
    }
  };

  const toggleExpand = (id: string) => {
    const next = expandedId === id ? null : id;
    setExpandedId(next);
    if (next) {
      const asset = assets.find((a) => a.id === id);
      if (asset) loadExpandedBody(asset);
    }
  };

  const baseFilteredAssets = assets.filter((asset) => {
    // Only core target assets belong in the main Assets table; secondary types have their own dedicated sub-tabs
    if (["js_file", "screenshot", "finding", "historical_url", "historical_dead", "unprobed_url", "uro_url", "gf_url", "content_path", "dns_record"].includes(asset.type)) {
      return false;
    }
    // Passive-only candidates have no HTTP status, DNS record, IP or ports;
    // keep the Assets table focused on actionable infrastructure.
    if (
      asset.type === "subdomain" &&
      ["candidate", "unknown"].includes(String(asset.status || "").toLowerCase()) &&
      !asset.metadata?.url &&
      !asset.metadata?.dnsx &&
      !(asset.open_ports?.length)
    ) {
      return false;
    }
    const q = search.toLowerCase().trim();
    const domainStr = asset.domain || (asset as any).value || "";
    const meta = asset.metadata || {};
    const openPorts = asset.open_ports || meta.open_ports || [];
    const tech = meta.technologies || [];
    const reasons = asset.hunt_reasons || (asset as any).risk?.reasons || [];
    const matchesSearch = !q ? true : (
      domainStr.toLowerCase().includes(q) ||
      (meta.url && String(meta.url).toLowerCase().includes(q)) ||
      (meta.ip_address && String(meta.ip_address).toLowerCase().includes(q)) ||
      (meta.ip && String(meta.ip).toLowerCase().includes(q)) ||
      openPorts.some((p: any) => String(p).includes(q)) ||
      tech.some((t: string) => (t || "").toLowerCase().includes(q)) ||
      (meta.title && String(meta.title).toLowerCase().includes(q)) ||
      (meta.server && String(meta.server).toLowerCase().includes(q)) ||
      (meta.web_server && String(meta.web_server).toLowerCase().includes(q)) ||
      (meta.status_code !== undefined && String(meta.status_code).includes(q)) ||
      (asset.status && String(asset.status).toLowerCase().includes(q)) ||
      (asset.discovered_by && String(asset.discovered_by).toLowerCase().includes(q)) ||
      (asset.type && String(asset.type).toLowerCase().includes(q)) ||
      reasons.some((r: string) => (r || "").toLowerCase().includes(q)) ||
      ((asset as any).risk?.level && String((asset as any).risk.level).toLowerCase().includes(q))
    );
    const matchesType = filterType === "all" || asset.type === filterType;
    const matchesStatus = filterStatus === "all" || asset.status === filterStatus;
    
    return matchesSearch && matchesType && matchesStatus;
  });

  const filteredAssets = React.useMemo(() => {
    if (!sortField) return baseFilteredAssets;
    return [...baseFilteredAssets].sort((a, b) => {
      let aVal: any = 0;
      let bVal: any = 0;
      if (sortField === "hunt_priority") {
        aVal = a.hunt_priority ?? -1;
        bVal = b.hunt_priority ?? -1;
      } else if (sortField === "domain") {
        aVal = (a.domain || "").toLowerCase();
        bVal = (b.domain || "").toLowerCase();
      } else if (sortField === "status") {
        aVal = a.metadata?.status_code ?? (a as any).status_code ?? -1;
        bVal = b.metadata?.status_code ?? (b as any).status_code ?? -1;
      } else if (sortField === "ip") {
        aVal = a.metadata?.ip || a.metadata?.ip_address || a.metadata?.dnsx?.a?.[0] || "";
        bVal = b.metadata?.ip || b.metadata?.ip_address || b.metadata?.dnsx?.a?.[0] || "";
      } else if (sortField === "ports") {
        aVal = (a.open_ports?.length ? a.open_ports : a.metadata?.open_ports || []).length;
        bVal = (b.open_ports?.length ? b.open_ports : b.metadata?.open_ports || []).length;
      }
      if (aVal < bVal) return sortAsc ? -1 : 1;
      if (aVal > bVal) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [baseFilteredAssets, sortField, sortAsc]);

  const exactMainAssetMatches = React.useMemo(() => {
    if (!search.trim()) return 0;
    return filteredAssets.filter((a) => getExactMatchFields(a, search).length > 0).length;
  }, [filteredAssets, search]);

  const screenshotByHost = React.useMemo(() => {
    const origin = API_BASE_URL.replace(/\/api\/v1\/?$/, "");
    const map: Record<string, { src: string; title: string; url: string; timestamp: string }> = {};
    for (const a of assets) {
      const meta = a.metadata || {};
      const hasScreenshotData = a.type === "screenshot"
        || Boolean(meta.filename && meta.run_id && meta.screenshot_path);
      if (!hasScreenshotData) continue;
      const host = String(meta.host || a.domain || "").toLowerCase();
      const filename = meta.filename || String(meta.screenshot_path || "").split("/").pop();
      const runId = meta.run_id;
      if (!projectId || !host || !filename || !runId) continue;
      const ts = String(meta.timestamp || a.updated_at || a.created_at || "");
      if (map[host] && map[host].timestamp >= ts) continue;
      map[host] = {
        src: `${origin}/api/v1/assets/project/${projectId}/screenshots/${runId}/${filename}`,
        title: meta.title || `Screenshot of ${host}`,
        url: meta.url || a.domain || host,
        timestamp: ts,
      };
    }
    return map;
  }, [assets, projectId]);

  const assetTotalPages = Math.max(1, Math.ceil(filteredAssets.length / assetPageSize));
  const assetSafePage = Math.min(assetPage, assetTotalPages);
  const pagedAssets = React.useMemo(
    () => filteredAssets.slice((assetSafePage - 1) * assetPageSize, assetSafePage * assetPageSize),
    [filteredAssets, assetSafePage, assetPageSize]
  );

  React.useEffect(() => {
    setAssetPage(1);
  }, [search, filterType, filterStatus, sortField, sortAsc, assetPageSize]);


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
    const files: { url: string; host: string; size: any; source: string }[] = [];
    const seen = new Set<string>();

    const addFile = (url: string, host: string, size: any, source: string) => {
      const clean = String(url || "").trim();
      if (!clean || seen.has(clean)) return;
      seen.add(clean);
      let resolvedHost = host;
      if (!resolvedHost) {
        try {
          resolvedHost = new URL(clean, "https://placeholder").hostname;
        } catch {
          resolvedHost = "";
        }
      }
      files.push({ url: clean, host: resolvedHost, size: size || "unknown", source: source || "unknown" });
    };

    // Stored js_file assets (JS analysis / SubJS / source maps)
    assets.filter((a) => a.type === "js_file").forEach((a) => {
      const meta = a.metadata || {};
      addFile(meta.url || (a as any).value || a.domain, meta.host || "", meta.size, meta.source || a.discovered_by || "subjs");
    });

    // Katana also records JS files on the host asset itself.
    assets.filter((a) => a.type === "subdomain" || a.type === "host").forEach((a) => {
      const list = (a.metadata?.katana?.js_files || []) as string[];
      for (const jsUrl of list) {
        addFile(jsUrl, a.domain || "", "unknown", "katana");
      }
    });

    return files;
  }, [assets]);

  const filteredHistoricalUrls = React.useMemo(() => {
    const q = historicalSearch.toLowerCase().trim();
    if (!q) return historicalUrls;
    return historicalUrls.filter((u) => {
      const matchUrl = u.url.toLowerCase().includes(q);
      const matchParams = (u.has_params ? "yes params parameter" : "no").includes(q);
      const matchExt = (u.extension || "").toLowerCase().includes(q);
      const matchSources = (u.sources || [u.source]).some((s: string) => (s || "").toLowerCase().includes(q));
      return matchUrl || matchParams || matchExt || matchSources;
    });
  }, [historicalUrls, historicalSearch]);

  const filteredJavascriptFiles = React.useMemo(() => {
    const q = jsSearch.toLowerCase().trim();
    if (!q) return javascriptFiles;
    return javascriptFiles.filter((j) => {
      return (
        j.url.toLowerCase().includes(q) ||
        (j.host || "").toLowerCase().includes(q) ||
        (j.source || "").toLowerCase().includes(q)
      );
    });
  }, [javascriptFiles, jsSearch]);

  const contentDiscoveryList = React.useMemo(() => {
    if (contentPathRecords && contentPathRecords.length > 0) {
      return contentPathRecords;
    }
    return assets.filter(a => a.type === "content_path").map(a => ({
      value: a.domain || a.metadata?.url || (a as any).value || "",
      host: a.metadata?.host || a.domain || "",
      status_code: a.metadata?.status_code || (a as any).status_code,
      content_length: a.metadata?.content_length || (a as any).content_length || 0,
      words: a.metadata?.words || (a as any).words || 0,
      lines: a.metadata?.lines || (a as any).lines || 0,
      redirect_location: a.metadata?.redirect_location || (a as any).redirect_location || "",
      calibration_used: a.metadata?.calibration_used ?? true,
      first_seen: a.created_at || (a as any).first_seen,
      last_seen: a.updated_at || (a as any).last_seen,
    }));
  }, [assets, contentPathRecords]);

  // Phase 8 — masked secrets, cloud bucket candidates and info-level recon assets
  const secretRecords = React.useMemo(() => {
    return assets.filter(a => ["secret_finding", "secret"].includes(a.type)).map((a) => ({
      id: a.id,
      host: a.metadata?.host || a.domain || "",
      detector: a.metadata?.secret_type || a.metadata?.detector || "secret",
      location: a.metadata?.location || `${a.metadata?.location_url || ""}:${a.metadata?.line || 0}`,
      prefix: a.metadata?.masked_preview || a.metadata?.prefix || "",
      verified: false,
      severity: a.metadata?.severity || "medium",
      scanner: a.metadata?.scanner || a.discovered_by || "secrets",
      url: a.metadata?.location_url || a.metadata?.url || "",
      first_seen: a.first_seen || a.created_at,
      last_seen: a.last_seen || a.updated_at,
    }));
  }, [assets]);

  const reconInfoRecords = React.useMemo(() => {
    return assets.filter(a => a.type === "recon_info").map((a) => ({
      template_id: a.metadata?.template_id || "",
      template_name: a.metadata?.template_name || a.metadata?.template_id || "Info",
      matched_url: a.metadata?.matched_url || "",
      host: a.metadata?.host || a.domain || "",
      tags: a.metadata?.tags || [],
      timestamp: a.metadata?.timestamp || a.first_seen || a.created_at,
    }));
  }, [assets]);

  const historicalPager = usePagination(filteredHistoricalUrls, 20, historicalSearch);
  const jsPager = usePagination(filteredJavascriptFiles, 20, jsSearch);
  const secretPager = usePagination(secretRecords, 20);
  const reconPager = usePagination(reconInfoRecords, 20);

  const inventoryTabs: { id: InventoryTab; label: string; count?: number }[] = [
    { id: "assets", label: "Assets", count: filteredAssets.length },
    { id: "dns", label: "DNS", count: dnsRecords.length },
    { id: "takeovers", label: "Takeovers", count: takeoverRecords.length },
    { id: "content_discovery", label: "Content Discovery", count: contentDiscoveryList.length },
    { id: "api_endpoints", label: "API" },
    { id: "normalized_urls", label: "Normalized URLs", count: displayedNormalizedUrls.length },
    { id: "gf", label: "Interesting URLs", count: gfTotalCount },
    { id: "secrets", label: "Secrets", count: secretRecords.length },
    { id: "cloud_buckets", label: "Cloud" },
    { id: "historical_urls", label: "Historical URLs", count: historicalUrls.length },
    { id: "js_files", label: "JS Files", count: javascriptFiles.length },
    { id: "screenshots", label: "Screenshots" },
  ];

  return (
    <div className="space-y-4">
      {/* Always-visible targeted actions on extracted URLs */}
      <DiscoveredActionPanel
        projectId={projectId}
        assets={assets}
        onRefresh={onRefresh}
        dnsRecordCount={dnsRecords.length}
        onOpenInventoryTab={(tab) => {
          setActiveInventoryTab(tab);
          if (tab === "screenshots") {
            setScreenshotsRefreshNonce((nonce) => nonce + 1);
          }
        }}
      />

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
        {projectId && (
          <div className="ml-auto flex items-center gap-1.5 pl-2">
            <a
              href={`${API_BASE_URL}/reports/project/${projectId}/export/urls`}
              className="px-2.5 py-1.5 rounded border border-dark-border text-[10px] font-mono font-bold uppercase tracking-wider text-slate-300 hover:text-cyber-accent hover:border-cyber-accent/50 transition-colors whitespace-nowrap"
              title="Download an in-scope URL list (Burp/ZAP importable)"
            >
              Export URLs
            </a>
            <a
              href={`${API_BASE_URL}/reports/project/${projectId}/export/burp`}
              className="px-2.5 py-1.5 rounded border border-dark-border text-[10px] font-mono font-bold uppercase tracking-wider text-slate-300 hover:text-cyber-accent hover:border-cyber-accent/50 transition-colors whitespace-nowrap"
              title="Download a Burp/ZAP XML URL export"
            >
              Burp XML
            </a>
          </div>
        )}
      </div>

      {/* DNS Tab */}
      {activeInventoryTab === "dns" && (
        <DnsTab records={dnsRecords} projectName={projectName} />
      )}

      {/* Takeovers Tab */}
      {activeInventoryTab === "takeovers" && (
        <TakeoverTab records={takeoverRecords} projectName={projectName} />
      )}

      {/* Content Discovery Tab */}
      {activeInventoryTab === "content_discovery" && (
        <ContentDiscoveryTab
          records={contentDiscoveryList}
          projectId={projectId}
          projectName={projectName}
          latestScanTime={latestScanTime}
        />
      )}

      {/* API endpoints tab */}
      {activeInventoryTab === "api_endpoints" && (
        <APITab projectId={projectId} />
      )}

      {/* Normalized URLs Tab */}
      {activeInventoryTab === "normalized_urls" && (
        <NormalizedUrlTab
          records={displayedNormalizedUrls}
          projectId={projectId}
          projectName={projectName}
        />
      )}

      {/* GF Interesting URLs Tab */}
      {activeInventoryTab === "gf" && (
        <GfTab
          records={gfRecords}
          projectId={projectId}
          projectName={projectName}
        />
      )}

      {/* Security Findings Tab */}
      {activeInventoryTab === "nuclei" && (
        <NucleiTab
          findings={nucleiFindings}
          projectName={projectName}
          initialSeverityFilter={initialSeverityFilter}
        />
      )}

      {/* Phase 8: Recon Info Tab */}
      {activeInventoryTab === "recon_info" && (
        <div className="bg-dark-card border border-dark-border rounded-xl glass p-4">
          <div className="border-b border-dark-border pb-3 mb-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-cyber-accent">Reconnaissance Context</h3>
            <span className="text-[10px] font-mono text-slate-500">{reconInfoRecords.length} info-level Nuclei match(es) — not scored as vulnerabilities</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="p-3">Template</th>
                  <th className="p-3">Matched URL</th>
                  <th className="p-3">Host</th>
                  <th className="p-3">Tags</th>
                </tr>
              </thead>
              <tbody>
                {reconInfoRecords.length === 0 ? (
                  <tr><td colSpan={4} className="p-6 text-center text-slate-500 uppercase tracking-widest font-mono text-[10px]">No info-level matches yet.</td></tr>
                ) : reconPager.pageItems.map((rec, idx) => (
                  <tr key={`${rec.template_id}-${idx}`} className="border-b border-dark-border/50 hover:bg-dark-hover/30 font-mono text-[11px]">
                    <td className="p-3 text-slate-300">{rec.template_name || rec.template_id}</td>
                    <td className="p-3 break-all">
                      {rec.matched_url ? (
                        <a href={rec.matched_url} target="_blank" rel="noopener noreferrer" className="text-cyber-accent hover:underline">{rec.matched_url}</a>
                      ) : "-"}
                    </td>
                    <td className="p-3 text-slate-300">{rec.host || "-"}</td>
                    <td className="p-3 text-slate-500">{(rec.tags || []).join(", ") || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            page={reconPager.page}
            pageSize={reconPager.pageSize}
            total={reconPager.total}
            onPageChange={reconPager.setPage}
            onPageSizeChange={reconPager.setPageSize}
            itemLabel="recon match(es)"
          />
        </div>
      )}

      {/* Phase 8: Secrets Tab (masked values only) */}
      {activeInventoryTab === "secrets" && (
        <div className="bg-dark-card border border-dark-border rounded-xl glass p-4">
          <div className="border-b border-dark-border pb-3 mb-4">
            <h3 className="text-xs font-mono uppercase tracking-wider text-cyber-accent">Secret Candidates</h3>
            <span className="text-[10px] font-mono text-slate-500">
              {secretRecords.length} masked candidate(s). Raw secret values are never stored, logged or exported.
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="p-3">Detector</th>
                  <th className="p-3">Prefix</th>
                  <th className="p-3">Host</th>
                  <th className="p-3">Location</th>
                  <th className="p-3">Verified</th>
                  <th className="p-3">Scanner</th>
                </tr>
              </thead>
              <tbody>
                {secretRecords.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-6 text-center text-slate-500 font-mono text-[10px]">
                      <div className="uppercase tracking-widest">No secret candidates found</div>
                      <div className="mt-2 normal-case text-slate-600 max-w-2xl mx-auto leading-relaxed">
                        Secrets are detected only in stored HTTP response bodies and JS files
                        (trufflehog/gitleaks). FFUF hits and historical URLs are not saved as
                        response bodies by default, so there is nothing to scan until a page
                        containing a credential is stored.
                      </div>
                    </td>
                  </tr>
                ) : secretPager.pageItems.map((rec) => (
                  <tr key={rec.id} className="border-b border-dark-border/50 hover:bg-dark-hover/30 font-mono text-[11px]">
                    <td className="p-3 text-slate-200 font-bold">{rec.detector}</td>
                    <td className="p-3 text-cyber-warning select-none">{rec.prefix || "****"}</td>
                    <td className="p-3 text-slate-300 break-all">{rec.host || "-"}</td>
                    <td className="p-3 text-slate-400 break-all">{rec.location || "-"}</td>
                    <td className="p-3">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${rec.verified ? "bg-cyber-danger/20 border-cyber-danger/40 text-cyber-danger" : "bg-slate-500/10 border-slate-500/30 text-slate-400"}`}>
                        {rec.verified ? "VERIFIED" : "UNVERIFIED"}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">{rec.scanner}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            page={secretPager.page}
            pageSize={secretPager.pageSize}
            total={secretPager.total}
            onPageChange={secretPager.setPage}
            onPageSizeChange={secretPager.setPageSize}
            itemLabel="secret candidate(s)"
          />
        </div>
      )}

      {/* Cloud services, cloud URLs and bucket candidates */}
      {activeInventoryTab === "cloud_buckets" && (
        <CloudTab projectId={projectId} />
      )}

      {/* Historical URLs Tab */}
      {activeInventoryTab === "historical_urls" && (
        <div className="bg-dark-card border border-dark-border rounded-xl glass p-4">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4 border-b border-dark-border pb-3">
            <div>
              <h3 className="text-xs font-mono uppercase tracking-wider text-cyber-accent">Historical URL Inventory</h3>
              <span className="text-[10px] font-mono text-slate-500">{filteredHistoricalUrls.length} / {historicalUrls.length} total entries</span>
            </div>
            <div className="relative w-full sm:w-72">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                <Search className="w-3.5 h-3.5" />
              </span>
              <input
                type="text"
                placeholder="Search URLs, params, ext, source..."
                value={historicalSearch}
                onChange={(e) => setHistoricalSearch(e.target.value)}
                className="w-full bg-dark-input border border-dark-border rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent font-mono"
              />
            </div>
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
                {filteredHistoricalUrls.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-6 text-center text-slate-500 uppercase tracking-widest font-mono text-[10px]">
                      {historicalUrls.length === 0 ? "No historical URLs discovered yet." : "No historical URLs match your search."}
                    </td>
                  </tr>
                ) : (
                  historicalPager.pageItems.map((urlObj, idx) => {
                    const exactMatch = Boolean(
                      historicalSearch.trim() &&
                      (urlObj.url.toLowerCase() === historicalSearch.trim().toLowerCase() ||
                       (urlObj.extension && urlObj.extension.toLowerCase() === historicalSearch.trim().toLowerCase()) ||
                       urlObj.sources.some((s: string) => s.toLowerCase() === historicalSearch.trim().toLowerCase()))
                    );

                    return (
                      <tr key={idx} className="border-b border-dark-border/50 hover:bg-dark-hover/30 transition-colors font-mono text-[11px]">
                        <td className="p-3 break-all select-all text-slate-300">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <a href={urlObj.url} target="_blank" rel="noopener noreferrer" className="text-cyber-accent hover:underline">
                              <HighlightText text={urlObj.url} highlight={historicalSearch} />
                            </a>
                            <FetchBodyButton projectId={projectId} url={urlObj.url} compact />
                            {exactMatch && <ExactMatchBadge />}
                          </div>
                        </td>
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
                              <HighlightText text={urlObj.extension} highlight={historicalSearch} />
                            </span>
                          ) : (
                            <span className="text-slate-600">-</span>
                          )}
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap gap-1">
                            {urlObj.sources.map((src: string) => (
                              <span key={src} className="px-1.5 py-0.5 bg-blue-500/15 border border-blue-500/35 text-blue-400 rounded text-[9px] uppercase font-semibold">
                                <HighlightText text={src} highlight={historicalSearch} />
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <Pagination
            page={historicalPager.page}
            pageSize={historicalPager.pageSize}
            total={historicalPager.total}
            onPageChange={historicalPager.setPage}
            onPageSizeChange={historicalPager.setPageSize}
            itemLabel="historical URL(s)"
          />
        </div>
      )}

      {/* JavaScript Files Tab */}
      {activeInventoryTab === "js_files" && (
        <div className="bg-dark-card border border-dark-border rounded-xl glass p-4">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4 border-b border-dark-border pb-3">
            <div>
              <h3 className="text-xs font-mono uppercase tracking-wider text-cyber-accent">JavaScript File Inventory</h3>
              <span className="text-[10px] font-mono text-slate-500">{filteredJavascriptFiles.length} / {javascriptFiles.length} total files</span>
            </div>
            <div className="relative w-full sm:w-72">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                <Search className="w-3.5 h-3.5" />
              </span>
              <input
                type="text"
                placeholder="Search JS files, host, source..."
                value={jsSearch}
                onChange={(e) => setJsSearch(e.target.value)}
                className="w-full bg-dark-input border border-dark-border rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent font-mono"
              />
            </div>
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
                {filteredJavascriptFiles.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="p-6 text-center text-slate-500 uppercase tracking-widest font-mono text-[10px]">
                      {javascriptFiles.length === 0 ? "No JavaScript files discovered yet." : "No JavaScript files match your search."}
                    </td>
                  </tr>
                ) : (
                  jsPager.pageItems.map((jsObj, idx) => {
                    const exactMatch = Boolean(
                      jsSearch.trim() &&
                      (jsObj.url.toLowerCase() === jsSearch.trim().toLowerCase() ||
                       (jsObj.host && jsObj.host.toLowerCase() === jsSearch.trim().toLowerCase()) ||
                       (jsObj.source && jsObj.source.toLowerCase() === jsSearch.trim().toLowerCase()))
                    );

                    return (
                      <tr key={idx} className="border-b border-dark-border/50 hover:bg-dark-hover/30 transition-colors font-mono text-[11px]">
                        <td className="p-3 break-all select-all text-slate-300">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <a href={jsObj.url} target="_blank" rel="noopener noreferrer" className="text-cyber-accent hover:underline">
                              <HighlightText text={jsObj.url} highlight={jsSearch} />
                            </a>
                            {exactMatch && <ExactMatchBadge />}
                          </div>
                        </td>
                        <td className="p-3 text-slate-400">
                          <HighlightText text={jsObj.host} highlight={jsSearch} />
                        </td>
                        <td className="p-3">
                          <span className="px-1.5 py-0.5 bg-blue-500/15 border border-blue-500/35 text-blue-400 rounded text-[9px] uppercase font-semibold">
                            <HighlightText text={jsObj.source} highlight={jsSearch} />
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <Pagination
            page={jsPager.page}
            pageSize={jsPager.pageSize}
            total={jsPager.total}
            onPageChange={jsPager.setPage}
            onPageSizeChange={jsPager.setPageSize}
            itemLabel="JS file(s)"
          />
        </div>
      )}

      {/* Screenshots Tab */}
      {activeInventoryTab === "screenshots" && (
        <ScreenshotsTab
          projectId={projectId}
          refreshNonce={screenshotsRefreshNonce}
        />
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
            placeholder="Search assets, IPs, ports, tech, status, reasons..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-input border border-dark-border rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyber-accent"
          />
          {search.trim() && (
            <div className="text-[10px] font-mono mt-1 flex items-center gap-1.5">
              {exactMainAssetMatches > 0 ? (
                <span className="text-amber-300 font-bold">🎯 {exactMainAssetMatches} exact match{exactMainAssetMatches === 1 ? "" : "es"}</span>
              ) : (
                <span className="text-slate-400">Partial matches</span>
              )}
              <span className="text-slate-500">• {filteredAssets.length} total</span>
            </div>
          )}
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

          
          <button
            onClick={() => handleCopyTopHosts(10)}
            className="bg-dark-input hover:bg-dark-hover border border-dark-border rounded text-xs px-2.5 py-1.5 text-cyber-accent hover:text-white transition-all flex items-center gap-1.5 cursor-pointer font-semibold"
            title="Copy top 10 highest hunt-priority hostnames to clipboard"
          >
            🎯 Copy Top 10 Hosts
          </button>

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
              <th className="p-4 cursor-pointer hover:text-cyber-accent select-none" onClick={() => handleSort("domain")}>Asset / URL {sortField === "domain" ? (sortAsc ? "▲" : "▼") : ""}</th>
              <th className="p-4 cursor-pointer hover:text-cyber-accent select-none" onClick={() => handleSort("status")}>Status & Code {sortField === "status" ? (sortAsc ? "▲" : "▼") : ""}</th>
              <th className="p-4 cursor-pointer hover:text-cyber-accent select-none" onClick={() => handleSort("ip")}>IP Address {sortField === "ip" ? (sortAsc ? "▲" : "▼") : ""}</th>
              <th className="p-4 cursor-pointer hover:text-cyber-accent select-none" onClick={() => handleSort("ports")}>Open Ports {sortField === "ports" ? (sortAsc ? "▲" : "▼") : ""}</th>
            </tr>
          </thead>
          <tbody>
            {filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono">
                  No assets match current criteria
                </td>
              </tr>
            ) : (
              pagedAssets.map((asset) => {
                const isExpanded = expandedId === asset.id;
                const ip =
                  asset.metadata?.ip_address ||
                  asset.metadata?.ip ||
                  asset.metadata?.dnsx?.a?.[0] ||
                  asset.metadata?.dnsx?.aaaa?.[0] ||
                  (asset as any).resolved_ip ||
                  "—";
                const assetPorts: number[] =
                  asset.open_ports?.length
                    ? asset.open_ports
                    : asset.metadata?.open_ports || [];
                const hasExposedPorts = assetPorts.some(p => [22, 21, 23, 3389].includes(p));
                const exactFields = getExactMatchFields(asset, search);

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
                        <div className="flex flex-col gap-1.5">
                          <div className="flex items-center space-x-2 flex-wrap">
                            <a
                              href={(asset.domain || "").startsWith("http://") || (asset.domain || "").startsWith("https://") ? (asset.domain || "") : `https://${asset.domain || ""}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="hover:text-cyber-accent hover:underline transition-colors break-all"
                            >
                              <HighlightText text={asset.domain || ""} highlight={search} />
                            </a>
                            {exactFields.length > 0 && <ExactMatchBadge fields={exactFields} />}
                            <button
                              onClick={() => handleCopy(asset.domain || "")}
                              className="text-slate-500 hover:text-cyber-accent transition-colors cursor-pointer"
                              title="Copy Domain"
                            >
                              <Copy className="w-3.5 h-3.5" />
                            </button>
                            {(asset.metadata?.response_body_path || asset.response_body_path) ? (
                              <button
                                onClick={() => handleOpenResponseBody(asset)}
                                className="px-1.5 py-0.5 rounded bg-cyan-500/15 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 text-[9px] font-mono flex items-center gap-1 transition-all cursor-pointer shadow-sm"
                                title="View stored HTTP response body"
                              >
                                <FileText className="w-3 h-3" />
                                Body
                              </button>
                            ) : (
                              <FetchBodyButton
                                projectId={projectId}
                                url={asset.metadata?.url || `https://${asset.domain}`}
                                compact
                              />
                            )}
                          </div>
                          {/* Badges row: CDN/WAF and Cluster Rep/Member */}
                          <div className="flex flex-wrap gap-1 items-center">
                            {(() => {
                              const cdnWaf = asset.cdn_waf || asset.metadata?.cdn_waf;
                              const cdnName = cdnWaf?.cdn_provider || cdnWaf?.waf_provider || asset.metadata?.cdn_provider || asset.metadata?.waf_provider;
                              const reason = cdnWaf?.exclusion_reason || asset.exclusion_reason || asset.metadata?.exclusion_reason;
                              if (!cdnName) return null;
                              return (
                                <span
                                  className="px-1.5 py-0.25 rounded bg-purple-500/15 border border-purple-500/35 text-purple-300 font-mono text-[9px] flex items-center gap-1 cursor-help"
                                  title={reason || `Protected by ${cdnName}. Excluded from wide port scans.`}
                                >
                                  <Shield className="w-2.5 h-2.5" />
                                  {cdnName}
                                </span>
                              );
                            })()}
                            {(asset.is_cluster_representative || asset.metadata?.is_cluster_representative) && (
                              <span
                                className="px-1.5 py-0.25 rounded bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 font-mono text-[9px] font-bold flex items-center gap-1"
                                title={`Cluster Representative (${asset.cluster_size || asset.metadata?.cluster_size || 1} similar hosts)`}
                              >
                                <Layers className="w-2.5 h-2.5" />
                                Rep ({asset.cluster_size || asset.metadata?.cluster_size || 1})
                              </span>
                            )}
                            {((asset.is_cluster_member || asset.metadata?.is_cluster_member) && !(asset.is_cluster_representative || asset.metadata?.is_cluster_representative)) && (
                              <span
                                className="px-1.5 py-0.25 rounded bg-blue-500/15 border border-blue-500/35 text-blue-300 font-mono text-[9px] flex items-center gap-1 cursor-help"
                                title={asset.cluster_skip_reason || asset.metadata?.cluster_skip_reason || "Cluster member: duplicate of leader. Expensive crawl & scan skipped."}
                              >
                                👥 Member (Skipped)
                              </span>
                            )}
                          </div>
                          {screenshotByHost[(asset.domain || "").toLowerCase()] && (
                            <button
                              onClick={() => {
                                const shot = screenshotByHost[(asset.domain || "").toLowerCase()];
                                setScreenshotModal({ src: shot.src, title: shot.title, url: shot.url });
                              }}
                              className="mt-1.5 block rounded border border-dark-border overflow-hidden hover:border-cyber-accent/60 transition-colors cursor-zoom-in"
                              title="Open screenshot"
                            >
                              <img
                                src={screenshotByHost[(asset.domain || "").toLowerCase()].src}
                                alt={`Screenshot of ${asset.domain}`}
                                className="w-28 h-16 object-cover"
                                loading="lazy"
                              />
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="p-4">
                        {(() => {
                          const statusCode = asset.metadata?.status_code !== undefined ? asset.metadata.status_code : (asset as any).status_code;
                          const isInteresting = asset.is_interesting || asset.metadata?.is_interesting || (statusCode === 401 || statusCode === 403);
                          const statusClass = asset.status_class || asset.metadata?.status_class;
                          return (
                            <div className="flex flex-col gap-1 items-start">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                                  asset.status === "live"
                                    ? "bg-cyber-success/10 border border-cyber-success/30 text-cyber-success"
                                    : asset.status === "stale"
                                    ? "bg-amber-500/10 border border-amber-500/30 text-amber-400"
                                    : asset.status === "unknown"
                                    ? "bg-slate-500/10 border border-slate-500/30 text-slate-400"
                                    : "bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger"
                                }`}>
                                  {asset.status || asset.metadata?.status || "unknown"}
                                </span>
                                {statusCode !== undefined ? (
                                  <span className="px-1.5 py-0.5 rounded bg-dark-bg border border-dark-border text-slate-200 font-mono text-[10px]">
                                    <HighlightText text={statusCode} highlight={search} />
                                  </span>
                                ) : asset.status === "resolved" ? (
                                  <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono text-[9px] uppercase">
                                    DNS resolved
                                  </span>
                                ) : null}
                              </div>
                              {isInteresting && (
                                <span
                                  className="px-1.5 py-0.25 rounded bg-amber-500/20 border border-amber-500/40 text-amber-300 font-mono text-[9px] font-bold"
                                  title="Interesting Auth/Forbidden Target (401/403)"
                                >
                                  ★ Interesting
                                </span>
                              )}
                              {statusClass && (
                                <span className="text-[9px] text-slate-500 font-mono">
                                  <HighlightText text={statusClass} highlight={search} />
                                </span>
                              )}
                            </div>
                          );
                        })()}
                      </td>
                      <td className="p-4 font-mono text-slate-300">
                        <HighlightText text={ip} highlight={search} />
                      </td>
                      <td className="p-4 font-mono">
                        <div className="flex flex-wrap gap-1">
                          {assetPorts.length === 0 ? (
                            <span className="text-slate-500 font-sans">-</span>
                          ) : (
                            assetPorts.map((port) => (
                              <span
                                key={port}
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  [22, 21, 23, 3389].includes(port)
                                    ? "bg-cyber-danger/25 border border-cyber-danger/50 text-cyber-danger animate-pulse"
                                    : "bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary"
                                }`}
                              >
                                <HighlightText text={port} highlight={search} />
                              </span>
                            ))
                          )}
                        </div>
                      </td>
                    </tr>

                    {/* Expandable Details Row */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={7} className="bg-dark-bg/30 p-4 border-b border-dark-border">
                          {/* Request / Response */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4 font-mono text-xs">
                            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
                              <h5 className="font-bold text-cyber-accent border-b border-dark-border pb-1.5 mb-2.5 uppercase tracking-wider text-[10px]">
                                Request
                              </h5>
                              <div className="space-y-1.5">
                                <div className="text-slate-200 break-all select-all">
                                  <span className="text-cyber-accent font-bold mr-2">
                                    {asset.metadata?.request_method || "GET"}
                                  </span>
                                  {asset.metadata?.url || asset.domain}
                                </div>
                                <div className="max-h-40 overflow-y-auto text-[10px] text-slate-400 space-y-0.5">
                                  {(asset.metadata?.request_headers || []).length > 0 ? (
                                    asset.metadata.request_headers.map((h: string, i: number) => (
                                      <div key={i} className="break-all select-all"><HighlightText text={h} highlight={search} /></div>
                                    ))
                                  ) : (
                                    <div className="text-slate-600">No stored request headers.</div>
                                  )}
                                </div>
                              </div>
                            </div>

                            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
                              <h5 className="font-bold text-cyber-accent border-b border-dark-border pb-1.5 mb-2.5 uppercase tracking-wider text-[10px]">
                                Response
                              </h5>
                              <div className="flex items-center gap-2 mb-1.5">
                                <span className="px-1.5 py-0.5 rounded bg-dark-bg border border-dark-border text-slate-200 text-[10px]">
                                  HTTP {asset.metadata?.status_code ?? (asset as any).status_code ?? "-"}
                                </span>
                                <span className="text-[10px] text-slate-500">
                                  {asset.metadata?.content_length ? `${asset.metadata.content_length} B` : ""}
                                </span>
                              </div>
                              <div className="max-h-24 overflow-y-auto text-[10px] text-slate-400 space-y-0.5 mb-2">
                                {(asset.metadata?.response_headers || []).length > 0 ? (
                                  asset.metadata.response_headers.map((h: string, i: number) => (
                                    <div key={i} className="break-all select-all"><HighlightText text={h} highlight={search} /></div>
                                  ))
                                ) : (
                                  <div className="text-slate-600">No stored response headers.</div>
                                )}
                              </div>
                              <div className="border-t border-dark-border pt-2">
                                {expandedBodies[asset.id]?.loading ? (
                                  <div className="text-slate-500 text-[10px]">Loading response body...</div>
                                ) : expandedBodies[asset.id]?.error ? (
                                  <div className="text-rose-300 text-[10px]">{expandedBodies[asset.id].error}</div>
                                ) : expandedBodies[asset.id]?.content ? (
                                  <pre className="text-slate-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto select-all text-[10px]">
                                    {expandedBodies[asset.id].content}
                                  </pre>
                                ) : (
                                  <div className="text-slate-600 text-[10px]">
                                    No stored response body for this asset.
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>

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
                                    <a
                                      href={asset.metadata.url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-cyber-accent hover:underline break-all"
                                    >
                                      {asset.metadata.url}
                                    </a>
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
                                    <a
                                      href={asset.metadata.redirect_location.startsWith("http") ? asset.metadata.redirect_location : `https://${asset.domain}${asset.metadata.redirect_location.startsWith("/") ? "" : "/"}${asset.metadata.redirect_location}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-cyber-accent hover:underline break-all"
                                    >
                                      {asset.metadata.redirect_location}
                                    </a>
                                  </div>
                                )}
                                {(asset.metadata.tls_info || asset.metadata.ssl_info) && (
                                  <div>
                                    <span className="text-slate-500">TLS:</span>{" "}
                                    <span className="text-slate-300">{asset.metadata.tls_info?.issuer || asset.metadata.ssl_info?.issuer || "Available"}</span>
                                  </div>
                                )}
                                {(asset.status_class || asset.metadata?.status_class) && (
                                  <div>
                                    <span className="text-slate-500">STATUS CLASS:</span>{" "}
                                    <span className="text-slate-300">{asset.status_class || asset.metadata?.status_class}</span>
                                  </div>
                                )}
                                {(asset.metadata?.response_body_path || asset.response_body_path) && (
                                  <div className="pt-2 mt-1 border-t border-dark-border/40 flex items-center justify-between">
                                    <span className="text-slate-500">RESPONSE BODY:</span>
                                    <button
                                      onClick={() => handleOpenResponseBody(asset)}
                                      className="px-2 py-0.5 rounded bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 text-[10px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                                    >
                                      <FileText className="w-3.5 h-3.5" />
                                      View Stored Body ({asset.metadata?.response_body_size ? `${Math.round(asset.metadata.response_body_size / 1024)} KB` : "Stored"})
                                    </button>
                                  </div>
                                )}
                                {(asset.cdn_waf || asset.metadata?.cdn_waf) && (
                                  <div className="pt-2 mt-1 border-t border-dark-border/40 space-y-1">
                                    <div className="flex items-center gap-1.5 text-purple-300 font-bold">
                                      <Shield className="w-3.5 h-3.5" />
                                      <span>CDN / WAF Protection: {(asset.cdn_waf?.cdn_provider || asset.cdn_waf?.waf_provider || asset.metadata?.cdn_provider || asset.metadata?.waf_provider || "Detected")}</span>
                                    </div>
                                    {(asset.cdn_waf?.exclusion_reason || asset.exclusion_reason || asset.metadata?.exclusion_reason) && (
                                      <div className="text-[10px] text-slate-400 pl-5">
                                        Reason: <span className="text-amber-400/90">{asset.cdn_waf?.exclusion_reason || asset.exclusion_reason || asset.metadata?.exclusion_reason}</span>
                                      </div>
                                    )}
                                  </div>
                                )}
                                {(asset.is_cluster_representative || asset.is_cluster_member || asset.metadata?.is_cluster_representative || asset.metadata?.is_cluster_member) && (
                                  <div className="pt-2 mt-1 border-t border-dark-border/40 space-y-1">
                                    <div className="flex items-center gap-1.5 text-emerald-300 font-bold">
                                      <Layers className="w-3.5 h-3.5" />
                                      <span>
                                        Clustering: {(asset.is_cluster_representative || asset.metadata?.is_cluster_representative) ? `Representative (${asset.cluster_size || asset.metadata?.cluster_size || 1} hosts)` : "Member (Skipped)"}
                                      </span>
                                    </div>
                                    {(asset.cluster_skip_reason || asset.metadata?.cluster_skip_reason) && (
                                      <div className="text-[10px] text-slate-400 pl-5">
                                        Skip Reason: <span className="text-blue-300">{asset.cluster_skip_reason || asset.metadata?.cluster_skip_reason}</span>
                                      </div>
                                    )}
                                  </div>
                                )}
                                {(asset.services || asset.metadata?.services) && (asset.services || asset.metadata?.services).length > 0 && (
                                  <div className="pt-2 mt-1 border-t border-dark-border/40 space-y-1">
                                    <span className="text-slate-500 font-bold block mb-1">NMAP SERVICE FINGERPRINTS:</span>
                                    <div className="space-y-1">
                                      {(asset.services || asset.metadata?.services).map((srv: any, idx: number) => (
                                        <div key={idx} className="bg-dark-bg/60 border border-dark-border/50 rounded px-2 py-1 text-[10px] flex items-center justify-between">
                                          <span className="text-cyber-accent font-bold">Port {srv.port}/{srv.protocol || "tcp"}</span>
                                          <span className="text-slate-300">{srv.service || "unknown"} {srv.product ? `(${srv.product} ${srv.version || ""})` : ""}</span>
                                        </div>
                                      ))}
                                    </div>
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
                                                    {urls.map((url: string, idx: number) => {
                                                      const fullUrl = url.startsWith("http") ? url : `https://${asset.domain}${url.startsWith("/") ? "" : "/"}${url}`;
                                                      return (
                                                        <div key={idx} className="text-slate-300 break-all select-all hover:text-white py-0.5 border-b border-dark-border/10 last:border-0">
                                                          <a href={fullUrl} target="_blank" rel="noopener noreferrer" className="hover:text-cyber-accent hover:underline">
                                                            {url}
                                                          </a>
                                                        </div>
                                                      );
                                                    })}
                                                  </div>
                                                </div>
                                              );
                                            })}
                                          </div>
                                        ) : (
                                          <div className="max-h-48 overflow-y-auto bg-dark-bg border border-dark-border rounded p-2 text-[10px] space-y-1 font-mono">
                                            {asset.metadata.katana.endpoints?.length > 0 ? (
                                              asset.metadata.katana.endpoints.map((ep: string, idx: number) => {
                                                const fullEp = ep.startsWith("http") ? ep : `https://${asset.domain}${ep.startsWith("/") ? "" : "/"}${ep}`;
                                                return (
                                                  <div key={idx} className="text-slate-300 break-all select-all hover:text-white py-0.5 border-b border-dark-border/20 last:border-0">
                                                    <a href={fullEp} target="_blank" rel="noopener noreferrer" className="hover:text-cyber-accent hover:underline">
                                                      {ep}
                                                    </a>
                                                  </div>
                                                );
                                              })
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
                                          asset.metadata.katana.js_files.map((js: string, idx: number) => {
                                            const fullJs = js.startsWith("http") ? js : `https://${asset.domain}${js.startsWith("/") ? "" : "/"}${js}`;
                                            return (
                                              <div key={idx} className="text-slate-300 break-all select-all hover:text-white py-0.5 border-b border-dark-border/20 last:border-0">
                                                <a href={fullJs} target="_blank" rel="noopener noreferrer" className="text-cyber-accent hover:underline">
                                                  {js}
                                                </a>
                                              </div>
                                            );
                                          })
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

      <Pagination
        page={assetSafePage}
        pageSize={assetPageSize}
        total={filteredAssets.length}
        onPageChange={setAssetPage}
        onPageSizeChange={setAssetPageSize}
        itemLabel="asset(s)"
      />
    </div>
      )}

      {/* Screenshot Modal */}
      {screenshotModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4"
          onClick={() => setScreenshotModal(null)}
        >
          <div className="max-w-6xl w-full max-h-full flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between gap-3 p-2 bg-dark-card border border-dark-border rounded-t-lg">
              <div className="min-w-0">
                <div className="text-xs font-mono text-slate-200 break-all select-all">{screenshotModal.title}</div>
                {screenshotModal.url && (
                  <a
                    href={screenshotModal.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono text-cyber-accent hover:underline break-all"
                    title="Open captured page"
                  >
                    {screenshotModal.url} ↗
                  </a>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <a
                  href={screenshotModal.src}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-2 py-1 rounded border border-dark-border bg-dark-input text-slate-300 hover:text-white text-[10px] font-mono"
                  title="Open screenshot image"
                >
                  Open image
                </a>
                <button
                  onClick={() => setScreenshotModal(null)}
                  className="p-1.5 rounded border border-dark-border bg-dark-input text-slate-300 hover:text-white cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="bg-black/40 border border-t-0 border-dark-border rounded-b-lg overflow-auto flex justify-center">
              <img src={screenshotModal.src} alt={screenshotModal.title} className="max-h-[80vh] w-auto object-contain" />
            </div>
          </div>
        </div>
      )}

      {/* Response Body Modal */}
      {responseBodyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-dark-card border border-dark-border rounded-xl shadow-2xl w-full max-w-4xl max-h-[85vh] flex flex-col overflow-hidden animate-fadeIn">
            {/* Header */}
            <div className="p-4 border-b border-dark-border flex justify-between items-center bg-dark-bg/60">
              <div className="flex items-center gap-3">
                <FileText className="w-5 h-5 text-cyber-accent" />
                <div>
                  <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                    <span>{responseBodyModal.asset.domain}</span>
                    {responseBodyModal.asset.metadata?.status_code !== undefined && (
                      <span className="px-2 py-0.25 bg-cyber-accent/20 border border-cyber-accent/40 text-cyber-accent rounded text-[10px]">
                        HTTP {responseBodyModal.asset.metadata.status_code}
                      </span>
                    )}
                  </h3>
                  <span className="text-[10px] text-slate-400 font-mono">
                    Stored HTTP Response Body (Isolated per-project disk storage)
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {responseBodyModal.content && (
                  <button
                    onClick={() => handleCopy(responseBodyModal.content || "")}
                    className="p-1.5 text-slate-400 hover:text-white hover:bg-dark-hover rounded transition-colors cursor-pointer"
                    title="Copy Body Content"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                )}
                <button
                  onClick={() => setResponseBodyModal(null)}
                  className="p-1.5 text-slate-400 hover:text-white hover:bg-dark-hover rounded transition-colors cursor-pointer"
                  title="Close Modal"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Content Area */}
            <div className="p-4 flex-1 overflow-auto bg-dark-bg font-mono text-xs">
              {responseBodyModal.loading && (
                <div className="flex items-center justify-center py-16 text-slate-400 gap-2">
                  <div className="w-4 h-4 border-2 border-cyber-accent border-t-transparent rounded-full animate-spin" />
                  <span>Loading response body securely from storage...</span>
                </div>
              )}
              {responseBodyModal.error && (
                <div className="p-4 bg-red-950/30 border border-red-800/50 rounded text-red-300 text-xs">
                  {responseBodyModal.error}
                </div>
              )}
              {responseBodyModal.content !== null && !responseBodyModal.loading && (
                <pre className="text-slate-200 select-all whitespace-pre-wrap break-all leading-relaxed max-h-[60vh] overflow-y-auto">
                  {responseBodyModal.content}
                </pre>
              )}
            </div>

            {/* Footer */}
            <div className="p-3 border-t border-dark-border bg-dark-bg/60 flex justify-between items-center text-[10px] font-mono text-slate-500">
              <span className="truncate max-w-md">
                Path: {responseBodyModal.asset.metadata?.response_body_path || responseBodyModal.asset.response_body_path || "N/A"}
              </span>
              <button
                onClick={() => setResponseBodyModal(null)}
                className="px-3 py-1 bg-dark-card hover:bg-dark-hover border border-dark-border rounded text-slate-300 text-xs transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
