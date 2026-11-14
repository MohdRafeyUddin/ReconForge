import React, { useState, useEffect } from "react";
import {
  Shield,
  Sliders,
  Cpu,
  Clock,
  Bell,
  X,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  RefreshCw,
  Save,
  Terminal,
  Layers,
  Globe,
  Key,
} from "lucide-react";
import { apiCall } from "../../services/api";

export interface ProjectScope {
  in_scope?: string[];
  out_of_scope?: string[];
}

export interface ProjectRateLimits {
  global_rps?: number;
  per_tool?: Record<string, number>;
  tool_overrides?: Record<string, number>;
}

export interface ProjectSchedule {
  enabled?: boolean;
  interval_hours?: number;
  scan_mode?: string;
  last_run?: string | null;
  next_run?: string | null;
}

export interface ProjectAlerts {
  enabled?: boolean;
  discord_webhook_url?: string;
  telegram_bot_token?: string;
  telegram_chat_id?: string;
  min_priority?: string;
  events?: {
    new_subdomains?: boolean;
    new_live_hosts?: boolean;
    new_ports?: boolean;
    new_findings?: boolean;
    scan_completed?: boolean;
  };
}

export interface ProjectSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  project: {
    id: string;
    name: string;
    description?: string;
    seed_domains: string[];
    scope?: ProjectScope;
    rate_limits?: ProjectRateLimits;
    custom_headers?: Record<string, string>;
    schedule?: ProjectSchedule;
    alerts?: ProjectAlerts;
    clustering?: { scan_all_cluster_members?: boolean };
    port_range?: string;
    response_body_max_kb?: number;
    scan_profile?: string;
    assume_tools_installed?: boolean;
    enable_root_expansion?: boolean;
    max_permutations?: number;
  };
  onProjectUpdated: (updatedProject: any) => void;
}

interface ToolStatus {
  name: string;
  wsl_binary: string;
  required: boolean;
  category: string;
  description: string;
  install_hint: string;
  installed: boolean;
  resolved_path: string | null;
}

export const ProjectSettingsModal: React.FC<ProjectSettingsModalProps> = ({
  isOpen,
  onClose,
  project,
  onProjectUpdated,
}) => {
  const [activeTab, setActiveTab] = useState<"scope" | "rate_limits" | "clustering" | "schedule" | "alerts" | "tools" | "suggested_roots" | "api_keys">("scope");

  // Scope state
  const [inScopeText, setInScopeText] = useState("");
  const [outScopeText, setOutScopeText] = useState("");
  const [scanProfile, setScanProfile] = useState<"recon" | "recon_validation">("recon");

  // Rate limit state
  const [globalRps, setGlobalRps] = useState<number>(10);
  const [httpxRps, setHttpxRps] = useState<string>("");
  const [katanaRps, setKatanaRps] = useState<string>("");
  const [nucleiRps, setNucleiRps] = useState<string>("");
  const [naabuRate, setNaabuRate] = useState<string>("");

  // Custom Header state
  const [headerKey, setHeaderKey] = useState("X-Bug-Bounty");
  const [headerValue, setHeaderValue] = useState("");

  // Schedule state (Phase 2)
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [intervalHours, setIntervalHours] = useState(24);
  const [scheduleScanMode, setScheduleScanMode] = useState("fast");
  const [lastRun, setLastRun] = useState<string | null>(null);
  const [nextRun, setNextRun] = useState<string | null>(null);

  // Alerts state (Phase 2)
  const [alertsEnabled, setAlertsEnabled] = useState(false);
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState("");
  const [telegramBotToken, setTelegramBotToken] = useState("");
  const [telegramChatId, setTelegramChatId] = useState("");
  const [minPriority, setMinPriority] = useState("medium");
  const [alertEvents, setAlertEvents] = useState({
    new_subdomains: true,
    new_live_hosts: true,
    new_ports: true,
    new_findings: true,
    scan_completed: true,
  });

  // Tools status state
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [toolsSummary, setToolsSummary] = useState<{ total: number; installed: number; missing: number } | null>(null);
  const [loadingTools, setLoadingTools] = useState(false);
  const [copiedTool, setCopiedTool] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<string | null>(null);
  const [wslWarning, setWslWarning] = useState<string | null>(null);
  const [assumeToolsInstalled, setAssumeToolsInstalled] = useState<boolean>(true);

  // Clustering & Probing state (Phase 3 & Phase 7)
  const [scanAllClusterMembers, setScanAllClusterMembers] = useState(false);
  const [portRange, setPortRange] = useState("1-10000");
  const [responseBodyMaxKb, setResponseBodyMaxKb] = useState(500);
  const [enableRootExpansion, setEnableRootExpansion] = useState(false);
  const [maxPermutations, setMaxPermutations] = useState<number>(50000);

  // Suggested roots state (Phase 7)
  const [suggestedRoots, setSuggestedRoots] = useState<any[]>([]);
  const [loadingSuggestedRoots, setLoadingSuggestedRoots] = useState(false);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  // Provider API Keys state (Phase 7)
  const [providerKeysStatus, setProviderKeysStatus] = useState<any>(null);
  const [keyInputs, setKeyInputs] = useState<Record<string, string>>({
    securitytrails: "",
    censys: "",
    shodan: "",
    virustotal: "",
    github: "",
    chaos: "",
  });
  const [savingKeys, setSavingKeys] = useState(false);
  const [keysSavedSuccess, setKeysSavedSuccess] = useState(false);

  // Form saving state
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Initialize form fields from project
  useEffect(() => {
    if (project) {
      const inRules = project.scope?.in_scope || [];
      const outRules = project.scope?.out_of_scope || [];
      setInScopeText(inRules.join("\n"));
      setOutScopeText(outRules.join("\n"));

      const rl = project.rate_limits || {};
      setGlobalRps(rl.global_rps ?? 10);
      const overrides = rl.per_tool || rl.tool_overrides || {};
      setHttpxRps(overrides.httpx ? String(overrides.httpx) : "");
      setKatanaRps(overrides.katana ? String(overrides.katana) : "");
      setNucleiRps(overrides.nuclei ? String(overrides.nuclei) : "");
      setNaabuRate(overrides.naabu ? String(overrides.naabu) : "");

      const headers = project.custom_headers || {};
      const firstKey = Object.keys(headers)[0];
      if (firstKey) {
        setHeaderKey(firstKey);
        setHeaderValue(headers[firstKey] || "");
      } else {
        setHeaderKey("X-Bug-Bounty");
        setHeaderValue("");
      }

      // Schedule fields
      const sched = project.schedule || {};
      setScheduleEnabled(Boolean(sched.enabled));
      setIntervalHours(sched.interval_hours || 24);
      setScheduleScanMode(sched.scan_mode || "fast");
      setLastRun(sched.last_run ? String(sched.last_run) : null);
      setNextRun(sched.next_run ? String(sched.next_run) : null);

      // Alerts fields
      const alt = project.alerts || {};
      setAlertsEnabled(Boolean(alt.enabled));
      setDiscordWebhookUrl(alt.discord_webhook_url || "");
      setTelegramBotToken(alt.telegram_bot_token || "");
      setTelegramChatId(alt.telegram_chat_id || "");
      setMinPriority(alt.min_priority || "medium");
      if (alt.events) {
        setAlertEvents({
          new_subdomains: alt.events.new_subdomains ?? true,
          new_live_hosts: alt.events.new_live_hosts ?? true,
          new_ports: alt.events.new_ports ?? true,
          new_findings: alt.events.new_findings ?? true,
          scan_completed: alt.events.scan_completed ?? true,
        });
      }

      // Clustering & Probing
      const cl = project.clustering || {};
      setScanAllClusterMembers(Boolean(cl.scan_all_cluster_members));
      setPortRange(project.port_range || "1-10000");
      setResponseBodyMaxKb(project.response_body_max_kb || 500);
      setScanProfile(project.scan_profile === "recon_validation" ? "recon_validation" : "recon");
      setAssumeToolsInstalled(project.assume_tools_installed !== false);
      setEnableRootExpansion(Boolean(project.enable_root_expansion));
      setMaxPermutations(project.max_permutations || 50000);
    }
  }, [project, isOpen]);

  // Load WSL Tools Status (returns cached immediately; ?refresh=true re-runs with 10s timeout)
  const fetchTools = async (refresh: boolean = false) => {
    setLoadingTools(true);
    setWslWarning(null);
    try {
      const url = refresh ? "/system/tools?refresh=true" : "/system/tools";
      const data = await apiCall(url);
      setTools(data.tools || []);
      setToolsSummary({
        total: data.total || (data.tools ? data.tools.length : 0),
        installed: data.installed || 0,
        missing: data.missing || 0,
      });
      if (data.last_checked) {
        setLastChecked(data.last_checked);
      }
      if (data.warning) {
        setWslWarning(data.warning);
      }
    } catch (err: any) {
      console.error("Failed to fetch WSL tools status:", err);
      setWslWarning(err.message || "WSL is unreachable or timed out");
    } finally {
      setLoadingTools(false);
    }
  };

  const fetchSuggestedRoots = async () => {
    if (!project?.id) return;
    setLoadingSuggestedRoots(true);
    try {
      const res = await apiCall(`/projects/${project.id}/suggested-roots`);
      setSuggestedRoots(res || []);
    } catch (e) {
      console.error("Failed to load suggested roots", e);
    } finally {
      setLoadingSuggestedRoots(false);
    }
  };

  const fetchProviderKeys = async () => {
    try {
      const res = await apiCall(`/system/provider-keys`);
      setProviderKeysStatus(res);
    } catch (e) {
      console.error("Failed to load provider keys", e);
    }
  };

  useEffect(() => {
    if (isOpen && (tools.length === 0 || activeTab === "tools")) {
      fetchTools(false);
    }
    if (isOpen && activeTab === "suggested_roots") {
      fetchSuggestedRoots();
    }
    if (isOpen && activeTab === "api_keys") {
      fetchProviderKeys();
    }
  }, [isOpen, activeTab]);

  const handleApproveRoot = async (domain: string) => {
    setActionInProgress(domain);
    try {
      await apiCall(`/projects/${project.id}/suggested-roots/${domain}/approve`, {
        method: "POST",
      });
      await fetchSuggestedRoots();
      setInScopeText((prev) => {
        const lines = prev.split("\n").map((l) => l.trim()).filter(Boolean);
        if (!lines.includes(domain)) {
          return [...lines, domain].join("\n");
        }
        return prev;
      });
    } catch (err: any) {
      setErrorMsg(err.message || `Failed to approve ${domain}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleRejectRoot = async (domain: string) => {
    setActionInProgress(domain);
    try {
      await apiCall(`/projects/${project.id}/suggested-roots/${domain}/reject`, {
        method: "POST",
      });
      await fetchSuggestedRoots();
    } catch (err: any) {
      setErrorMsg(err.message || `Failed to reject ${domain}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleSaveKeys = async () => {
    setSavingKeys(true);
    try {
      const payload: Record<string, string> = {};
      Object.entries(keyInputs).forEach(([k, v]) => {
        if (v && v.trim()) payload[k] = v.trim();
      });
      const res = await apiCall(`/system/provider-keys`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setProviderKeysStatus(res.status || res);
      setKeysSavedSuccess(true);
      setTimeout(() => setKeysSavedSuccess(false), 2500);
      setKeyInputs({
        securitytrails: "",
        censys: "",
        shodan: "",
        virustotal: "",
        github: "",
        chaos: "",
      });
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to save provider keys");
    } finally {
      setSavingKeys(false);
    }
  };

  const handleCopyInstall = (cmd: string, toolName: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedTool(toolName);
    setTimeout(() => setCopiedTool(null), 2500);
  };

  const handleSave = async () => {
    setSaving(true);
    setErrorMsg(null);
    setSaveSuccess(false);

    try {
      // Parse rules
      const inScopeRules = inScopeText
        .split(/[\n,]/)
        .map((r) => r.trim())
        .filter((r) => r.length > 0);

      const outScopeRules = outScopeText
        .split(/[\n,]/)
        .map((r) => r.trim())
        .filter((r) => r.length > 0);

      // Validate scope for recurring schedule
      if (scheduleEnabled && inScopeRules.length === 0) {
        setErrorMsg("Cannot enable recurring schedule without configured in-scope targets. Please define at least one in-scope rule under Scope settings.");
        setSaving(false);
        return;
      }

      const tool_overrides: Record<string, number> = {};
      if (httpxRps.trim()) tool_overrides.httpx = parseInt(httpxRps, 10);
      if (katanaRps.trim()) tool_overrides.katana = parseInt(katanaRps, 10);
      if (nucleiRps.trim()) tool_overrides.nuclei = parseInt(nucleiRps, 10);
      if (naabuRate.trim()) tool_overrides.naabu = parseInt(naabuRate, 10);

      const custom_headers: Record<string, string> = {};
      if (headerKey.trim() && headerValue.trim()) {
        custom_headers[headerKey.trim()] = headerValue.trim();
      }

      const payload = {
        scope: {
          in_scope: inScopeRules,
          out_of_scope: outScopeRules,
        },
        rate_limits: {
          global_rps: Number(globalRps) || 10,
          per_tool: tool_overrides,
          tool_overrides,
        },
        custom_headers,
        schedule: {
          enabled: scheduleEnabled,
          interval_hours: Number(intervalHours) || 24,
          scan_mode: scheduleScanMode,
        },
        alerts: {
          enabled: alertsEnabled,
          discord_webhook_url: discordWebhookUrl.trim(),
          telegram_bot_token: telegramBotToken.trim(),
          telegram_chat_id: telegramChatId.trim(),
          min_priority: minPriority,
          events: alertEvents,
        },
        clustering: {
          scan_all_cluster_members: scanAllClusterMembers,
        },
        port_range: portRange.trim() || "1-10000",
        response_body_max_kb: Number(responseBodyMaxKb) || 500,
        scan_profile: scanProfile,
        assume_tools_installed: assumeToolsInstalled,
        enable_root_expansion: enableRootExpansion,
        max_permutations: Number(maxPermutations) || 50000,
      };

      const updated = await apiCall(`/projects/${project.id}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });

      onProjectUpdated(updated);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2000);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to update project settings");
    } finally {
      setSaving(false);
    }
  };

  if (!isOpen) return null;

  const hasScopeConfigured =
    inScopeText.trim().length > 0 || outScopeText.trim().length > 0;

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fadeIn">
      <div className="bg-dark-card border border-dark-border max-w-3xl w-full rounded-xl glass shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-dark-border flex items-center justify-between bg-dark-bg/60">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-accent">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
                <span>PROJECT CONFIGURATION</span>
                <span className="text-xs font-mono font-normal text-slate-400">
                  ({project.name})
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Scope rules, rate limit overrides, headers, and WSL2 environment tools
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg border border-dark-border text-slate-400 hover:text-slate-100 hover:bg-dark-border/40 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-dark-border bg-dark-bg/40 px-6 pt-2">
          <button
            onClick={() => setActiveTab("scope")}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "scope"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Scope Engine</span>
            {!hasScopeConfigured && (
              <span className="w-2 h-2 rounded-full bg-cyber-warning animate-pulse" />
            )}
          </button>

          <button
            onClick={() => setActiveTab("rate_limits")}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "rate_limits"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Rate Limits & Headers</span>
          </button>

          <button
            onClick={() => setActiveTab("clustering")}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "clustering"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Clustering & Probing</span>
            {scanAllClusterMembers && (
              <span className="text-[9px] px-1 py-0.2 rounded bg-amber-500/20 text-amber-400">All</span>
            )}
          </button>

          <button
            onClick={() => setActiveTab("schedule")}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "schedule"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Recurring Schedule</span>
            {scheduleEnabled && (
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
            )}
          </button>

          <button
            onClick={() => setActiveTab("alerts")}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "alerts"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Bell className="w-3.5 h-3.5" />
            <span>Alerts & Webhooks</span>
            {alertsEnabled && (
              <span className="w-2 h-2 rounded-full bg-cyber-accent" />
            )}
          </button>

          <button
            onClick={() => setActiveTab("suggested_roots")}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "suggested_roots"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Suggested Roots</span>
            {suggestedRoots.filter(r => r.status === "pending" || !r.status).length > 0 && (
              <span className="text-[9px] px-1.5 py-0.2 rounded-full bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/30 font-bold">
                {suggestedRoots.filter(r => r.status === "pending" || !r.status).length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab("api_keys")}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "api_keys"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            <span>API Keys</span>
          </button>

          <button
            onClick={() => setActiveTab("tools")}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-bold font-mono uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
              activeTab === "tools"
                ? "border-cyber-accent text-cyber-accent bg-cyber-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>WSL Tool Registry</span>
            {toolsSummary && (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-dark-border text-slate-300">
                {toolsSummary.installed}/{toolsSummary.total}
              </span>
            )}
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {errorMsg && (
            <div className="p-3 bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger text-xs font-mono rounded-lg">
              {errorMsg}
            </div>
          )}

          {saveSuccess && (
            <div className="p-3 bg-cyber-success/10 border border-cyber-success/30 text-cyber-success text-xs font-mono rounded-lg flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>Project settings updated and saved successfully!</span>
            </div>
          )}

          {/* TAB 1: SCOPE */}
          {activeTab === "scope" && (
            <div className="space-y-4">
              {/* Unset warning banner */}
              {!hasScopeConfigured ? (
                <div className="p-3.5 rounded-lg bg-cyber-warning/10 border border-cyber-warning/40 text-cyber-warning flex items-start space-x-3 text-xs leading-relaxed">
                  <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                  <div>
                    <span className="font-bold uppercase tracking-wider font-mono">
                      Scope Unset (Warning):
                    </span>{" "}
                    Target discovery will run in open mode. To avoid accidental testing of third-party
                    hosts or out-of-scope targets, specify authorized domain wildcards, hosts, or CIDRs below.
                  </div>
                </div>
              ) : (
                <div className="p-3 rounded-lg bg-cyber-success/10 border border-cyber-success/30 text-cyber-success text-xs font-mono flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>
                    Scope Engine Active: Scans fail-closed on any target not explicitly permitted in-scope. Out-of-scope rules always take priority.
                  </span>
                </div>
              )}

              {/* Scan Profile Selector */}
              <div className="p-4 rounded-lg bg-dark-bg/60 border border-dark-border space-y-2.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-mono text-slate-200 font-bold uppercase tracking-wider flex items-center space-x-2">
                    <Shield className="w-3.5 h-3.5 text-cyber-accent" />
                    <span>Scan Profile</span>
                  </label>
                  <span className="text-[10px] text-slate-400 font-mono">Profile controls discovery depth & active vulnerability testing</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                  <button
                    type="button"
                    onClick={() => setScanProfile("recon")}
                    className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                      scanProfile === "recon"
                        ? "border-cyber-accent bg-cyber-accent/10 text-white"
                        : "border-dark-border bg-dark-card/40 text-slate-400 hover:border-slate-600"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold font-mono text-xs text-cyber-accent">Recon (Default)</span>
                      {scanProfile === "recon" && <Check className="w-3.5 h-3.5 text-cyber-accent" />}
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Subdomains, DNS, ports, liveness, clustering, crawling, API & parameter discovery. Skips active vulnerability verification (Nuclei, Dalfox, OpenRedirex).
                    </p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setScanProfile("recon_validation")}
                    className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                      scanProfile === "recon_validation"
                        ? "border-amber-400 bg-amber-500/10 text-white"
                        : "border-dark-border bg-dark-card/40 text-slate-400 hover:border-slate-600"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold font-mono text-xs text-amber-400">Recon + Validation</span>
                      {scanProfile === "recon_validation" && <Check className="w-3.5 h-3.5 text-amber-400" />}
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Full discovery plus active vulnerability testing (Nuclei host & endpoint templates, Dalfox XSS scanner, and OpenRedirex).
                    </p>
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* In-Scope Box */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-mono text-cyber-success font-bold uppercase tracking-widest flex items-center space-x-1.5">
                      <span className="w-2 h-2 rounded-full bg-cyber-success" />
                      <span>In-Scope Target Rules</span>
                    </label>
                    <span className="text-[10px] text-slate-400 font-mono">1 per line</span>
                  </div>
                  <textarea
                    rows={7}
                    placeholder="*.example.com&#10;api.example.com&#10;192.168.1.0/24"
                    value={inScopeText}
                    onChange={(e) => setInScopeText(e.target.value)}
                    className="w-full bg-dark-bg border border-dark-border rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyber-accent transition-colors"
                  />
                  <p className="text-[10px] text-slate-500 mt-1 font-mono">
                    Supported: Wildcards (<code className="text-slate-400">*.example.com</code>), Exact FQDNs, CIDR subnets (<code className="text-slate-400">10.0.0.0/24</code>), or Single IPs.
                  </p>
                </div>

                {/* Out-of-Scope Box */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-mono text-cyber-danger font-bold uppercase tracking-widest flex items-center space-x-1.5">
                      <span className="w-2 h-2 rounded-full bg-cyber-danger" />
                      <span>Out-of-Scope Rules (Drop)</span>
                    </label>
                    <span className="text-[10px] text-slate-400 font-mono">Always wins</span>
                  </div>
                  <textarea
                    rows={7}
                    placeholder="dev.example.com&#10;*.corp.example.com&#10;10.0.0.0/8"
                    value={outScopeText}
                    onChange={(e) => setOutScopeText(e.target.value)}
                    className="w-full bg-dark-bg border border-dark-border rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyber-danger transition-colors"
                  />
                  <p className="text-[10px] text-slate-500 mt-1 font-mono">
                    Any match here is immediately dropped before active DNSx, Naabu, HTTPX, and vulnerability scanners run.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: RATE LIMITS & HEADERS */}
          {activeTab === "rate_limits" && (
            <div className="space-y-5">
              {/* Global RPS */}
              <div className="bg-dark-bg/60 border border-dark-border rounded-lg p-4">
                <label className="block text-xs font-mono text-slate-300 font-bold uppercase tracking-wider mb-1">
                  Global Rate Limit (Requests / Second)
                </label>
                <p className="text-[11px] text-slate-500 font-mono mb-2">
                  Default request rate applied to all discovery and active probing tools.
                </p>
                <div className="flex items-center space-x-3 max-w-xs">
                  <input
                    type="number"
                    min={1}
                    max={5000}
                    value={globalRps}
                    onChange={(e) => setGlobalRps(parseInt(e.target.value, 10) || 1)}
                    className="w-32 bg-dark-input border border-dark-border rounded p-2 text-sm text-slate-100 font-mono focus:outline-none focus:border-cyber-accent"
                  />
                  <span className="text-xs font-mono text-slate-400">req / sec</span>
                </div>
              </div>

              {/* Tool Overrides */}
              <div className="bg-dark-bg/60 border border-dark-border rounded-lg p-4">
                <h4 className="text-xs font-mono text-slate-300 font-bold uppercase tracking-wider mb-1">
                  Tool-Specific Rate Overrides
                </h4>
                <p className="text-[11px] text-slate-500 font-mono mb-3">
                  Leave blank to inherit the global rate limit. Mapped directly to CLI flags:
                </p>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase">
                      HTTPX (<code className="text-cyber-accent">-rl</code>)
                    </label>
                    <input
                      type="number"
                      placeholder={String(globalRps)}
                      value={httpxRps}
                      onChange={(e) => setHttpxRps(e.target.value)}
                      className="w-full mt-1 bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase">
                      Katana (<code className="text-cyber-accent">-rl</code>)
                    </label>
                    <input
                      type="number"
                      placeholder={String(globalRps)}
                      value={katanaRps}
                      onChange={(e) => setKatanaRps(e.target.value)}
                      className="w-full mt-1 bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase">
                      Nuclei (<code className="text-cyber-accent">-rl</code>)
                    </label>
                    <input
                      type="number"
                      placeholder={String(globalRps)}
                      value={nucleiRps}
                      onChange={(e) => setNucleiRps(e.target.value)}
                      className="w-full mt-1 bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase">
                      Naabu (<code className="text-cyber-accent">-rate</code>)
                    </label>
                    <input
                      type="number"
                      placeholder="1000"
                      value={naabuRate}
                      onChange={(e) => setNaabuRate(e.target.value)}
                      className="w-full mt-1 bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                  </div>
                </div>
              </div>

              {/* Custom Header Injection */}
              <div className="bg-dark-bg/60 border border-dark-border rounded-lg p-4">
                <h4 className="text-xs font-mono text-slate-300 font-bold uppercase tracking-wider mb-1 flex items-center space-x-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyber-accent" />
                  <span>Custom Bug Bounty Identification Header</span>
                </h4>
                <p className="text-[11px] text-slate-500 font-mono mb-3">
                  Automatically injected into HTTP requests via <code className="text-cyber-accent">-H</code> (httpx, katana, nuclei).
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase">Header Name</label>
                    <input
                      type="text"
                      placeholder="X-Bug-Bounty"
                      value={headerKey}
                      onChange={(e) => setHeaderKey(e.target.value)}
                      className="w-full mt-1 bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase">Header Value</label>
                    <input
                      type="text"
                      placeholder="hackerone-handle / bugcrowd-handle"
                      value={headerValue}
                      onChange={(e) => setHeaderValue(e.target.value)}
                      className="w-full mt-1 bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                  </div>
                </div>

                {headerKey.trim() && headerValue.trim() && (
                  <div className="mt-2 text-[10px] font-mono text-cyber-accent bg-cyber-accent/5 p-2 rounded border border-cyber-accent/20">
                    Injected flag: <code className="text-slate-200">-H "{headerKey.trim()}: {headerValue.trim()}"</code>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB: CLUSTERING & PROBING (PHASE 3) */}
          {activeTab === "clustering" && (
            <div className="space-y-4">
              <div className="p-4 bg-dark-bg/60 border border-dark-border rounded-lg space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-mono text-slate-200 font-bold uppercase tracking-wider">
                      Force Scan All Cluster Members
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono mt-1 max-w-xl">
                      ReconForge clusters duplicate responses by body hash, favicon hash, and title+size to avoid redundant scans. By default, only one representative per cluster is scanned with Katana, Nuclei endpoint, and Dalfox. Skipped members remain visible in the UI with their reason. Enable this toggle to scan every member.
                    </p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={scanAllClusterMembers}
                      onChange={(e) => setScanAllClusterMembers(e.target.checked)}
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-accent"></div>
                  </label>
                </div>

                <div className="pt-4 border-t border-dark-border/60 space-y-4">
                  <div>
                    <label className="block text-xs font-mono text-slate-300 font-bold uppercase tracking-wider mb-1">
                      Deep Mode Port Range
                    </label>
                    <input
                      type="text"
                      value={portRange}
                      onChange={(e) => setPortRange(e.target.value)}
                      placeholder="1-10000"
                      className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                    <p className="text-[10px] text-slate-500 font-mono mt-1">
                      Wide port range scanned by Naabu in Deep mode (e.g. 1-10000 or custom comma-separated list). CDN edge nodes are automatically excluded to protect IP reputation.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-slate-300 font-bold uppercase tracking-wider mb-1">
                      Response Body Storage Cap (KB per host)
                    </label>
                    <input
                      type="number"
                      value={responseBodyMaxKb}
                      onChange={(e) => setResponseBodyMaxKb(Number(e.target.value) || 500)}
                      min={50}
                      max={2048}
                      className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                    <p className="text-[10px] text-slate-500 font-mono mt-1">
                      Maximum HTTP response body size stored to disk per host (default: 500 KB, max 2048 KB). Stored per-project with automatic FIFO retention limits.
                    </p>
                  </div>

                  <div className="pt-4 border-t border-dark-border/60">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-xs font-mono text-slate-200 font-bold uppercase tracking-wider">
                          Enable Root-Domain Expansion (Opt-in)
                        </h4>
                        <p className="text-[11px] text-slate-400 font-mono mt-1 max-w-xl">
                          Discovers related root domains, ASNs, and CIDR blocks using asnmap, dnsx -ptr, and amass intel. Suggestions will appear in the Suggested Roots tab and are NEVER scanned automatically without manual approval.
                        </p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={enableRootExpansion}
                          onChange={(e) => setEnableRootExpansion(e.target.checked)}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-accent"></div>
                      </label>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-slate-300 font-bold uppercase tracking-wider mb-1">
                      Deep Mode DNS Permutations Cap (alterx)
                    </label>
                    <input
                      type="number"
                      value={maxPermutations}
                      onChange={(e) => setMaxPermutations(Number(e.target.value) || 50000)}
                      min={1000}
                      max={500000}
                      className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent"
                    />
                    <p className="text-[10px] text-slate-500 font-mono mt-1">
                      Maximum permutation candidates generated by alterx from passive subdomains before resolution (default: 50,000).
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: RECURRING SCHEDULE */}
          {activeTab === "schedule" && (
            <div className="space-y-4">
              <div className="p-4 bg-dark-bg/60 border border-dark-border rounded-lg space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-mono text-slate-200 font-bold uppercase tracking-wider">
                      Automated Continuous Scanning
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                      Run discovery scans automatically on an in-process recurring interval
                    </p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={scheduleEnabled}
                      onChange={(e) => setScheduleEnabled(e.target.checked)}
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-dark-input peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-accent"></div>
                  </label>
                </div>

                <div className="p-3 bg-cyber-primary/5 border border-cyber-primary/20 rounded text-[11px] font-mono text-slate-300 leading-relaxed">
                  <span className="text-cyber-accent font-bold">In-Process Concurrency Guard:</span>{" "}
                  Scans are executed natively by ReconForge's background asyncio scheduler without external task queues.
                  If a previous scan for this project is still in progress when a scheduled run is due, the scheduler
                  will automatically skip the run to prevent overlapping jobs.
                </div>

                {inScopeText.trim().length === 0 && (
                  <div className="p-3 bg-red-950/40 border border-red-500/30 rounded text-[11px] font-mono text-red-300 flex items-start space-x-2">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-bold text-red-200">Scope Required for Scheduling:</span> Recurring schedules require at least one configured in-scope target. Please define in-scope rules in the Scope tab before enabling.
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                      Scan Interval (Hours)
                    </label>
                    <select
                      value={intervalHours}
                      onChange={(e) => setIntervalHours(parseInt(e.target.value, 10))}
                      disabled={!scheduleEnabled}
                      className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent disabled:opacity-40"
                    >
                      <option value={6}>Every 6 Hours (High Frequency)</option>
                      <option value={12}>Every 12 Hours (Twice Daily)</option>
                      <option value={24}>Every 24 Hours (Daily Recon)</option>
                      <option value={48}>Every 48 Hours (Bi-Daily)</option>
                      <option value={72}>Every 72 Hours (3 Days)</option>
                      <option value={168}>Every 168 Hours (Weekly)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                      Scan Profile Mode
                    </label>
                    <select
                      value={scheduleScanMode}
                      onChange={(e) => setScheduleScanMode(e.target.value)}
                      disabled={!scheduleEnabled}
                      className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent disabled:opacity-40"
                    >
                      <option value="fast">Fast Scan (Subdomains, DNS, Ports, HTTP)</option>
                      <option value="deep">Deep Scan (Full 10-Phase Pipeline + Active Probes)</option>
                    </select>
                  </div>
                </div>

                {/* Telemetry info */}
                <div className="border-t border-dark-border/60 pt-3 grid grid-cols-2 gap-3 text-xs font-mono text-slate-400">
                  <div>
                    <span className="text-[10px] uppercase text-slate-500 block">Last Scheduled Scan</span>
                    <span className="text-slate-200">
                      {lastRun ? new Date(lastRun).toLocaleString() : "Never triggered"}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase text-slate-500 block">Next Scheduled Scan</span>
                    <span className={scheduleEnabled ? "text-cyber-accent font-bold" : "text-slate-500"}>
                      {scheduleEnabled
                        ? nextRun
                          ? new Date(nextRun).toLocaleString()
                          : "Scheduled on next evaluation"
                        : "Disabled"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: ALERTS & WEBHOOKS */}
          {activeTab === "alerts" && (
            <div className="space-y-4">
              <div className="p-4 bg-dark-bg/60 border border-dark-border rounded-lg space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-mono text-slate-200 font-bold uppercase tracking-wider">
                      Webhook Alert Notifications
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                      Send rich notifications to Discord and Telegram when attack surface changes
                    </p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={alertsEnabled}
                      onChange={(e) => setAlertsEnabled(e.target.checked)}
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-dark-input peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-accent"></div>
                  </label>
                </div>

                {/* Security Guarantee Banner */}
                <div className="p-3 bg-cyber-success/5 border border-cyber-success/30 rounded text-[11px] font-mono text-cyber-success leading-relaxed flex items-start space-x-2">
                  <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
                  <div>
                    <span className="font-bold">Strict Secrets Redaction:</span> All outbound notification
                    payloads are processed through ReconForge's redaction engine. Authorization headers, API keys,
                    Bearer tokens, and passwords are automatically masked before any webhook is transmitted.
                  </div>
                </div>

                <div className="space-y-3 pt-2">
                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                      Discord Webhook URL
                    </label>
                    <input
                      type="text"
                      placeholder="https://discord.com/api/webhooks/..."
                      value={discordWebhookUrl}
                      onChange={(e) => setDiscordWebhookUrl(e.target.value)}
                      disabled={!alertsEnabled}
                      className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent disabled:opacity-40"
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                        Telegram Bot Token
                      </label>
                      <input
                        type="password"
                        placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
                        value={telegramBotToken}
                        onChange={(e) => setTelegramBotToken(e.target.value)}
                        disabled={!alertsEnabled}
                        className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent disabled:opacity-40"
                      />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                        Telegram Chat ID
                      </label>
                      <input
                        type="text"
                        placeholder="-1001234567890 or @channel"
                        value={telegramChatId}
                        onChange={(e) => setTelegramChatId(e.target.value)}
                        disabled={!alertsEnabled}
                        className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent disabled:opacity-40"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-[10px] font-mono text-slate-400 uppercase block mb-1">
                      Minimum Finding Severity Filter
                    </label>
                    <select
                      value={minPriority}
                      onChange={(e) => setMinPriority(e.target.value)}
                      disabled={!alertsEnabled}
                      className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-cyber-accent disabled:opacity-40"
                    >
                      <option value="info">Informational and higher (All findings)</option>
                      <option value="low">Low severity and higher</option>
                      <option value="medium">Medium severity and higher (Recommended)</option>
                      <option value="high">High severity and higher</option>
                      <option value="critical">Critical findings only</option>
                    </select>
                  </div>

                  <div className="pt-2">
                    <label className="text-[10px] font-mono text-slate-400 uppercase block mb-2">
                      Alert Trigger Events
                    </label>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-slate-300">
                      {[
                        { key: "new_subdomains", label: "New Subdomains Discovered" },
                        { key: "new_live_hosts", label: "New Live Hosts (HTTP 200/300)" },
                        { key: "new_ports", label: "Port Changes (Open / Closed)" },
                        { key: "new_findings", label: "New Vulnerability Findings" },
                        { key: "scan_completed", label: "Scan Completion Summary" },
                      ].map((item) => (
                        <label
                          key={item.key}
                          className="flex items-center space-x-2 p-2 bg-dark-input/60 rounded border border-dark-border/40 cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={Boolean((alertEvents as any)[item.key])}
                            onChange={(e) =>
                              setAlertEvents((prev) => ({ ...prev, [item.key]: e.target.checked }))
                            }
                            disabled={!alertsEnabled}
                            className="rounded bg-dark-bg border-dark-border text-cyber-accent focus:ring-0"
                          />
                          <span>{item.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB: SUGGESTED ROOTS (PHASE 7) */}
          {activeTab === "suggested_roots" && (
            <div className="space-y-4">
              <div className="p-4 bg-dark-bg/60 border border-dark-border rounded-lg flex items-start justify-between gap-4">
                <div>
                  <h4 className="text-xs font-mono text-slate-200 font-bold uppercase tracking-wider flex items-center gap-2">
                    <Globe className="w-4 h-4 text-cyber-accent" />
                    <span>Opt-In Suggested Root Domains</span>
                  </h4>
                  <p className="text-[11px] text-slate-400 font-mono mt-1 max-w-xl">
                    Discovered via ASNMap, reverse DNS PTR lookups, and Amass Intel. Suggestions are strictly ideas for human review and are <strong className="text-amber-400">NEVER</strong> scanned automatically. Approving a domain adds it to your authorized seeds and in-scope target rules for future scans.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={fetchSuggestedRoots}
                  disabled={loadingSuggestedRoots}
                  className="px-3 py-1.5 rounded border border-dark-border text-xs font-mono text-slate-300 hover:text-white bg-dark-input hover:bg-dark-hover flex items-center gap-1.5 cursor-pointer shrink-0"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loadingSuggestedRoots ? "animate-spin text-cyber-accent" : ""}`} />
                  <span>Refresh</span>
                </button>
              </div>

              <div className="overflow-x-auto border border-dark-border rounded-lg">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-dark-bg/80 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider">
                      <th className="p-3">Suggested Domain</th>
                      <th className="p-3">Source Tool</th>
                      <th className="p-3">Evidence</th>
                      <th className="p-3">Status</th>
                      <th className="p-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {suggestedRoots.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="p-8 text-center text-slate-500 font-mono uppercase tracking-widest">
                          {loadingSuggestedRoots
                            ? "Loading suggested roots..."
                            : "No root domain suggestions found. Enable 'Root-Domain Expansion' in Clustering settings and run a scan."}
                        </td>
                      </tr>
                    ) : (
                      suggestedRoots.map((s, idx) => {
                        const domain = s.domain || s.value;
                        const status = s.status || "pending";
                        const inAction = actionInProgress === domain;

                        return (
                          <tr key={`${domain}-${idx}`} className="border-b border-dark-border hover:bg-dark-hover/30 transition-colors">
                            <td className="p-3 font-mono font-bold text-slate-200">
                              <a
                                href={`https://${domain}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="hover:text-cyber-accent hover:underline flex items-center gap-1"
                              >
                                {domain}
                              </a>
                            </td>
                            <td className="p-3 font-mono text-slate-400">
                              <span className="px-2 py-0.5 rounded bg-dark-bg border border-dark-border text-[10px] text-cyber-accent">
                                {s.source || "intel"}
                              </span>
                            </td>
                            <td className="p-3 text-[11px] text-slate-400 font-mono max-w-xs truncate" title={s.evidence || ""}>
                              {s.evidence || "—"}
                            </td>
                            <td className="p-3 font-mono">
                              {status === "approved" ? (
                                <span className="px-2 py-0.5 rounded-full text-[10px] uppercase font-bold bg-emerald-500/20 border border-emerald-500/40 text-emerald-400">
                                  Approved (In Scope)
                                </span>
                              ) : status === "rejected" ? (
                                <span className="px-2 py-0.5 rounded-full text-[10px] uppercase font-mono bg-slate-700/40 border border-slate-600 text-slate-400">
                                  Rejected
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded-full text-[10px] uppercase font-mono bg-amber-500/20 border border-amber-500/40 text-amber-300">
                                  Pending Review
                                </span>
                              )}
                            </td>
                            <td className="p-3 text-right">
                              <div className="flex items-center justify-end gap-2">
                                {status !== "approved" && (
                                  <button
                                    type="button"
                                    disabled={inAction}
                                    onClick={() => handleApproveRoot(domain)}
                                    className="px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 font-mono text-[11px] font-bold cursor-pointer transition-colors"
                                  >
                                    {inAction ? "..." : "Approve"}
                                  </button>
                                )}
                                {status !== "rejected" && (
                                  <button
                                    type="button"
                                    disabled={inAction}
                                    onClick={() => handleRejectRoot(domain)}
                                    className="px-2.5 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 font-mono text-[11px] cursor-pointer transition-colors"
                                  >
                                    {inAction ? "..." : "Reject"}
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: PROVIDER API KEYS (PHASE 7) */}
          {activeTab === "api_keys" && (
            <div className="space-y-4">
              <div className="p-4 bg-dark-bg/60 border border-dark-border rounded-lg">
                <h4 className="text-xs font-mono text-slate-200 font-bold uppercase tracking-wider flex items-center gap-2">
                  <Key className="w-4 h-4 text-cyber-accent" />
                  <span>Subfinder Passive Provider API Keys</span>
                </h4>
                <p className="text-[11px] text-slate-400 font-mono mt-1">
                  API keys are stored securely in <code className="text-slate-300">backend/config/provider_keys.json</code> (gitignored) and automatically synchronized to <code className="text-slate-300">~/.config/subfinder/provider-config.yaml</code> inside WSL. Values are never logged or returned unmasked.
                </p>
                {keysSavedSuccess && (
                  <div className="mt-3 p-2 bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs font-mono rounded flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Provider API keys saved and synchronized to WSL Subfinder config successfully!</span>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { id: "securitytrails", name: "SecurityTrails", placeholder: "Enter SecurityTrails API Key" },
                  { id: "censys", name: "Censys", placeholder: "Enter Censys API Key" },
                  { id: "shodan", name: "Shodan", placeholder: "Enter Shodan API Key" },
                  { id: "virustotal", name: "VirusTotal", placeholder: "Enter VirusTotal API Key" },
                  { id: "github", name: "GitHub PAT", placeholder: "Enter GitHub Personal Access Token" },
                  { id: "chaos", name: "Chaos (ProjectDiscovery)", placeholder: "Enter ProjectDiscovery Chaos Key" },
                ].map((p) => {
                  const currentMasked = providerKeysStatus?.keys?.[p.id];
                  const hasKey = Boolean(currentMasked && currentMasked !== "");

                  return (
                    <div key={p.id} className="bg-dark-bg/60 border border-dark-border rounded-lg p-3.5 space-y-2">
                      <div className="flex items-center justify-between">
                        <label className="text-xs font-mono text-slate-200 font-bold uppercase">
                          {p.name}
                        </label>
                        {hasKey ? (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-emerald-500/20 border border-emerald-500/40 text-emerald-400">
                            Configured ({currentMasked})
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 border border-slate-700 text-slate-500">
                            Not Set
                          </span>
                        )}
                      </div>
                      <input
                        type="password"
                        placeholder={hasKey ? "Leave blank to keep existing key" : p.placeholder}
                        value={keyInputs[p.id] || ""}
                        onChange={(e) => setKeyInputs((prev) => ({ ...prev, [p.id]: e.target.value }))}
                        className="w-full bg-dark-input border border-dark-border rounded p-2 text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyber-accent"
                      />
                    </div>
                  );
                })}
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  disabled={savingKeys}
                  onClick={handleSaveKeys}
                  className="flex items-center space-x-1.5 px-4 py-2 bg-cyber-primary hover:bg-cyber-accent text-white rounded text-xs font-mono font-bold uppercase tracking-wider cursor-pointer transition-colors"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>{savingKeys ? "Saving & Syncing..." : "Save & Sync Provider Keys"}</span>
                </button>
              </div>
            </div>
          )}

          {/* TAB 5: WSL TOOL REGISTRY */}
          {activeTab === "tools" && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-dark-bg/60 border border-dark-border p-3.5 rounded-lg">
                <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
                  <div>
                    <span className="text-slate-400">Total Tools: </span>
                    <span className="text-slate-200 font-bold">{toolsSummary?.total ?? tools.length}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Installed: </span>
                    <span className="text-cyber-success font-bold">{toolsSummary?.installed ?? 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Missing (Optional): </span>
                    <span className="text-cyber-warning font-bold">{toolsSummary?.missing ?? 0}</span>
                  </div>
                  {lastChecked && (
                    <div className="text-[11px] text-slate-500">
                      <span>Last checked: </span>
                      <span className="text-slate-300">{new Date(lastChecked).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                    </div>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => fetchTools(true)}
                  disabled={loadingTools}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-dark-card border border-dark-border hover:border-cyber-accent/50 text-slate-300 rounded text-xs font-mono cursor-pointer transition-colors shrink-0"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loadingTools ? "animate-spin text-cyber-accent" : ""}`} />
                  <span>{loadingTools ? "Checking WSL..." : "Rescan WSL"}</span>
                </button>
              </div>

              {/* Requirement 4: Setting assume_tools_installed */}
              <div className="flex items-center justify-between p-3.5 bg-dark-bg/60 border border-dark-border rounded-lg">
                <div>
                  <h4 className="text-xs font-mono text-slate-200 font-bold uppercase tracking-wider flex items-center space-x-2">
                    <span>Assume Tools Installed</span>
                    <span className="text-[10px] text-cyber-accent bg-cyber-accent/10 border border-cyber-accent/30 px-1.5 py-0.2 rounded font-normal">
                      High Performance
                    </span>
                  </h4>
                  <p className="text-[11px] text-slate-400 font-mono mt-0.5 max-w-xl">
                    Skips the pre-scan WSL availability gate and executes pipeline tools using cached absolute paths. Any missing or failed tool will emit a stage error while the scan continues uninterrupted.
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer ml-4">
                  <input
                    type="checkbox"
                    checked={assumeToolsInstalled}
                    onChange={(e) => setAssumeToolsInstalled(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-dark-input peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyber-accent"></div>
                </label>
              </div>

              {/* Error or Warning State if WSL Unreachable or Timeout */}
              {wslWarning && (
                <div className="p-3 bg-amber-950/30 border border-amber-500/30 rounded text-xs font-mono text-amber-300 flex items-start space-x-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-bold text-amber-200">WSL Tool Detection Notice: </span>
                    {wslWarning}
                  </div>
                </div>
              )}

              {loadingTools && tools.length === 0 ? (
                <div className="py-12 text-center text-slate-400 text-xs font-mono flex items-center justify-center space-x-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-cyber-accent" />
                  <span>Loading cached WSL tool registry...</span>
                </div>
              ) : (
                <div className="border border-dark-border rounded-lg overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-dark-bg text-slate-400 uppercase tracking-wider text-[10px] border-b border-dark-border">
                        <tr>
                          <th className="py-2.5 px-3">Tool</th>
                          <th className="py-2.5 px-3">Category</th>
                          <th className="py-2.5 px-3">WSL Binary</th>
                          <th className="py-2.5 px-3">Status</th>
                          <th className="py-2.5 px-3 text-right">Install Hint / Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-dark-border/50">
                        {tools.map((t) => (
                          <tr key={t.name} className="hover:bg-dark-bg/30 transition-colors">
                            <td className="py-2.5 px-3 font-bold text-slate-200">
                              {t.name}
                              <div className="text-[10px] font-normal text-slate-500">{t.description}</div>
                            </td>
                            <td className="py-2.5 px-3 text-slate-400">{t.category}</td>
                            <td className="py-2.5 px-3">
                              <code className="text-cyber-accent text-[11px] bg-dark-bg px-1.5 py-0.5 rounded border border-dark-border/40">
                                {t.wsl_binary}
                              </code>
                            </td>
                            <td className="py-2.5 px-3">
                              {t.installed ? (
                                <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-cyber-success/10 border border-cyber-success/30 text-cyber-success">
                                  <CheckCircle2 className="w-3 h-3" />
                                  <span>Installed</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-cyber-warning/10 border border-cyber-warning/30 text-cyber-warning">
                                  <XCircle className="w-3 h-3" />
                                  <span>Missing</span>
                                </span>
                              )}
                            </td>
                            <td className="py-2.5 px-3 text-right">
                              {!t.installed ? (
                                <button
                                  type="button"
                                  onClick={() => handleCopyInstall(t.install_hint, t.name)}
                                  className="inline-flex items-center space-x-1.5 px-2.5 py-1 bg-cyber-primary/10 border border-cyber-primary/30 hover:bg-cyber-primary/20 text-cyber-accent rounded text-[11px] font-mono transition-all cursor-pointer"
                                  title={t.install_hint}
                                >
                                  {copiedTool === t.name ? (
                                    <>
                                      <Check className="w-3 h-3 text-cyber-success" />
                                      <span className="text-cyber-success">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3 h-3" />
                                      <span>Copy Install</span>
                                    </>
                                  )}
                                </button>
                              ) : (
                                <span className="text-[10px] text-slate-500">Ready in WSL</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-dark-border bg-dark-bg/60 flex items-center justify-between">
          <div className="text-[11px] text-slate-500 font-mono">
            {hasScopeConfigured ? (
              <span className="text-cyber-success">✓ Scope rules defined</span>
            ) : (
              <span className="text-cyber-warning">⚠ Scope unset — warning active</span>
            )}
          </div>

          <div className="flex items-center space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-dark-border rounded text-xs font-mono font-semibold text-slate-400 hover:text-slate-200 cursor-pointer transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={saving}
              onClick={handleSave}
              className="flex items-center space-x-1.5 px-5 py-2 bg-gradient-to-r from-cyber-primary to-cyber-accent text-white rounded text-xs font-mono font-bold uppercase tracking-wider hover:opacity-90 active:scale-[0.98] transition-all cursor-pointer shadow-lg shadow-cyber-primary/20"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{saving ? "Saving..." : "Save Configuration"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
