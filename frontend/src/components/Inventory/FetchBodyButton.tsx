import React, { useState } from "react";
import { createPortal } from "react-dom";
import { AlertCircle, FileText, Loader2, RefreshCw, X } from "lucide-react";
import { apiCall } from "../../services/api";

interface FetchBodyButtonProps {
  projectId?: string;
  url: string;
  label?: string;
  compact?: boolean;
}

interface BodyResult {
  ok: boolean;
  url?: string;
  requested_url?: string;
  cached?: boolean;
  status_code?: number;
  content_type?: string;
  size?: number;
  stored?: boolean;
  stored_path?: string;
  truncated?: boolean;
  fetched_at?: string;
  body_preview?: string;
  request?: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    params?: Record<string, string>;
  };
  response_headers?: Record<string, string>;
  error?: string;
}

const formatBytes = (value?: number) => {
  if (!value || value <= 0) return "0 B";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${Math.round(value / 102.4) / 10} KB`;
  return `${Math.round(value / (1024 * 102.4)) / 10} MB`;
};

export const FetchBodyButton: React.FC<FetchBodyButtonProps> = ({
  projectId,
  url,
  label = "Body",
  compact = false,
}) => {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BodyResult | null>(null);
  const [error, setError] = useState("");
  const [showHeaders, setShowHeaders] = useState(false);

  if (!projectId || !url) return null;

  const run = async (force = false) => {
    setLoading(true);
    setError("");
    try {
      const res: BodyResult = await apiCall(
        `/assets/project/${projectId}/fetch-body`,
        {
          method: "POST",
          body: JSON.stringify({ url, force }),
        }
      );
      setResult(res);
    } catch (err: any) {
      setResult(null);
      const message = String(err?.message || "Failed to fetch response body");
      setError(
        /dns resolution failed/i.test(message)
          ? `${url} does not resolve in DNS (dead, passive-only, or not publicly resolvable). ${message}`
          : message
      );
    } finally {
      setLoading(false);
    }
  };

  const close = () => {
    setResult(null);
    setError("");
    setShowHeaders(false);
  };

  const requestPayload = result?.request
    ? JSON.stringify(result.request, null, 2)
    : "";
  const responseHeaders = result?.response_headers
    ? JSON.stringify(result.response_headers, null, 2)
    : "";

  return (
    <>
      <button
        type="button"
        onClick={(event) => {
          event.stopPropagation();
          run(false);
        }}
        disabled={loading}
        title={`Fetch and store response body for ${url}`}
        className={`inline-flex items-center justify-center gap-1 rounded border border-dark-border bg-dark-input text-[9px] font-mono font-bold uppercase text-slate-400 hover:text-cyber-accent hover:border-cyber-accent/50 disabled:opacity-50 cursor-pointer ${
          compact ? "px-1.5 py-0.5" : "px-2 py-1"
        }`}
      >
        {loading ? (
          <Loader2 className="w-3 h-3 animate-spin" />
        ) : (
          <FileText className="w-3 h-3" />
        )}
        {!compact && <span>{label}</span>}
      </button>

      {(result || error) &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-[100] bg-black/90 p-4 overflow-y-auto"
            onClick={close}
          >
            <div
              className="mx-auto w-full max-w-5xl bg-dark-card border border-dark-border rounded-lg overflow-hidden"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="flex items-start justify-between gap-3 p-3 border-b border-dark-border">
                <div className="min-w-0">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-cyber-accent">
                    {error ? "Response Body Fetch Failed" : "Stored Response Body"}
                  </div>
                  <div className="text-xs font-mono text-slate-200 break-all select-all mt-1">
                    {url}
                  </div>
                </div>
                <button
                  onClick={close}
                  className="shrink-0 p-1.5 rounded border border-dark-border bg-dark-input text-slate-300 hover:text-white cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {error ? (
                <div className="p-6 flex items-start gap-2 text-xs font-mono text-rose-300">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{error}</span>
                </div>
              ) : (
                result && (
                  <div className="p-3 space-y-3">
                    <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
                      <span className="px-2 py-0.5 rounded border border-dark-border bg-dark-bg text-slate-300">
                        HTTP {result.status_code ?? "—"}
                      </span>
                      <span className="px-2 py-0.5 rounded border border-dark-border bg-dark-bg text-slate-300">
                        {formatBytes(result.size)}
                        {result.truncated ? " (truncated)" : ""}
                      </span>
                      <span className="px-2 py-0.5 rounded border border-dark-border bg-dark-bg text-slate-400">
                        {result.content_type || "unknown content-type"}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded border font-bold uppercase ${
                          result.cached
                            ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-300"
                            : result.stored
                              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                              : "border-amber-500/40 bg-amber-500/10 text-amber-300"
                        }`}
                      >
                        {result.cached ? "Cached" : result.stored ? "Stored" : "Not stored"}
                      </span>
                      <button
                        onClick={() => run(true)}
                        disabled={loading}
                        className="ml-auto inline-flex items-center gap-1 px-2 py-1 rounded border border-dark-border bg-dark-input text-slate-300 hover:text-white cursor-pointer disabled:opacity-50"
                        title="Fetch again and overwrite the stored body"
                      >
                        <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
                        Force refetch
                      </button>
                    </div>

                    {result.stored_path && (
                      <div className="text-[10px] font-mono text-slate-500 break-all select-all">
                        Stored: {result.stored_path}
                        {result.fetched_at ? ` • ${result.fetched_at}` : ""}
                      </div>
                    )}

                    <button
                      onClick={() => setShowHeaders((current) => !current)}
                      className="text-[10px] font-mono text-cyber-accent hover:underline cursor-pointer"
                    >
                      {showHeaders ? "Hide request/response headers" : "Show request/response headers"}
                    </button>

                    {showHeaders && (
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                        <div>
                          <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                            Request
                          </div>
                          <pre className="bg-dark-bg border border-dark-border rounded p-2 text-[10px] text-slate-300 max-h-56 overflow-auto whitespace-pre-wrap break-all">
                            {requestPayload}
                          </pre>
                        </div>
                        <div>
                          <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                            Response Headers
                          </div>
                          <pre className="bg-dark-bg border border-dark-border rounded p-2 text-[10px] text-slate-300 max-h-56 overflow-auto whitespace-pre-wrap break-all">
                            {responseHeaders || "—"}
                          </pre>
                        </div>
                      </div>
                    )}

                    <div>
                      <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                        Body Preview
                      </div>
                      <pre className="bg-dark-bg border border-dark-border rounded p-3 text-[10px] text-slate-300 max-h-[55vh] overflow-auto whitespace-pre-wrap break-all select-all">
                        {result.body_preview || "(empty body)"}
                      </pre>
                    </div>
                  </div>
                )
              )}
            </div>
          </div>,
          document.body
        )}
    </>
  );
};
