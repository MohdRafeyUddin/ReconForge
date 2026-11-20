import React, { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { Camera, RefreshCw, X, AlertCircle } from "lucide-react";
import { apiCall, API_BASE_URL } from "../../services/api";
import { Pagination, usePagination } from "../Common/Pagination";
import { classifyCloudHost } from "../../utils/cloud";

interface ScreenshotItem {
  job_id: string;
  url: string;
  host: string;
  title?: string;
  filename: string;
  path: string;
  size?: number;
  page_hash?: string;
  previous_page_hash?: string;
  changed?: boolean;
  first_seen?: string;
  last_seen?: string;
  image_url: string;
}

interface ScreenshotRun {
  job_id: string;
  started_at?: string | null;
  status?: string;
  count: number;
}

interface ScreenshotResponse {
  runs: ScreenshotRun[];
  selected_job_id?: string | null;
  items: ScreenshotItem[];
  total: number;
}

interface ScreenshotsTabProps {
  projectId?: string;
  refreshNonce?: number;
}

const origin = API_BASE_URL.replace(/\/api\/v1\/?$/, "");

export const ScreenshotsTab: React.FC<ScreenshotsTabProps> = ({
  projectId,
  refreshNonce = 0,
}) => {
  const [runs, setRuns] = useState<ScreenshotRun[]>([]);
  const [selectedJob, setSelectedJob] = useState<string>("");
  const [items, setItems] = useState<ScreenshotItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [fullImage, setFullImage] = useState<ScreenshotItem | null>(null);
  const [imageError, setImageError] = useState(false);
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    if (!projectId) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    const fetchShots = async () => {
      setLoading(true);
      setError("");
      try {
        const query = selectedJob ? `?job_id=${encodeURIComponent(selectedJob)}` : "";
        const res: ScreenshotResponse = await apiCall(
          `/assets/project/${projectId}/screenshots${query}`
        );
        if (cancelled) return;
        setRuns(res.runs || []);
        setItems(res.items || []);
        if (res.selected_job_id && res.selected_job_id !== selectedJob) {
          setSelectedJob(res.selected_job_id);
        }
      } catch (err: any) {
        if (!cancelled) setError(err.message || "Failed to load screenshots");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchShots();
    return () => {
      cancelled = true;
    };
  }, [projectId, selectedJob, refreshTick, refreshNonce]);

  // Poll while the tab is open so targeted runs appear without a manual
  // refresh (the run list only gains entries as shots are recorded).
  useEffect(() => {
    if (!projectId) return;
    const timer = window.setInterval(() => {
      setRefreshTick((n) => n + 1);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [projectId]);

  // Cloud-service screenshots are ordered first so they occupy the leading
  // "Cloud Services" subsection across pages.
  const orderedItems = useMemo(() => {
    return [...items].sort((a, b) => {
      const aCloud = classifyCloudHost(a.host) ? 1 : 0;
      const bCloud = classifyCloudHost(b.host) ? 1 : 0;
      return bCloud - aCloud;
    });
  }, [items]);

  const {
    page,
    setPage,
    pageSize,
    setPageSize,
    pageItems,
    total,
  } = usePagination(orderedItems, 20, selectedJob);

  const cloudPageItems = useMemo(
    () => pageItems.filter((item) => Boolean(classifyCloudHost(item.host))),
    [pageItems]
  );

  const byHost = useMemo(() => {
    const grouped: Record<string, ScreenshotItem[]> = {};
    for (const item of pageItems) {
      if (classifyCloudHost(item.host)) continue;
      const host = item.host || "unknown";
      if (!grouped[host]) grouped[host] = [];
      grouped[host].push(item);
    }
    return Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b));
  }, [pageItems]);

  const renderScreenshotCard = (item: ScreenshotItem) => {
    const cloudInfo = classifyCloudHost(item.host);
    return (
      <div
        key={`${item.job_id}-${item.filename}`}
        className="bg-dark-bg border border-dark-border rounded-lg overflow-hidden"
      >
        <button
          onClick={() => {
            setImageError(false);
            setFullImage(item);
          }}
          className="block w-full bg-black/30 cursor-zoom-in"
          title="Open full size"
        >
          <img
            src={`${origin}${item.image_url}`}
            alt={`Screenshot of ${item.host}`}
            className="w-full h-40 object-cover"
            loading="lazy"
          />
        </button>
        <div className="p-2 font-mono space-y-0.5">
          {cloudInfo && (
            <span className="inline-flex w-fit px-1.5 py-0.5 rounded border border-cyber-accent/40 bg-cyber-accent/10 text-cyber-accent text-[8px] font-bold uppercase">
              {cloudInfo.provider} • {cloudInfo.service}
            </span>
          )}
          {item.url ? (
            <a
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
              className="block text-[9px] text-cyber-accent hover:underline break-all"
              title="Open captured page"
            >
              {item.url} ↗
            </a>
          ) : (
            <span className="text-[9px] text-slate-500">No captured URL</span>
          )}
          <div className="flex items-center justify-between gap-2 text-[9px] text-slate-500">
            <span>
              {item.size ? `${Math.round(item.size / 1024)} KB` : ""}
              {item.first_seen ? ` • ${new Date(item.first_seen).toLocaleString()}` : ""}
            </span>
            {item.changed && (
              <span className="shrink-0 px-1 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 text-amber-300 text-[8px] font-bold uppercase">
                Changed
              </span>
            )}
          </div>
        </div>
      </div>
    );
  };

  if (!projectId) return null;

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      <div className="p-4 border-b border-dark-border flex flex-wrap items-center justify-between gap-3 bg-dark-bg/50">
        <div className="flex items-center gap-2">
          <Camera className="w-4 h-4 text-cyber-accent" />
          <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            Screenshots
          </span>
          <span className="text-[10px] font-mono text-slate-500">
            {items.length} image(s)
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Run:</span>
          <select
            value={selectedJob}
            onChange={(e) => setSelectedJob(e.target.value)}
            className="bg-dark-input border border-dark-border rounded px-2 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyber-accent max-w-[260px]"
          >
            {runs.length === 0 && <option value="">No runs with screenshots</option>}
            {runs.map((run) => (
              <option key={run.job_id} value={run.job_id}>
                {run.started_at ? new Date(run.started_at).toLocaleString() : run.job_id.slice(-8)}
                {" — "}
                {run.count} shot(s)
              </option>
            ))}
          </select>
          <button
            onClick={() => setRefreshTick((n) => n + 1)}
            className="p-1.5 rounded border border-dark-border bg-dark-input hover:bg-dark-hover text-slate-300 cursor-pointer"
            title="Refresh"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 text-xs font-mono text-rose-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4" /> {error}
        </div>
      )}

      {loading && !items.length ? (
        <div className="p-10 text-center text-xs font-mono text-slate-500 uppercase tracking-widest">
          Loading screenshots...
        </div>
      ) : items.length === 0 ? (
        <div className="p-10 text-center text-xs font-mono text-slate-500">
          No screenshots for this run. Only live HTTP hosts are captured — DNS-resolved
          hosts that do not answer over HTTP have no screenshot.
        </div>
      ) : (
        <div className="p-4 space-y-5">
          {cloudPageItems.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between border-b border-cyber-accent/30 pb-1.5">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyber-accent">
                  Cloud Services
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {cloudPageItems.length} cloud shot(s)
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                {cloudPageItems.map(renderScreenshotCard)}
              </div>
            </div>
          )}
          {byHost.map(([host, hostItems]) => (
            <div key={host} className="space-y-2">
              <div className="flex items-center justify-between border-b border-dark-border pb-1.5">
                <span className="text-xs font-mono font-bold text-slate-200 select-all">{host}</span>
                <span className="text-[10px] font-mono text-slate-500">{hostItems.length} shot(s)</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                {hostItems.map(renderScreenshotCard)}
              </div>
            </div>
          ))}
        </div>
      )}

      {items.length > 0 && (
        <Pagination
          page={page}
          pageSize={pageSize}
          total={total}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
          itemLabel="image(s)"
        />
      )}

      {fullImage &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            className="fixed inset-0 z-[100] bg-black/90 p-4 overflow-y-auto"
            onClick={() => setFullImage(null)}
          >
            <div
              className="min-h-full flex flex-col items-center justify-center gap-3"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="w-full max-w-6xl flex items-center justify-between gap-3 p-2 bg-dark-card border border-dark-border rounded-t-lg">
                <div className="min-w-0">
                  {fullImage.url ? (
                    <a
                      href={fullImage.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-mono text-cyber-accent hover:underline break-all"
                      title="Open captured page"
                    >
                      {fullImage.url} ↗
                    </a>
                  ) : (
                    <span className="text-xs font-mono text-slate-300">Screenshot</span>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <a
                    href={`${origin}${fullImage.image_url}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2 py-1 rounded border border-dark-border bg-dark-input text-slate-300 hover:text-white text-[10px] font-mono"
                    title="Open screenshot image"
                  >
                    Open image
                  </a>
                  <button
                    onClick={() => setFullImage(null)}
                    className="p-1.5 rounded border border-dark-border bg-dark-input text-slate-300 hover:text-white cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>
              <div className="w-full max-w-6xl bg-black/60 border border-t-0 border-dark-border rounded-b-lg flex items-center justify-center min-h-[40vh] p-2">
                {imageError ? (
                  <div className="p-6 text-center text-xs font-mono text-rose-300 space-y-2">
                    <div>Unable to render this screenshot.</div>
                    <a
                      href={`${origin}${fullImage.image_url}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyber-accent underline"
                    >
                      Open image in a new tab
                    </a>
                  </div>
                ) : (
                  <img
                    key={fullImage.image_url}
                    src={`${origin}${fullImage.image_url}`}
                    alt={`Screenshot of ${fullImage.host}`}
                    className="block max-w-full max-h-[80vh] w-auto h-auto object-contain"
                    onError={() => setImageError(true)}
                  />
                )}
              </div>
            </div>
          </div>,
          document.body
        )}
    </div>
  );
};
