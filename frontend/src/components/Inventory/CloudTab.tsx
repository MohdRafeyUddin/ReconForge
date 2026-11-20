import React, { useEffect, useMemo, useState } from "react";
import { Cloud, RefreshCw, AlertCircle } from "lucide-react";
import { apiCall } from "../../services/api";
import { Pagination, usePagination } from "../Common/Pagination";
import { FetchBodyButton } from "./FetchBodyButton";

interface CloudAsset {
  id: string;
  type: string;
  domain?: string;
  value?: string;
  status?: string;
  metadata?: Record<string, any>;
}

interface CloudTabProps {
  projectId?: string;
}

export const CloudTab: React.FC<CloudTabProps> = ({ projectId }) => {
  const [items, setItems] = useState<CloudAsset[]>([]);
  const [providers, setProviders] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    if (!projectId) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError("");
    apiCall(`/assets/project/${projectId}/cloud-services`)
      .then((res: any) => {
        if (cancelled) return;
        setItems(Array.isArray(res?.items) ? res.items : []);
        setProviders(res?.providers || {});
      })
      .catch((err: any) => {
        if (!cancelled) setError(err?.message || "Failed to load cloud services");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, refreshTick]);

  const rows = useMemo(
    () =>
      items.map((asset) => {
        const meta = asset.metadata || {};
        const isBucket = ["bucket", "cloud_bucket"].includes(asset.type);
        const category = String(meta.category || (isBucket ? "storage" : "cloud"));
        return {
          id: asset.id,
          url: String(meta.url || asset.value || asset.domain || ""),
          provider: String(meta.provider || "").toLowerCase(),
          service: String(meta.service || (isBucket ? "bucket" : category)),
          category,
          access: isBucket
            ? (meta.public ? "PUBLIC" : "EXISTS")
            : category === "storage"
              ? (meta.public ? "PUBLIC" : "STORAGE")
              : "DETECTED",
          related: String(meta.parent_host || meta.in_scope_keyword || meta.tied_to_keyword || ""),
          bucketName: String(meta.bucket_name || ""),
        };
      }),
    [items]
  );

  const pager = usePagination(rows, 20);

  if (!projectId) return null;

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl glass overflow-hidden">
      <div className="p-4 border-b border-dark-border flex flex-wrap items-center justify-between gap-3 bg-dark-bg/50">
        <div className="flex items-center gap-2">
          <Cloud className="w-4 h-4 text-cyber-accent" />
          <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            Cloud Services &amp; Buckets
          </span>
          <span className="text-[10px] font-mono text-slate-500">
            {rows.length} resource(s)
          </span>
        </div>
        <div className="flex items-center gap-2">
          {Object.entries(providers).length > 0 && (
            <div className="flex flex-wrap gap-1">
              {Object.entries(providers)
                .sort(([, a], [, b]) => b - a)
                .map(([provider, count]) => (
                  <span
                    key={provider}
                    className="px-1.5 py-0.5 rounded border border-dark-border bg-dark-input text-[9px] font-mono uppercase text-slate-400"
                  >
                    {provider}: {count}
                  </span>
                ))}
            </div>
          )}
          <button
            onClick={() => setRefreshTick((tick) => tick + 1)}
            className="p-1.5 rounded border border-dark-border bg-dark-input hover:bg-dark-hover text-slate-300 cursor-pointer"
            title="Refresh cloud services"
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

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-dark-bg/70 border-b border-dark-border text-slate-400 font-mono uppercase tracking-wider text-[10px]">
              <th className="p-3">Resource</th>
              <th className="p-3">Provider</th>
              <th className="p-3">Service</th>
              <th className="p-3">Type / Access</th>
              <th className="p-3">Related Host</th>
              <th className="p-3">Body</th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-8 text-center text-slate-500 uppercase tracking-widest font-mono text-[10px]">
                  Loading cloud resources...
                </td>
              </tr>
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-8 text-center text-slate-500 font-mono text-[10px]">
                  <div className="uppercase tracking-widest">No cloud resources detected yet</div>
                  <div className="mt-2 normal-case text-slate-600">
                    Cloud URLs are classified automatically from discovered URLs (S3, CloudFront, EC2,
                    GCS, Azure, Cloudflare, etc.). Bucket enumeration is additionally opt-in.
                  </div>
                </td>
              </tr>
            ) : (
              pager.pageItems.map((row) => (
                <tr
                  key={row.id || row.url}
                  className="border-b border-dark-border/50 hover:bg-dark-hover/30 font-mono text-[11px]"
                >
                  <td className="p-3 break-all max-w-md">
                    <a
                      href={row.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyber-accent hover:underline"
                    >
                      {row.url}
                    </a>
                    {row.bucketName && (
                      <div className="text-[9px] text-slate-500 mt-0.5">
                        bucket: {row.bucketName}
                      </div>
                    )}
                  </td>
                  <td className="p-3 uppercase text-slate-300">{row.provider || "—"}</td>
                  <td className="p-3 text-slate-300">{row.service || "—"}</td>
                  <td className="p-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${
                        row.access === "PUBLIC"
                          ? "bg-cyber-danger/20 border-cyber-danger/40 text-cyber-danger"
                          : row.access === "DETECTED"
                            ? "bg-cyber-accent/10 border-cyber-accent/35 text-cyber-accent"
                            : "bg-cyber-success/10 border-cyber-success/30 text-cyber-success"
                      }`}
                    >
                      {row.access}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400 break-all">
                    {row.related || "—"}
                  </td>
                  <td className="p-3">
                    <FetchBodyButton projectId={projectId} url={row.url} compact />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <Pagination
        page={pager.page}
        pageSize={pager.pageSize}
        total={pager.total}
        onPageChange={pager.setPage}
        onPageSizeChange={pager.setPageSize}
        itemLabel="cloud resource(s)"
      />
    </div>
  );
};
