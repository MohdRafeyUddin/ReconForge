import React from "react";
import { Target, Wifi } from "lucide-react";

export interface GfCategoryStats {
  xss: number;
  sqli: number;
  ssrf: number;
  redirect: number;
  lfi: number;
  rce: number;
  idor: number;
  ssti: number;
  debug: number;
  upload: number;
  aws: number;
  graphql: number;
  [key: string]: number;
}

interface GfCardProps {
  stats: GfCategoryStats;
  isRunning?: boolean;
}

const CATEGORY_META: { key: keyof GfCategoryStats; label: string; color: string; border: string }[] = [
  { key: "xss",      label: "XSS",      color: "text-cyber-danger",   border: "border-cyber-danger/30" },
  { key: "sqli",     label: "SQLi",     color: "text-orange-400",     border: "border-orange-400/30" },
  { key: "ssrf",     label: "SSRF",     color: "text-cyber-warning",  border: "border-cyber-warning/30" },
  { key: "redirect", label: "Redirect", color: "text-cyber-accent",   border: "border-cyber-accent/30" },
  { key: "lfi",      label: "LFI",      color: "text-purple-400",     border: "border-purple-400/30" },
  { key: "rce",      label: "RCE",      color: "text-red-400",        border: "border-red-400/30" },
  { key: "idor",     label: "IDOR",     color: "text-pink-400",       border: "border-pink-400/30" },
  { key: "ssti",     label: "SSTI",     color: "text-indigo-400",     border: "border-indigo-400/30" },
  { key: "debug",    label: "Debug",    color: "text-slate-400",      border: "border-slate-500/30" },
  { key: "upload",   label: "Upload",   color: "text-teal-400",       border: "border-teal-400/30" },
  { key: "aws",      label: "AWS",      color: "text-yellow-400",     border: "border-yellow-400/30" },
  { key: "graphql",  label: "GraphQL",  color: "text-cyber-primary",  border: "border-cyber-primary/30" },
];

export const GfCard: React.FC<GfCardProps> = ({ stats, isRunning = false }) => {
  const totalClassified = Object.values(stats).reduce((a, b) => a + b, 0);
  const nonZero = CATEGORY_META.filter((c) => stats[c.key] > 0);

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
      <div className="flex items-center justify-between border-b border-dark-border pb-2 mb-4">
        <div className="flex items-center gap-2">
          <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <Target className="w-3.5 h-3.5 text-cyber-danger" />
            Interesting Endpoints
          </h4>
          {totalClassified > 0 && (
            <span className="px-1.5 py-0.5 bg-cyber-danger/20 border border-cyber-danger/40 text-cyber-danger rounded text-[9px] font-bold font-mono">
              {totalClassified}
            </span>
          )}
        </div>
        {isRunning && (
          <Wifi className="w-3.5 h-3.5 text-cyber-accent animate-pulse" />
        )}
      </div>

      {totalClassified === 0 ? (
        <div className="text-center text-xs font-mono text-slate-600 py-4 uppercase tracking-widest">
          No Matches Yet
        </div>
      ) : (
        <div className="grid grid-cols-3 md:grid-cols-4 gap-2">
          {CATEGORY_META.map((cat) => (
            <div
              key={cat.key}
              className={`bg-dark-bg border ${cat.border} rounded-lg p-2 flex flex-col items-center text-center transition-all hover:scale-[1.03] ${
                stats[cat.key] === 0 ? "opacity-30" : ""
              }`}
            >
              <span className="text-[9px] font-mono text-slate-500 uppercase tracking-widest mb-1">
                {cat.label}
              </span>
              <span className={`text-xl font-mono font-bold ${cat.color}`}>
                {stats[cat.key] > 0 ? stats[cat.key] : "0"}
              </span>
            </div>
          ))}
        </div>
      )}

      {nonZero.length > 0 && totalClassified > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {nonZero
            .sort((a, b) => stats[b.key] - stats[a.key])
            .slice(0, 5)
            .map((cat) => (
              <span
                key={cat.key}
                className={`px-1.5 py-0.5 border ${cat.border} rounded text-[9px] font-mono ${cat.color}`}
              >
                {cat.label}: {stats[cat.key]}
              </span>
            ))}
        </div>
      )}
    </div>
  );
};
