import React from "react";
import { Link2, Wifi } from "lucide-react";

interface UroStats {
  input_urls: number;
  normalised_urls: number;
  removed: number;
}

interface UroCardProps {
  stats: UroStats;
  isRunning?: boolean;
}

export const UroCard: React.FC<UroCardProps> = ({
  stats,
  isRunning = false,
}) => {
  const dedupeRatio =
    stats.input_urls > 0
      ? Math.round((stats.removed / stats.input_urls) * 100)
      : 0;

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
      <div className="flex items-center justify-between border-b border-dark-border pb-2 mb-4">
        <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <Link2 className="w-3.5 h-3.5 text-cyber-primary" />
          Normalized URLs
        </h4>
        {isRunning && (
          <Wifi className="w-3.5 h-3.5 text-cyber-accent animate-pulse" />
        )}
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="bg-dark-bg border border-dark-border rounded-lg p-3 flex flex-col items-center text-center">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
            Original
          </span>
          <span className="text-2xl font-mono font-bold text-slate-300">
            {stats.input_urls !== undefined && stats.input_urls !== null ? stats.input_urls : "-"}
          </span>
        </div>
        <div className="bg-cyber-primary/10 border border-cyber-primary/30 rounded-lg p-3 flex flex-col items-center text-center">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
            Normalized
          </span>
          <span className="text-2xl font-mono font-bold text-cyber-primary">
            {stats.normalised_urls !== undefined && stats.normalised_urls !== null ? stats.normalised_urls : "-"}
          </span>
        </div>
        <div className="bg-dark-bg border border-dark-border rounded-lg p-3 flex flex-col items-center text-center">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
            Removed
          </span>
          <span className="text-2xl font-mono font-bold text-slate-500">
            {stats.removed !== undefined && stats.removed !== null ? stats.removed : "-"}
          </span>
        </div>
      </div>

      {stats.input_urls > 0 && (
        <div className="mt-3 text-center text-[10px] font-mono text-slate-500">
          {dedupeRatio}% reduction in URL noise
        </div>
      )}
    </div>
  );
};
