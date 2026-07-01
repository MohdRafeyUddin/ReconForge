import React from "react";
import { ShieldAlert, Wifi } from "lucide-react";

interface SubzyStats {
  vulnerable: number;
  not_vulnerable: number;
  unknown: number;
}

interface SubzyCardProps {
  stats: SubzyStats;
  isRunning?: boolean;
}

export const SubzyCard: React.FC<SubzyCardProps> = ({
  stats,
  isRunning = false,
}) => {
  const total = stats.vulnerable + stats.not_vulnerable + stats.unknown;

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
      <div className="flex items-center justify-between border-b border-dark-border pb-2 mb-4">
        <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 text-cyber-danger" />
          Subdomain Takeovers
        </h4>
        {isRunning && (
          <Wifi className="w-3.5 h-3.5 text-cyber-accent animate-pulse" />
        )}
      </div>

      <div className="grid grid-cols-3 gap-3 mb-3">
        <div className="bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg p-3 flex flex-col items-center text-center">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
            Vulnerable
          </span>
          <span className="text-2xl font-mono font-bold text-cyber-danger">
            {stats.vulnerable !== undefined && stats.vulnerable !== null ? stats.vulnerable : "-"}
          </span>
        </div>
        <div className="bg-cyber-success/10 border border-cyber-success/30 rounded-lg p-3 flex flex-col items-center text-center">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
            Safe
          </span>
          <span className="text-2xl font-mono font-bold text-cyber-success">
            {stats.not_vulnerable !== undefined && stats.not_vulnerable !== null ? stats.not_vulnerable : "-"}
          </span>
        </div>
        <div className="bg-cyber-warning/10 border border-cyber-warning/30 rounded-lg p-3 flex flex-col items-center text-center">
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
            Unknown
          </span>
          <span className="text-2xl font-mono font-bold text-cyber-warning">
            {stats.unknown !== undefined && stats.unknown !== null ? stats.unknown : "-"}
          </span>
        </div>
      </div>

      {total > 0 && (
        <div className="mt-2">
          <div className="flex h-1.5 rounded-full overflow-hidden gap-px">
            {stats.vulnerable > 0 && (
              <div
                className="bg-cyber-danger"
                style={{ width: `${(stats.vulnerable / total) * 100}%` }}
              />
            )}
            {stats.not_vulnerable > 0 && (
              <div
                className="bg-cyber-success"
                style={{ width: `${(stats.not_vulnerable / total) * 100}%` }}
              />
            )}
            {stats.unknown > 0 && (
              <div
                className="bg-cyber-warning"
                style={{ width: `${(stats.unknown / total) * 100}%` }}
              />
            )}
          </div>
          <div className="text-[9px] font-mono text-slate-600 mt-1 text-center">
            {total} total checked
          </div>
        </div>
      )}
    </div>
  );
};
