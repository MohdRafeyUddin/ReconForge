import React from "react";
import { Server, Wifi } from "lucide-react";

interface DnsxStats {
  resolved: number;
  unique_ips: number;
  wildcard_filtered: number;
  nxdomain: number;
}

interface DnsxCardProps {
  stats: DnsxStats;
  isRunning?: boolean;
}

export const DnsxCard: React.FC<DnsxCardProps> = ({
  stats,
  isRunning = false,
}) => {
  const items = [
    {
      label: "Resolved Hosts",
      value: stats.resolved,
      color: "text-cyber-accent",
      border: "border-cyber-accent/30",
    },
    {
      label: "Unique IPs",
      value: stats.unique_ips,
      color: "text-cyber-primary",
      border: "border-cyber-primary/30",
    },
    {
      label: "Wildcard Filtered",
      value: stats.wildcard_filtered,
      color: "text-cyber-warning",
      border: "border-cyber-warning/30",
    },
    {
      label: "NXDOMAIN",
      value: stats.nxdomain,
      color: "text-cyber-danger",
      border: "border-cyber-danger/30",
    },
  ];

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-5 glass">
      <div className="flex items-center justify-between border-b border-dark-border pb-2 mb-4">
        <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <Server className="w-3.5 h-3.5 text-cyber-accent" />
          Resolved Hosts
        </h4>
        {isRunning && (
          <Wifi className="w-3.5 h-3.5 text-cyber-accent animate-pulse" />
        )}
      </div>
      <div className="grid grid-cols-2 gap-3">
        {items.map((item) => (
          <div
            key={item.label}
            className={`bg-dark-bg border ${item.border} rounded-lg p-3 flex flex-col items-center text-center transition-all hover:scale-[1.02]`}
          >
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1.5">
              {item.label}
            </span>
            <span className={`text-2xl font-mono font-bold ${item.color}`}>
              {item.value !== undefined && item.value !== null ? item.value : "-"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
