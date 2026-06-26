import React from "react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtext?: string;
  icon: React.ReactNode;
  colorClass?: string; // e.g. text-cyber-accent
  glowClass?: string; // e.g. glow-cyan
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtext,
  icon,
  colorClass = "text-cyber-primary",
  glowClass = "glow-blue"
}) => {
  return (
    <div className={`bg-dark-card border border-dark-border rounded-xl p-5 glass relative overflow-hidden flex items-center justify-between ${glowClass}`}>
      <div>
        <span className="text-xs font-mono text-slate-400 uppercase tracking-widest block mb-1">
          {title}
        </span>
        <span className="text-3xl font-extrabold tracking-tight text-white block">
          {value}
        </span>
        {subtext && (
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block mt-1.5">
            {subtext}
          </span>
        )}
      </div>
      <div className={`p-3 bg-dark-bg border border-dark-border rounded-lg ${colorClass}`}>
        {icon}
      </div>
    </div>
  );
};
