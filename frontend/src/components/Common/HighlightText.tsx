import React from "react";

interface HighlightTextProps {
  text: string | number | null | undefined;
  highlight?: string;
  className?: string;
  matchClassName?: string;
}

/**
 * Escapes regex special characters in a string.
 */
export const escapeRegex = (str: string): string => {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
};

/**
 * Renders text with any case-insensitive matches to `highlight` wrapped in a styled <mark>.
 */
export const HighlightText: React.FC<HighlightTextProps> = ({
  text,
  highlight,
  className = "",
  matchClassName = "bg-amber-400/30 text-amber-200 font-bold px-0.5 rounded shadow-sm",
}) => {
  if (text === null || text === undefined) return null;
  const str = String(text);
  if (!highlight || !highlight.trim()) {
    return <span className={className}>{str}</span>;
  }

  const query = highlight.trim();
  const escaped = escapeRegex(query);

  try {
    const regex = new RegExp(`(${escaped})`, "gi");
    const parts = str.split(regex);

    return (
      <span className={className}>
        {parts.map((part, idx) => {
          if (part.toLowerCase() === query.toLowerCase()) {
            return (
              <mark key={idx} className={matchClassName}>
                {part}
              </mark>
            );
          }
          return part;
        })}
      </span>
    );
  } catch {
    return <span className={className}>{str}</span>;
  }
};

/**
 * Checks if a given string, array, or object value is an exact match for the query.
 * Exact match means exact equality (case-insensitive) or word-boundary match.
 */
export const checkValueExactMatch = (val: any, query: string): boolean => {
  if (val === null || val === undefined) return false;
  const q = query.trim().toLowerCase();
  if (!q) return false;

  if (typeof val === "number") {
    return String(val) === q;
  }

  if (typeof val === "string") {
    const s = val.trim().toLowerCase();
    if (s === q) return true;
    // Word boundary exact match (e.g. "nginx" in "server: nginx" or "403" in "HTTP 403")
    try {
      const wordRegex = new RegExp(`(^|[^a-zA-Z0-9_-])${escapeRegex(q)}($|[^a-zA-Z0-9_-])`, "i");
      return wordRegex.test(s);
    } catch {
      return s.includes(q);
    }
  }

  if (Array.isArray(val)) {
    return val.some((item) => checkValueExactMatch(item, q));
  }

  return false;
};

/**
 * Returns names of specific fields that have an exact match for the search query.
 */
export const getExactMatchFields = (record: Record<string, any>, query: string): string[] => {
  const q = query.trim().toLowerCase();
  if (!q || !record) return [];

  const matchedFields: string[] = [];

  // Check top-level domain / value / url / subdomain
  if (checkValueExactMatch(record.domain, q)) matchedFields.push("Domain");
  else if (checkValueExactMatch(record.value, q)) matchedFields.push("Value");
  else if (checkValueExactMatch(record.subdomain, q)) matchedFields.push("Subdomain");
  else if (checkValueExactMatch(record.url, q)) matchedFields.push("URL");
  else if (checkValueExactMatch(record.normalized_url, q)) matchedFields.push("Normalized URL");
  else if (checkValueExactMatch(record.job_id, q)) matchedFields.push("Job ID");

  // Check metadata
  const meta = record.metadata || {};
  if (checkValueExactMatch(meta.url, q)) matchedFields.push("URL");
  if (checkValueExactMatch(meta.ip_address, q) || checkValueExactMatch(meta.ip, q)) matchedFields.push("IP");
  if (checkValueExactMatch(record.ipv4, q) || checkValueExactMatch(record.ipv6, q)) matchedFields.push("IP");
  if (checkValueExactMatch(record.cname, q)) matchedFields.push("CNAME");

  // Check ports
  const openPorts = record.open_ports || meta.open_ports;
  if (openPorts && checkValueExactMatch(openPorts, q)) matchedFields.push("Port");

  // Check technologies
  const tech = meta.technologies;
  if (tech && checkValueExactMatch(tech, q)) matchedFields.push("Tech");

  // Check status codes
  const code = meta.status_code !== undefined ? meta.status_code : record.status_code;
  if (code !== undefined && checkValueExactMatch(code, q)) matchedFields.push("Status Code");

  // Check vulnerability fields
  if (checkValueExactMatch(record.template_id || record.template, q)) matchedFields.push("Template");
  if (checkValueExactMatch(record.severity, q)) matchedFields.push("Severity");
  if (checkValueExactMatch(record.cve, q)) matchedFields.push("CVE");

  // Check hunt reasons
  const reasons = record.hunt_reasons || (record.risk?.reasons);
  if (reasons && checkValueExactMatch(reasons, q)) matchedFields.push("Reason");

  // Check categories / provider
  if (record.categories && checkValueExactMatch(record.categories, q)) matchedFields.push("Category");
  if (record.provider && checkValueExactMatch(record.provider, q)) matchedFields.push("Provider");

  return Array.from(new Set(matchedFields));
};

interface ExactMatchBadgeProps {
  fields?: string[];
  label?: string;
  className?: string;
}

export const ExactMatchBadge: React.FC<ExactMatchBadgeProps> = ({
  fields = [],
  label,
  className = "",
}) => {
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm ${className}`}
      title={fields.length > 0 ? `Exact match in: ${fields.join(", ")}` : "Exact match present in result"}
    >
      <span>🎯 {label || "Exact Match"}</span>
      {fields.length > 0 && (
        <span className="text-amber-400/80 font-normal">({fields.slice(0, 2).join(", ")})</span>
      )}
    </span>
  );
};
