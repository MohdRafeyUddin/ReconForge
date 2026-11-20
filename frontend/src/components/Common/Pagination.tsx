import React, { useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

export const PAGE_SIZE_OPTIONS = [10, 20, 50, 100];

interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  itemLabel?: string;
}

/**
 * Shared pagination footer used below every inventory table.
 * Defaults to 20 rows per page; the page size is user-selectable.
 */
export const Pagination: React.FC<PaginationProps> = ({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  itemLabel = "row(s)",
}) => {
  const safeSize = Math.max(1, pageSize);
  const totalPages = Math.max(1, Math.ceil(total / safeSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = total === 0 ? 0 : (safePage - 1) * safeSize + 1;
  const end = Math.min(safePage * safeSize, total);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-dark-border bg-dark-bg/40 font-mono text-[10px] text-slate-400">
      <span>
        Showing {start}–{end} of {total} {itemLabel}
      </span>
      <div className="flex flex-wrap items-center gap-2">
        <span className="uppercase tracking-wider">Rows per page</span>
        <select
          value={safeSize}
          onChange={(e) => onPageSizeChange(Number(e.target.value) || 20)}
          className="bg-dark-input border border-dark-border rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyber-accent"
          title="Rows per page"
        >
          {PAGE_SIZE_OPTIONS.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => onPageChange(safePage - 1)}
          disabled={safePage <= 1}
          className="flex items-center gap-0.5 px-2 py-1 rounded border border-dark-border bg-dark-input text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
        >
          <ChevronLeft className="w-3 h-3" /> Prev
        </button>
        <span className="px-1">
          Page {safePage} / {totalPages}
        </span>
        <button
          type="button"
          onClick={() => onPageChange(safePage + 1)}
          disabled={safePage >= totalPages}
          className="flex items-center gap-0.5 px-2 py-1 rounded border border-dark-border bg-dark-input text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
        >
          Next <ChevronRight className="w-3 h-3" />
        </button>
      </div>
    </div>
  );
};

/**
 * Pagination state helper. `resetKey` resets to page 1 when filters/search
 * change; the page is also clamped when the filtered list shrinks.
 */
export function usePagination<T>(
  items: T[],
  initialPageSize = 20,
  resetKey?: unknown
) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);

  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));

  useEffect(() => {
    setPage(1);
  }, [resetKey, pageSize]);

  useEffect(() => {
    setPage((current) => Math.min(Math.max(1, current), totalPages));
  }, [totalPages]);

  const safePage = Math.min(Math.max(1, page), totalPages);
  const pageStart = (safePage - 1) * pageSize;
  const pageItems = useMemo(
    () => items.slice(pageStart, pageStart + pageSize),
    [items, pageStart, pageSize]
  );

  return {
    page: safePage,
    setPage,
    pageSize,
    setPageSize,
    totalPages,
    pageItems,
    pageStart,
    total,
  };
}
