import type { FC } from "react";

export type RiskFilter = "all" | "high" | "medium" | "low";
export type SortOrder = "desc" | "asc";

interface FiltersProps {
  disabled?: boolean;
  filter: RiskFilter;
  onFilterChange: (value: RiskFilter) => void;
  search: string;
  onSearchChange: (value: string) => void;
  sortOrder: SortOrder;
  onSortOrderChange: (value: SortOrder) => void;
}

const riskOptions: { value: RiskFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const Filters: FC<FiltersProps> = ({
  disabled,
  filter,
  onFilterChange,
  search,
  onSearchChange,
  sortOrder,
  onSortOrderChange,
}) => {
  return (
    <section className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-4 md:p-5">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap gap-2">
          {riskOptions.map((option) => {
            const isActive = filter === option.value;
            return (
              <button
                key={option.value}
                type="button"
                disabled={disabled}
                onClick={() => onFilterChange(option.value)}
                className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                  isActive
                    ? "border-neutral-200 bg-neutral-50 text-neutral-950"
                    : "border-neutral-700 bg-neutral-900 text-neutral-300 hover:border-neutral-500"
                } ${disabled ? "opacity-60 cursor-not-allowed" : ""}`}
              >
                {option.label}
              </button>
            );
          })}
        </div>
        <div className="flex flex-1 flex-col gap-3 md:flex-row md:items-center md:justify-end">
          <div className="relative w-full max-w-xs">
            <input
              type="search"
              placeholder="Search attacks or responses..."
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
              disabled={disabled}
              className="w-full rounded-lg border border-neutral-800 bg-neutral-950/60 px-3 py-2 text-sm text-neutral-100 placeholder:text-neutral-500 focus:border-neutral-400 focus:outline-none focus:ring-1 focus:ring-neutral-500 disabled:cursor-not-allowed disabled:opacity-60"
            />
          </div>
          <button
            type="button"
            disabled={disabled}
            onClick={() => onSortOrderChange(sortOrder === "desc" ? "asc" : "desc")}
            className="inline-flex items-center justify-center rounded-lg border border-neutral-800 bg-neutral-950/80 px-3 py-2 text-xs font-medium text-neutral-200 shadow-sm transition-colors hover:border-neutral-500 hover:bg-neutral-900 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <span className="mr-1.5 text-[11px] uppercase tracking-[0.16em] text-neutral-400">
              Sort
            </span>
            <span className="font-mono text-[12px] text-neutral-100">
              risk {sortOrder === "desc" ? "▼" : "▲"}
            </span>
          </button>
        </div>
      </div>
    </section>
  );
};

export default Filters;

