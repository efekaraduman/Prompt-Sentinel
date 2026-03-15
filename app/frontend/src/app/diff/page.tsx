"use client";

import { useState } from "react";
import { getCampaignDiff } from "../../../lib/api";
import type { CampaignDiff } from "../../../lib/types";

function DeltaBadge({ value }: { value: number }) {
  const sign = value > 0 ? "+" : "";
  const color =
    value > 0 ? "text-red-400" : value < 0 ? "text-emerald-400" : "text-neutral-400";
  return (
    <span className={`font-mono font-semibold tabular-nums ${color}`}>
      {sign}
      {value.toFixed(2)}
    </span>
  );
}

export default function DiffPage() {
  const [leftId, setLeftId] = useState<string>("");
  const [rightId, setRightId] = useState<string>("");
  const [data, setData] = useState<CampaignDiff | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCompare(e: React.FormEvent) {
    e.preventDefault();
    const l = parseInt(leftId, 10);
    const r = parseInt(rightId, 10);
    if (!l || !r) {
      setError("Both campaign IDs are required.");
      return;
    }
    setError(null);
    setData(null);
    setLoading(true);
    try {
      const apiKey = localStorage.getItem("apiKey") ?? undefined;
      const result = await getCampaignDiff(l, r, apiKey);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch diff.");
    } finally {
      setLoading(false);
    }
  }

  const categoryEntries: [string, number][] = data?.category_deltas
    ? (Object.entries(data.category_deltas)
        .filter(([, v]) => typeof v === "number") as [string, number][])
        .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
    : [];

  const maxAbs =
    categoryEntries.length > 0
      ? Math.max(...categoryEntries.map(([, v]) => Math.abs(v)), 1)
      : 1;

  return (
    <main className="mx-auto max-w-4xl space-y-8 px-6 py-10">
      <h1 className="text-xl font-semibold text-neutral-100">Campaign Diff</h1>

      <form onSubmit={handleCompare} className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <label className="text-xs font-medium uppercase tracking-[0.18em] text-neutral-400">
            Left Campaign ID
          </label>
          <input
            type="number"
            min={1}
            value={leftId}
            onChange={(e) => setLeftId(e.target.value)}
            placeholder="e.g. 1"
            className="w-32 rounded-lg border border-neutral-800 bg-neutral-950/80 px-3 py-2 text-sm text-neutral-100 outline-none transition-colors focus:border-neutral-400 focus:ring-1 focus:ring-neutral-500"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium uppercase tracking-[0.18em] text-neutral-400">
            Right Campaign ID
          </label>
          <input
            type="number"
            min={1}
            value={rightId}
            onChange={(e) => setRightId(e.target.value)}
            placeholder="e.g. 2"
            className="w-32 rounded-lg border border-neutral-800 bg-neutral-950/80 px-3 py-2 text-sm text-neutral-100 outline-none transition-colors focus:border-neutral-400 focus:ring-1 focus:ring-neutral-500"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center justify-center rounded-lg border border-indigo-500/70 bg-indigo-500/10 px-4 py-2 text-sm font-medium text-indigo-300 transition-colors hover:bg-indigo-500/20 hover:text-indigo-100 disabled:cursor-not-allowed disabled:border-neutral-700 disabled:bg-neutral-800 disabled:text-neutral-400"
        >
          {loading ? "Comparing…" : "Compare"}
        </button>
      </form>

      {error && (
        <div className="rounded-lg border border-red-800/70 bg-red-950/50 px-3 py-2 text-xs text-red-200">
          <span className="font-semibold">Error:</span> {error}
        </div>
      )}

      {loading && (
        <div className="flex items-center gap-2 text-xs text-neutral-400">
          <span className="h-2 w-2 animate-pulse rounded-full bg-indigo-400" />
          Fetching diff…
        </div>
      )}

      {data && !loading && (
        <div className="space-y-6">
          {/* Overall deltas */}
          <section className="space-y-3">
            <h2 className="text-xs font-medium uppercase tracking-[0.18em] text-neutral-500">
              Overall Deltas — Campaign #{data.left_id} → #{data.right_id}
            </h2>
            {data.avg_risk_delta == null && data.max_risk_delta == null ? (
              <p className="text-xs text-neutral-500">No overall delta data.</p>
            ) : (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {data.avg_risk_delta != null && (
                  <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4">
                    <p className="text-[11px] uppercase tracking-[0.18em] text-neutral-500">
                      Avg Risk Δ
                    </p>
                    <p className="mt-1 text-2xl">
                      <DeltaBadge value={data.avg_risk_delta} />
                    </p>
                  </div>
                )}
                {data.max_risk_delta != null && (
                  <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4">
                    <p className="text-[11px] uppercase tracking-[0.18em] text-neutral-500">
                      Max Risk Δ
                    </p>
                    <p className="mt-1 text-2xl">
                      <DeltaBadge value={data.max_risk_delta} />
                    </p>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Per-category deltas */}
          <section className="space-y-3">
            <h2 className="text-xs font-medium uppercase tracking-[0.18em] text-neutral-500">
              Category Deltas
            </h2>
            {categoryEntries.length === 0 ? (
              <p className="text-xs text-neutral-500">No category delta data.</p>
            ) : (
              <div className="space-y-2">
                {categoryEntries.map(([cat, delta]) => {
                  const pct = Math.round((Math.abs(delta) / maxAbs) * 100);
                  const barColor =
                    delta > 0
                      ? "bg-red-500"
                      : delta < 0
                      ? "bg-emerald-500"
                      : "bg-neutral-600";
                  const textColor =
                    delta > 0
                      ? "text-red-400"
                      : delta < 0
                      ? "text-emerald-400"
                      : "text-neutral-400";
                  const sign = delta > 0 ? "+" : "";
                  return (
                    <div key={cat} className="flex items-center gap-3">
                      <span className="w-36 shrink-0 truncate text-[11px] capitalize text-neutral-400">
                        {cat.replace(/_/g, " ")}
                      </span>
                      <div className="h-2 flex-1 overflow-hidden rounded-full bg-neutral-800">
                        <div
                          className={`h-full rounded-full ${barColor} transition-[width] duration-500`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span
                        className={`w-14 shrink-0 text-right text-[11px] tabular-nums ${textColor}`}
                      >
                        {sign}
                        {delta.toFixed(2)}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      )}
    </main>
  );
}
