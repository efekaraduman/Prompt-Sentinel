"use client";

import { useEffect, useState } from "react";
import { getTrustScore } from "../lib/api";
import type { TrustScoreResponse } from "../lib/types";

// ── helpers ───────────────────────────────────────────────────────────────────

const MATURITY_STYLES: Record<string, { badge: string; ring: string }> = {
  starter:    { badge: "bg-neutral-700/60 text-neutral-300",        ring: "text-neutral-400" },
  developing: { badge: "bg-amber-600/20 text-amber-400",            ring: "text-amber-400"  },
  advanced:   { badge: "bg-blue-600/20 text-blue-400",              ring: "text-blue-400"   },
  hardened:   { badge: "bg-emerald-600/20 text-emerald-400",        ring: "text-emerald-400"},
};

function DimBar({ label, value, invert = false }: { label: string; value: number; invert?: boolean }) {
  // For threat_pressure we show the bar reversed (red when high)
  const fillPct = Math.min(100, Math.max(0, value));
  const color = invert
    ? fillPct > 60 ? "bg-red-500" : fillPct > 30 ? "bg-amber-500" : "bg-emerald-500"
    : fillPct >= 70 ? "bg-emerald-500" : fillPct >= 40 ? "bg-amber-500" : "bg-red-500";

  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[11px] text-neutral-400">
        <span>{label}</span>
        <span className="tabular-nums font-mono">{value}</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-neutral-800">
        <div className={`h-1.5 rounded-full transition-all ${color}`} style={{ width: `${fillPct}%` }} />
      </div>
    </div>
  );
}

// ── component ─────────────────────────────────────────────────────────────────

export default function TrustScoreCard() {
  const [data, setData] = useState<TrustScoreResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const apiKey = typeof window !== "undefined" ? (localStorage.getItem("apiKey") ?? undefined) : undefined;

    getTrustScore(30, apiKey)
      .then((d) => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch((e) => { if (!cancelled) { setError(e instanceof Error ? e.message : "Failed"); setLoading(false); } });

    return () => { cancelled = true; };
  }, []);

  const styles = MATURITY_STYLES[data?.maturity_level ?? "starter"];

  return (
    <section className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-5 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <h2 className="text-sm font-medium uppercase tracking-[0.2em] text-neutral-400">
          Trust Score
        </h2>
        {data && (
          <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[11px] font-medium capitalize ${styles.badge}`}>
            {data.maturity_level}
          </span>
        )}
      </div>

      {loading && (
        <p className="mt-4 text-xs text-neutral-500">Loading…</p>
      )}
      {error && !loading && (
        <p className="mt-4 text-xs text-red-400">{error}</p>
      )}

      {data && !loading && (
        <>
          {/* Big score */}
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-5xl font-semibold tabular-nums ${styles.ring}`}>
              {data.trust_score}
            </span>
            <span className="text-sm text-neutral-500">/ 100</span>
          </div>

          {/* Dimension bars */}
          <div className="mt-4 space-y-2.5">
            <DimBar label="Protection coverage"  value={data.protection_coverage} />
            <DimBar label="Control maturity"     value={data.control_maturity} />
            <DimBar label="Threat pressure"      value={data.threat_pressure} invert />
            <DimBar label="Response readiness"   value={data.response_readiness} />
          </div>

          {/* Notes */}
          {data.notes.length > 0 && (
            <ul className="mt-4 space-y-1.5">
              {data.notes.slice(0, 3).map((note) => (
                <li key={note} className="flex items-start gap-1.5 text-[11px] text-neutral-400">
                  <span className="mt-px shrink-0 text-amber-500">›</span>
                  {note}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}
