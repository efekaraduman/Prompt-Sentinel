"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { createCheckoutSession, createPortalSession, getAnomalies, getDashboardSummary, getGuardAnalytics, getGuardTrend, getGuardHistory, getMe, getMeUsage, getPerformanceAnalytics, getRecentCampaigns, getRiskTrend, getScorecard, getTopThreats, getUsageStatus, getUsageSummary, replayGuardScan, safeExternalRedirect } from "../../../lib/api";
import type { AnomalyAlertItem, DailyCountPoint, DashboardSummary, GuardAnalyticsResponse, GuardHistoryItem, GuardReplayResponse, MeResponse, MeUsageResponse, PerformanceAnalyticsResponse, RecentCampaignItem, RiskTrendItem, SecurityScorecardResponse, ThreatSignatureItem, ThreatTrendResponse, UsageStatus, UsageSummary } from "../../../lib/types";

function UpgradeButton() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [alreadyPro, setAlreadyPro] = useState(false);

  async function handleUpgrade() {
    setError(null);
    setAlreadyPro(false);
    const apiKey = localStorage.getItem("apiKey") ?? undefined;
    if (!apiKey) {
      setError("API key required");
      return;
    }
    setLoading(true);
    try {
      const { checkout_url } = await createCheckoutSession(apiKey);
      safeExternalRedirect(checkout_url);
    } catch (e) {
      const raw = e instanceof Error ? e.message : "Checkout failed";
      const isAlreadyPro =
        raw === "already_pro" ||
        raw.toLowerCase().includes("already has an active pro") ||
        raw.toLowerCase().includes("already subscribed");
      const isBillingOff =
        raw.toLowerCase().includes("not configured") ||
        raw.toLowerCase().includes("not available") ||
        raw.toLowerCase().includes("not installed");
      if (isAlreadyPro) {
        setAlreadyPro(true);
      } else if (isBillingOff) {
        setError("Billing is not available on this server.");
      } else {
        setError(raw);
      }
      setLoading(false);
    }
  }

  if (alreadyPro) {
    return (
      <p className="text-[11px] text-emerald-400">You're already on Pro 🎉</p>
    );
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <button
        onClick={handleUpgrade}
        disabled={loading}
        className="rounded-lg bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? "Redirecting…" : "Upgrade to Pro"}
      </button>
      {error && (
        <p className="text-[11px] text-red-400">{error}</p>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl border border-neutral-800 bg-neutral-900 p-6">
      <p className="text-xs font-medium uppercase tracking-wide text-neutral-500">{label}</p>
      <p className="mt-2 text-3xl font-bold text-neutral-100">{value}</p>
    </div>
  );
}

function BarRow({
  label,
  value,
  max,
  colorClass,
}: {
  label: string;
  value: number;
  max: number;
  colorClass: string;
}) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="flex items-center gap-4">
      <span className="w-24 shrink-0 text-sm text-neutral-400">{label}</span>
      <div className="h-3 flex-1 overflow-hidden rounded-full bg-neutral-800">
        <div
          className={`h-full rounded-full ${colorClass} transition-[width] duration-700`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-10 shrink-0 text-right text-sm tabular-nums text-neutral-300">
        {value}
      </span>
    </div>
  );
}

function UsageRow({
  label,
  used,
  limit,
  remaining,
}: {
  label: string;
  used: number;
  limit: number;
  remaining: number;
}) {
  const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-neutral-400">{label}</span>
        <span className="tabular-nums text-neutral-500">
          {used.toLocaleString()}&thinsp;/&thinsp;{limit.toLocaleString()}
          <span className="ml-2 text-neutral-300">{remaining.toLocaleString()} left</span>
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-neutral-800">
        <div
          className="h-full rounded-full bg-indigo-500 transition-[width] duration-700"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function UsageStatusRow({
  label,
  used,
  limit,
  remaining,
  pctUsed,
}: {
  label: string;
  used: number;
  limit: number | null;
  remaining: number | null;
  pctUsed: number | null;
}) {
  const pct = pctUsed !== null ? Math.min(100, Math.round(pctUsed * 100)) : 0;
  const barColor =
    pctUsed !== null && pctUsed >= 1
      ? "bg-red-500"
      : pctUsed !== null && pctUsed >= 0.8
      ? "bg-yellow-500"
      : "bg-indigo-500";
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-neutral-400">{label}</span>
        <span className="tabular-nums text-neutral-500">
          {used.toLocaleString()}&thinsp;/&thinsp;
          {limit !== null ? limit.toLocaleString() : "∞"}
          {remaining !== null ? (
            <span className={`ml-2 ${remaining === 0 ? "text-red-400 font-medium" : "text-neutral-300"}`}>
              {remaining.toLocaleString()} left
            </span>
          ) : (
            <span className="ml-2 text-emerald-400">unlimited</span>
          )}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-neutral-800">
        <div
          className={`h-full rounded-full ${barColor} transition-[width] duration-700`}
          style={{ width: pctUsed !== null ? `${pct}%` : "0%" }}
        />
      </div>
    </div>
  );
}

const CATEGORY_COLORS: Record<string, string> = {
  injection: "bg-red-500/15 text-red-400",
  jailbreak: "bg-orange-500/15 text-orange-400",
  exfiltration: "bg-yellow-500/15 text-yellow-400",
  override: "bg-purple-500/15 text-purple-400",
  unknown: "bg-neutral-700/40 text-neutral-400",
};

function CategoryBadge({ category }: { category: string | null }) {
  const key = (category ?? "unknown").toLowerCase();
  const cls = CATEGORY_COLORS[key] ?? "bg-neutral-700/40 text-neutral-400";
  return (
    <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium capitalize ${cls}`}>
      {category ?? "unknown"}
    </span>
  );
}

const STATUS_COLORS: Record<string, string> = {
  running: "bg-indigo-500/15 text-indigo-400",
  completed: "bg-emerald-500/15 text-emerald-400",
  failed: "bg-red-500/15 text-red-400",
  queued: "bg-neutral-700/40 text-neutral-400",
  stopped: "bg-neutral-700/40 text-neutral-500",
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_COLORS[status] ?? "bg-neutral-700/40 text-neutral-400";
  return (
    <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium capitalize ${cls}`}>
      {status}
    </span>
  );
}

function FreeLimit({ onUpgrade }: { onUpgrade: () => Promise<void> }) {
  const [loading, setLoading] = useState(false);
  return (
    <div className="flex items-center justify-between gap-4 rounded-xl border border-indigo-700/40 bg-indigo-950/30 px-5 py-4">
      <p className="text-sm text-indigo-300">
        <span className="font-semibold">You&rsquo;re at your free limit.</span>{" "}
        <span className="text-indigo-400">Upgrade to Pro for 20 000 scans and campaigns per month.</span>
      </p>
      <button
        onClick={async () => { setLoading(true); await onUpgrade(); setLoading(false); }}
        disabled={loading}
        className="shrink-0 rounded-lg bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-indigo-500 disabled:opacity-50"
      >
        {loading ? "Redirecting…" : "Upgrade"}
      </button>
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [recent, setRecent] = useState<RecentCampaignItem[]>([]);
  const [threats, setThreats] = useState<ThreatSignatureItem[]>([]);
  const [threatsUnavailable, setThreatsUnavailable] = useState(false);
  const [trend, setTrend] = useState<RiskTrendItem[]>([]);
  const [trendUnavailable, setTrendUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [plan, setPlan] = useState<string | null>(null);
  const [meData, setMeData] = useState<MeResponse | null>(null);
  const [planRefreshing, setPlanRefreshing] = useState(false);
  const [usage, setUsage] = useState<MeUsageResponse | null>(null);
  const [usageUnavailable, setUsageUnavailable] = useState(false);
  const [usageStatus, setUsageStatus] = useState<UsageStatus | null>(null);
  const [usageStatusUnavailable, setUsageStatusUnavailable] = useState(false);
  const [usageSummary, setUsageSummary] = useState<UsageSummary | null>(null);
  const [guardAnalytics, setGuardAnalytics] = useState<GuardAnalyticsResponse | null>(null);
  const [guardAnalyticsUnavailable, setGuardAnalyticsUnavailable] = useState(false);
  const [guardTrend, setGuardTrend] = useState<ThreatTrendResponse | null>(null);
  const [guardTrendUnavailable, setGuardTrendUnavailable] = useState(false);
  const [anomalies, setAnomalies] = useState<AnomalyAlertItem[]>([]);
  const [guardHistory, setGuardHistory] = useState<GuardHistoryItem[]>([]);
  const [perfAnalytics, setPerfAnalytics] = useState<PerformanceAnalyticsResponse | null>(null); // PHASE 2.22
  const [scorecard, setScorecard] = useState<SecurityScorecardResponse | null>(null); // PHASE 2.29
  const [replayResults, setReplayResults] = useState<Record<number, GuardReplayResponse | "loading" | "error">>({});
  const [hasApiKey, setHasApiKey] = useState(process.env.NEXT_PUBLIC_DEMO_MODE === "1");
  const [portalLoading, setPortalLoading] = useState(false);
  const [portalError, setPortalError] = useState<string | null>(null);
  const [billingBanner, setBillingBanner] = useState<"success" | "cancel" | null>(null);

  async function handleManageBilling() {
    setPortalError(null);
    const apiKey = localStorage.getItem("apiKey") ?? undefined;
    if (!apiKey) return;
    setPortalLoading(true);
    try {
      const { url } = await createPortalSession(apiKey);
      safeExternalRedirect(url);
    } catch (e) {
      const raw = e instanceof Error ? e.message : "";
      if (raw.toLowerCase().includes("not configured") || raw.toLowerCase().includes("not available") || raw.toLowerCase().includes("not installed")) {
        setPortalError("Billing is not available on this server.");
      } else if (raw.toLowerCase().includes("no billing account") || raw.toLowerCase().includes("no stripe customer")) {
        setPortalError("No billing account found — upgrade to Pro to enable billing management.");
      } else {
        setPortalError(raw || "Billing portal unavailable.");
      }
      setPortalLoading(false);
    }
  }

  async function handleReplay(scanId: number) {
    const apiKey = localStorage.getItem("apiKey") ?? undefined;
    setReplayResults(prev => ({ ...prev, [scanId]: "loading" }));
    try {
      const result = await replayGuardScan(scanId, apiKey);
      setReplayResults(prev => ({ ...prev, [scanId]: result }));
    } catch {
      setReplayResults(prev => ({ ...prev, [scanId]: "error" }));
    }
  }

  async function refreshPlan() {
    const apiKey = localStorage.getItem("apiKey") ?? undefined;
    if (!apiKey) return;
    setPlanRefreshing(true);
    try {
      const me = await getMe(apiKey);
      setPlan(me.plan);
      setMeData(me);
    } catch {
      // silently ignore
    } finally {
      setPlanRefreshing(false);
    }
  }

  useEffect(() => {
    const billing = new URLSearchParams(window.location.search).get("billing");
    if (billing === "success" || billing === "cancel") setBillingBanner(billing);

    // On billing=success fire an extra getMe immediately so the banner reflects
    // the webhook-updated plan as soon as it has been processed.
    if (billing === "success") {
      const key = localStorage.getItem("apiKey");
      if (key) {
        getMe(key).then((me) => {
          setPlan(me.plan);
          setMeData(me);
        }).catch(() => { /* ignore; main fetch below will still run */ });
      }
    }

    const apiKey = localStorage.getItem("apiKey") ?? undefined;
    // In demo mode, bypass the "not logged in" gate so public visitors
    // can see the seeded dashboard data without any credentials.
    const isDemoMode = process.env.NEXT_PUBLIC_DEMO_MODE === "1";
    setHasApiKey(!!apiKey || isDemoMode);
    const safeThreats = getTopThreats(5, apiKey).catch(() => null);
    const safeTrend = getRiskTrend(10, apiKey).catch(() => null);
    const safeMe = getMe(apiKey).catch(() => null);
    const safeUsage = apiKey ? getMeUsage(apiKey).catch(() => null) : Promise.resolve(null);
    const safeGuardAnalytics = apiKey ? getGuardAnalytics(apiKey).catch(() => null) : Promise.resolve(null);
    const safeUsageStatus = apiKey ? getUsageStatus(apiKey).catch(() => null) : Promise.resolve(null);
    const safeGuardTrend = apiKey ? getGuardTrend(7, apiKey).catch(() => null) : Promise.resolve(null);
    const safeAnomalies = apiKey ? getAnomalies(30, apiKey).catch(() => null) : Promise.resolve(null);
    if (apiKey) getUsageSummary(apiKey).then(setUsageSummary).catch(() => {});
    if (apiKey) getGuardHistory(20, apiKey).then(setGuardHistory).catch(() => {});
    if (apiKey) getPerformanceAnalytics(7, apiKey).then(setPerfAnalytics).catch(() => {}); // PHASE 2.22
    if (apiKey) getScorecard(30, apiKey).then(setScorecard).catch(() => {}); // PHASE 2.29
    Promise.all([getDashboardSummary(apiKey), getRecentCampaigns(10, apiKey), safeThreats, safeTrend, safeMe, safeUsage, safeGuardAnalytics, safeUsageStatus, safeGuardTrend, safeAnomalies])
      .then(([summary, recentList, threatsList, trendList, me, usageData, analyticsData, usageStatusData, guardTrendData, anomalyData]) => {
        setData(summary);
        setRecent(recentList);
        if (threatsList !== null) {
          setThreats(threatsList);
        } else {
          setThreatsUnavailable(true);
        }
        if (trendList !== null) {
          setTrend(trendList);
        } else {
          setTrendUnavailable(true);
        }
        if (me !== null) {
          setPlan(me.plan);
          setMeData(me);
        }
        if (usageData !== null) {
          setUsage(usageData);
        } else if (apiKey) {
          setUsageUnavailable(true);
        }
        if (analyticsData !== null) {
          setGuardAnalytics(analyticsData);
        } else if (apiKey) {
          setGuardAnalyticsUnavailable(true);
        }
        if (usageStatusData !== null) {
          setUsageStatus(usageStatusData);
        } else if (apiKey) {
          setUsageStatusUnavailable(true);
        }
        if (guardTrendData !== null) {
          setGuardTrend(guardTrendData);
        } else if (apiKey) {
          setGuardTrendUnavailable(true);
        }
        if (anomalyData !== null) setAnomalies(anomalyData.alerts ?? []);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load dashboard");
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <main className="flex min-h-[60vh] items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-neutral-700 border-t-indigo-500" />
      </main>
    );
  }

  if (error) {
    return (
      <main className="flex min-h-[60vh] flex-col items-center justify-center gap-3">
        <p className="text-sm text-red-400">{error}</p>
        <button
          onClick={() => window.location.reload()}
          className="rounded-lg border border-neutral-700 px-4 py-2 text-sm text-neutral-300 transition-colors hover:border-neutral-500"
        >
          Retry
        </button>
      </main>
    );
  }

  if (!hasApiKey) {
    return (
      <main className="flex min-h-[60vh] items-center justify-center">
        <div className="rounded-xl border border-neutral-800 bg-neutral-900 px-8 py-10 text-center space-y-4">
          <p className="text-sm text-neutral-300 font-medium">You are not logged in</p>
          <p className="text-xs text-neutral-500">Sign in to view your dashboard.</p>
          <button
            onClick={() => router.push("/login")}
            className="rounded-lg bg-blue-600 hover:bg-blue-500 px-5 py-2 text-sm font-medium text-white transition-colors"
          >
            Go to Login
          </button>
        </div>
      </main>
    );
  }

  const barMax = Math.max(data?.running ?? 0, data?.completed ?? 0, data?.failed ?? 0, 1);

  return (
    <main className="mx-auto max-w-4xl space-y-10 px-6 py-10">
      {/* Billing result banners */}
      {billingBanner === "success" && (
        <div className="flex items-center justify-between gap-4 rounded-lg border border-emerald-700/50 bg-emerald-950/30 px-4 py-3 text-sm">
          <p className="text-emerald-400">
            {plan === "pro" ? "🎉 Pro active ✅" : "⏳ Upgrade received, syncing…"}
          </p>
          <button
            onClick={() => setBillingBanner(null)}
            className="text-xs text-neutral-500 hover:text-neutral-300 transition-colors"
          >
            Dismiss
          </button>
        </div>
      )}
      {billingBanner === "cancel" && (
        <div className="flex items-center justify-between gap-4 rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-3 text-sm">
          <p className="text-neutral-400">Checkout was cancelled — no charge was made.</p>
          <button
            onClick={() => setBillingBanner(null)}
            className="text-xs text-neutral-500 hover:text-neutral-300 transition-colors"
          >
            Dismiss
          </button>
        </div>
      )}
      {/* Upgrade banner — shown when plan != pro and near/at limit */}
      {usageStatus !== null && usageStatus.plan !== "pro" && (() => {
        const exceeded =
          usageStatus.remaining.guard_scans === 0 ||
          usageStatus.remaining.campaigns_started === 0;
        const nearLimit =
          !exceeded && (
            (usageStatus.pct_used.guard_scans !== null && usageStatus.pct_used.guard_scans >= 0.8) ||
            (usageStatus.pct_used.campaigns_started !== null && usageStatus.pct_used.campaigns_started >= 0.8)
          );
        if (!exceeded && !nearLimit) return null;
        return exceeded ? (
          <div className="flex items-center justify-between gap-4 rounded-xl border border-red-700/40 bg-red-950/30 px-5 py-4">
            <p className="text-sm text-red-300">
              <span className="font-semibold">Limit reached</span>{" "}
              <span className="text-red-400/80">— upgrade to continue.</span>
            </p>
            <a
              href="/pricing"
              className="shrink-0 rounded-lg bg-red-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-red-500"
            >
              Upgrade now
            </a>
          </div>
        ) : (
          <div className="flex items-center justify-between gap-4 rounded-xl border border-yellow-700/40 bg-yellow-950/20 px-5 py-4">
            <p className="text-sm text-yellow-300">
              <span className="font-semibold">Approaching your monthly limit.</span>{" "}
              <span className="text-yellow-400/80">Upgrade to Pro before you run out.</span>
            </p>
            <a
              href="/pricing"
              className="shrink-0 rounded-lg bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white transition-colors hover:bg-indigo-500"
            >
              Upgrade to Pro
            </a>
          </div>
        );
      })()}

      {/* Security Alerts — PHASE 2.17 */}
      {(() => {
        const hasCritical = anomalies.some(a => a.severity === "critical");
        return (
          <section className={`rounded-xl border p-5 ${hasCritical ? "border-red-700/50 bg-red-950/20" : "border-neutral-800 bg-neutral-900"}`}>
            <h2 className="mb-3 text-xs font-medium uppercase tracking-wide text-neutral-500">Security Alerts</h2>
            {anomalies.length === 0 ? (
              <p className="text-xs text-neutral-600">No active anomalies</p>
            ) : (
              <ul className="space-y-2">
                {anomalies.map((alert) => (
                  <li key={`${alert.metric}-${alert.day}`} className="flex items-start gap-3">
                    <span className={`mt-0.5 shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${
                      alert.severity === "critical" ? "bg-red-500/15 text-red-400" :
                      alert.severity === "high"     ? "bg-orange-500/15 text-orange-400" :
                      alert.severity === "medium"   ? "bg-yellow-500/15 text-yellow-400" :
                                                      "bg-neutral-700/40 text-neutral-400"
                    }`}>
                      {alert.severity}
                    </span>
                    <div className="min-w-0">
                      <span className="text-sm text-neutral-300">{alert.metric}</span>
                      <span className="ml-2 tabular-nums text-xs text-neutral-500">z={alert.z_score.toFixed(2)}</span>
                      <p className="text-[11px] text-neutral-500">{alert.metric} spiked on {alert.day}</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        );
      })()}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold text-neutral-100">Dashboard</h1>
          {plan !== null && (
            <span
              className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                plan === "pro"
                  ? "bg-emerald-500/15 text-emerald-400"
                  : "bg-neutral-700/40 text-neutral-400"
              }`}
            >
              {plan === "pro" ? "Pro" : "Free"}
            </span>
          )}
        </div>
        <div className="flex flex-col items-end gap-1">
          <div className="flex items-center gap-2">
            <button
              onClick={refreshPlan}
              disabled={planRefreshing}
              className="rounded-lg border border-neutral-700 px-3 py-1.5 text-xs text-neutral-400 transition-colors hover:border-neutral-500 disabled:opacity-50"
            >
              {planRefreshing ? "Refreshing…" : "Refresh plan"}
            </button>
            {hasApiKey && plan === "pro" && (
              <button
                onClick={handleManageBilling}
                disabled={portalLoading}
                className="rounded-lg border border-neutral-700 px-3 py-1.5 text-xs text-neutral-400 transition-colors hover:border-neutral-500 disabled:opacity-50"
              >
                {portalLoading ? "Opening…" : "Manage billing"}
              </button>
            )}
            {plan !== "pro" && <UpgradeButton />}
          </div>
          {portalError && (
            <p className="text-[11px] text-red-400">{portalError}</p>
          )}
        </div>
      </div>

      {/* Plan / limits badge row */}
      {meData !== null && (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg border border-neutral-800 bg-neutral-900/50 px-4 py-2.5 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-neutral-500">Plan</span>
            <span
              className={`rounded-full px-2 py-0.5 font-medium ${
                meData.plan === "pro"
                  ? "bg-emerald-500/15 text-emerald-400"
                  : meData.plan === "free"
                  ? "bg-indigo-500/15 text-indigo-400"
                  : "bg-neutral-700/40 text-neutral-500"
              }`}
            >
              {meData.plan === "pro" ? "Pro" : meData.plan === "free" ? "Free" : "Public"}
            </span>
          </div>
          <span className="text-neutral-700">·</span>
          <div className="flex items-center gap-1.5">
            <span className="text-neutral-500">Max iterations</span>
            <span className="tabular-nums text-neutral-300">{meData.max_iterations.toLocaleString()}</span>
          </div>
          <span className="text-neutral-700">·</span>
          <div className="flex items-center gap-1.5">
            <span className="text-neutral-500">Export</span>
            <span className={meData.allow_export ? "text-emerald-400" : "text-neutral-600"}>
              {meData.allow_export ? "On" : "Off"}
            </span>
          </div>
        </div>
      )}

      {/* Plan & Usage */}
      <section className="rounded-xl border border-neutral-800 bg-neutral-900 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">Plan &amp; Usage</h2>
          {usageStatus && (
            <span className="font-mono text-[11px] text-neutral-600">
              {usageSummary
                ? `${usageSummary.period_start} → ${usageSummary.period_end}`
                : usageStatus.period}
            </span>
          )}
        </div>
        {!hasApiKey ? (
          <p className="text-xs text-neutral-500">Set API key to see usage.</p>
        ) : usageStatusUnavailable ? (
          <p className="text-xs text-neutral-600">Usage unavailable.</p>
        ) : usageStatus ? (
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <span className="text-xs text-neutral-500">Plan</span>
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                  usageStatus.plan === "pro"
                    ? "bg-emerald-500/15 text-emerald-400"
                    : "bg-indigo-500/15 text-indigo-400"
                }`}
              >
                {usageStatus.plan === "pro" ? "Pro" : "Free"}
              </span>
            </div>
            <UsageStatusRow
              label="Guard scans"
              used={usageStatus.guard_scans}
              limit={usageStatus.limits.guard_scans}
              remaining={usageStatus.remaining.guard_scans}
              pctUsed={usageStatus.pct_used.guard_scans}
            />
            <UsageStatusRow
              label="Campaigns started"
              used={usageStatus.campaigns_started}
              limit={usageStatus.limits.campaigns_started}
              remaining={usageStatus.remaining.campaigns_started}
              pctUsed={usageStatus.pct_used.campaigns_started}
            />
          </div>
        ) : (
          <p className="text-xs text-neutral-600">Loading…</p>
        )}
      </section>

      {/* Guard Analytics */}
      <section className="rounded-xl border border-neutral-800 bg-neutral-900 p-5">
        <h2 className="mb-4 text-xs font-medium uppercase tracking-wide text-neutral-500">
          Guard Analytics
        </h2>
        {!hasApiKey ? (
          <p className="text-xs text-neutral-500">Set API key to see analytics.</p>
        ) : guardAnalyticsUnavailable ? (
          <p className="text-xs text-neutral-600">Analytics unavailable.</p>
        ) : guardAnalytics ? (
          <div className="flex flex-wrap gap-x-8 gap-y-4">
            {/* Counters */}
            <div className="flex gap-6">
              <div>
                <p className="text-[11px] text-neutral-500">Total</p>
                <p className="mt-0.5 text-2xl font-bold tabular-nums text-neutral-100">
                  {guardAnalytics.total_scans}
                </p>
              </div>
              <div>
                <p className="text-[11px] text-neutral-500">Blocks</p>
                <p className="mt-0.5 text-2xl font-bold tabular-nums text-red-400">
                  {guardAnalytics.blocks}
                </p>
              </div>
              <div>
                <p className="text-[11px] text-neutral-500">Warns</p>
                <p className="mt-0.5 text-2xl font-bold tabular-nums text-yellow-400">
                  {guardAnalytics.warns}
                </p>
              </div>
              <div>
                <p className="text-[11px] text-neutral-500">Avg latency</p>
                <p className="mt-0.5 text-2xl font-bold tabular-nums text-neutral-100">
                  {Math.round(guardAnalytics.avg_latency_ms)}
                  <span className="ml-1 text-sm font-normal text-neutral-500">ms</span>
                </p>
              </div>
            </div>
            {/* Top categories */}
            {Object.keys(guardAnalytics.top_category_counts).length > 0 && (
              <div className="min-w-0">
                <p className="mb-1.5 text-[11px] text-neutral-500">Top categories</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(guardAnalytics.top_category_counts)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 3)
                    .map(([cat, count]) => (
                      <span
                        key={cat}
                        className="rounded-full bg-neutral-800 px-2.5 py-0.5 text-[11px] font-medium text-neutral-300"
                      >
                        {cat}&nbsp;
                        <span className="text-neutral-500">{count}</span>
                      </span>
                    ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="text-xs text-neutral-600">Loading…</p>
        )}
      </section>

      {/* Guard Trend (7d) */}
      <section className="rounded-xl border border-neutral-800 bg-neutral-900 p-5">
        <h2 className="mb-4 text-xs font-medium uppercase tracking-wide text-neutral-500">
          Guard Trend <span className="normal-case">(7d)</span>
        </h2>
        {!hasApiKey ? (
          <p className="text-xs text-neutral-500">Set API key to see trend.</p>
        ) : guardTrendUnavailable ? (
          <p className="text-xs text-neutral-600">Trend unavailable.</p>
        ) : guardTrend ? (
          (() => {
            const maxTotal = guardTrend.points.length > 0
              ? Math.max(...guardTrend.points.map((p: DailyCountPoint) => p.total), 1)
              : 1;
            return (
              <>
                <div className="flex items-end gap-1.5" style={{ height: "80px" }}>
                  {guardTrend.points.map((pt: DailyCountPoint) => {
                    const heightPct = Math.round((pt.total / maxTotal) * 100);
                    const blockedPct = pt.total > 0 ? Math.round((pt.blocked / pt.total) * 100) : 0;
                    return (
                      <div
                        key={pt.day}
                        className="flex-1 flex flex-col items-center gap-1"
                        title={`${pt.day}: ${pt.total} total, ${pt.blocked} blocked`}
                      >
                        <div className="relative w-full" style={{ height: "64px" }}>
                          <div
                            className="absolute bottom-0 left-0 right-0 rounded-sm overflow-hidden bg-indigo-900/40"
                            style={{ height: `${Math.max(heightPct, 2)}%` }}
                          >
                            {blockedPct > 0 && (
                              <div
                                className="absolute top-0 left-0 right-0 bg-red-500/60"
                                style={{ height: `${blockedPct}%` }}
                              />
                            )}
                          </div>
                        </div>
                        <span className="text-[9px] tabular-nums text-neutral-600">
                          {pt.day.slice(5)}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <div className="mt-3 flex items-center gap-4 text-[10px] text-neutral-600">
                  <span className="flex items-center gap-1.5">
                    <span className="inline-block h-2 w-2 rounded-sm bg-indigo-900/40" />
                    Total
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="inline-block h-2 w-2 rounded-sm bg-red-500/60" />
                    Blocked
                  </span>
                </div>
              </>
            );
          })()
        ) : (
          <p className="text-xs text-neutral-600">Loading…</p>
        )}
      </section>

      {/* Free-limit upgrade CTA — kept for fallback when usageStatus unavailable */}
      {usageStatus === null && usage !== null && plan !== "pro" &&
        (usage.guard_scans_remaining === 0 || usage.campaign_iterations_remaining === 0) && (
        <FreeLimit onUpgrade={async () => {
          const apiKey = localStorage.getItem("apiKey") ?? undefined;
          if (!apiKey) return;
          try {
            const { checkout_url } = await createCheckoutSession(apiKey);
            safeExternalRedirect(checkout_url);
          } catch { /* ignore */ }
        }} />
      )}

      {/* Number cards */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Total Campaigns" value={data?.total_campaigns ?? 0} />
        <StatCard label="Total Users" value={data?.total_users ?? 0} />
        <StatCard
          label="Avg Risk Global"
          value={`${((data?.avg_risk_global ?? 0) * 100).toFixed(1)}%`}
        />
      </section>

      {/* Campaign status bar chart */}
      <section className="space-y-4 rounded-xl border border-neutral-800 bg-neutral-900 p-6">
        <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">
          Campaign Status
        </h2>
        <div className="space-y-3">
          <BarRow label="Running" value={data?.running ?? 0} max={barMax} colorClass="bg-indigo-500" />
          <BarRow label="Completed" value={data?.completed ?? 0} max={barMax} colorClass="bg-emerald-500" />
          <BarRow label="Failed" value={data?.failed ?? 0} max={barMax} colorClass="bg-red-500" />
        </div>
      </section>

      {/* Risk Trend */}
      <section className="space-y-3">
        <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">
          Risk Trend
        </h2>
        {trendUnavailable ? (
          <p className="text-sm text-neutral-600">Trend unavailable.</p>
        ) : trend.length === 0 ? (
          <p className="text-sm text-neutral-500">No completed campaigns yet.</p>
        ) : (() => {
          const maxAvg = Math.max(...trend.map((t) => t.avg_risk), 0.001);
          return (
            <div className="space-y-2 rounded-xl border border-neutral-800 bg-neutral-900 p-4">
              {trend.map((t) => {
                const pct = Math.round((t.avg_risk / maxAvg) * 100);
                return (
                  <div key={t.campaign_id} className="flex items-center gap-3">
                    <span className="w-16 shrink-0 font-mono text-xs text-neutral-400">
                      #{t.campaign_id}
                    </span>
                    <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-neutral-800">
                      <div
                        className="h-full rounded-full bg-indigo-500 transition-[width] duration-700"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="w-20 shrink-0 text-right text-xs tabular-nums text-neutral-300">
                      avg {t.avg_risk.toFixed(1)} / max {t.max_risk}
                    </span>
                    <span className="w-24 shrink-0 text-right text-xs text-neutral-600">
                      {new Date(t.created_at).toLocaleDateString()}
                    </span>
                  </div>
                );
              })}
            </div>
          );
        })()}
      </section>

      {/* Scan History with Replay — PHASE 2.19 */}
      <section className="space-y-3">
        <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">Scan History</h2>
        {!hasApiKey ? (
          <p className="text-xs text-neutral-500">Set API key to see scan history.</p>
        ) : guardHistory.length === 0 ? (
          <p className="text-sm text-neutral-500">No scan history yet.</p>
        ) : (
          <div className="overflow-hidden rounded-xl border border-neutral-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-800 bg-neutral-900/60 text-left text-[11px] uppercase tracking-[0.18em] text-neutral-500">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Decision</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Replay</th>
                </tr>
              </thead>
              <tbody>
                {guardHistory.flatMap((scan) => {
                  const rr = replayResults[scan.id];
                  const isMismatch = rr && rr !== "loading" && rr !== "error" && !rr.replay_match;
                  const mainRow = (
                    <tr
                      key={`scan-${scan.id}`}
                      className={`border-b border-neutral-800/60 last:border-0 ${isMismatch ? "bg-yellow-950/20" : "bg-neutral-900/20"}`}
                    >
                      <td className="px-4 py-3 font-mono text-xs text-neutral-400">#{scan.id}</td>
                      <td className="px-4 py-3 text-xs text-neutral-400">{new Date(scan.created_at).toLocaleString()}</td>
                      <td className="px-4 py-3">
                        <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                          scan.decision === "block" ? "bg-red-500/15 text-red-400" :
                          scan.decision === "warn"  ? "bg-yellow-500/15 text-yellow-400" :
                                                      "bg-neutral-700/40 text-neutral-400"
                        }`}>{scan.decision || "—"}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-neutral-400">{scan.severity || "—"}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleReplay(scan.id)}
                          disabled={rr === "loading"}
                          className="rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-400 transition-colors hover:border-indigo-600 hover:text-indigo-400 disabled:opacity-40"
                        >
                          {rr === "loading" ? "…" : "Replay"}
                        </button>
                      </td>
                    </tr>
                  );
                  if (!rr || rr === "loading") return [mainRow];
                  const resultRow = (
                    <tr key={`replay-${scan.id}`} className={`border-b border-neutral-800/40 last:border-0 ${isMismatch ? "bg-yellow-950/10" : ""}`}>
                      <td colSpan={5} className="px-4 py-2 text-xs">
                        {rr === "error" ? (
                          <span className="text-red-400">Replay failed</span>
                        ) : (
                          <span className="flex flex-wrap items-center gap-3 text-neutral-400">
                            <span className={`font-semibold ${rr.replay_match ? "text-emerald-400" : "text-yellow-400"}`}>
                              {rr.replay_match ? "✓ Match" : "⚠ Mismatch"}
                            </span>
                            <span>Original: <span className="text-neutral-300">{rr.original_severity}</span></span>
                            <span>Replay: <span className="text-neutral-300">{rr.replay_severity}</span></span>
                            <span className={rr.replay_match ? "text-neutral-600" : "text-yellow-500/70"}>
                              {rr.replay_match ? "Result unchanged" : "Result changed since recorded"}
                            </span>
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                  return [mainRow, resultRow];
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Performance Analytics — PHASE 2.22 */}
      <section className="space-y-3">
        <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">Performance (last 7 days)</h2>
        {!hasApiKey ? (
          <p className="text-xs text-neutral-500">Set API key to see performance metrics.</p>
        ) : perfAnalytics === null ? (
          <p className="text-xs text-neutral-600">Loading…</p>
        ) : perfAnalytics.total_scans === 0 ? (
          <p className="text-sm text-neutral-500">No scans in this window.</p>
        ) : (
          <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-4 space-y-4">
            {/* KPI row */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { label: "Avg latency", value: `${perfAnalytics.avg_elapsed_ms} ms` },
                { label: "P95 latency", value: `${perfAnalytics.p95_elapsed_ms} ms` },
                { label: "Slow scans (>50 ms)", value: perfAnalytics.slow_scan_count },
                { label: "Total scans", value: perfAnalytics.total_scans },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
                  <p className="text-[11px] font-medium uppercase tracking-[0.18em] text-neutral-500">{label}</p>
                  <p className="mt-1 text-xl font-bold tabular-nums text-neutral-100">{value}</p>
                </div>
              ))}
            </div>
            {/* Stage timing mini-bars */}
            {Object.keys(perfAnalytics.avg_stage_timings).length > 0 && (
              <div className="space-y-2">
                <p className="text-[11px] font-medium uppercase tracking-[0.18em] text-neutral-500">Avg stage timings</p>
                {(() => {
                  const maxMs = Math.max(...Object.values(perfAnalytics.avg_stage_timings), 1);
                  return Object.entries(perfAnalytics.avg_stage_timings)
                    .sort(([, a], [, b]) => b - a)
                    .map(([stage, ms]) => (
                      <div key={stage} className="flex items-center gap-3">
                        <span className="w-32 shrink-0 truncate text-xs text-neutral-400">{stage}</span>
                        <div className="h-2 flex-1 overflow-hidden rounded-full bg-neutral-800">
                          <div
                            className="h-full rounded-full bg-indigo-500/70 transition-[width] duration-700"
                            style={{ width: `${Math.round((ms / maxMs) * 100)}%` }}
                          />
                        </div>
                        <span className="w-16 shrink-0 text-right text-xs tabular-nums text-neutral-400">{ms} ms</span>
                      </div>
                    ));
                })()}
              </div>
            )}
          </div>
        )}
      </section>

      {/* Security Scorecard — PHASE 2.29 */}
      {hasApiKey && (
        <section className="space-y-3">
          <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">Security Scorecard (last 30 days)</h2>
          {scorecard === null ? (
            <p className="text-xs text-neutral-600">Loading…</p>
          ) : (
            <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-4 space-y-4">
              {/* Grade badge + sub-scores */}
              <div className="flex flex-wrap items-center gap-4">
                {/* Grade badge */}
                <div className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-xl text-2xl font-bold ${
                  scorecard.overall_grade === "A" ? "bg-emerald-500/20 text-emerald-400" :
                  scorecard.overall_grade === "B" ? "bg-teal-500/20 text-teal-400" :
                  scorecard.overall_grade === "C" ? "bg-yellow-500/20 text-yellow-400" :
                  scorecard.overall_grade === "D" ? "bg-orange-500/20 text-orange-400" :
                  "bg-red-500/20 text-red-400"
                }`}>
                  {scorecard.overall_grade}
                </div>
                {/* Sub-score bars */}
                <div className="flex-1 min-w-0 space-y-2">
                  {[
                    { label: "Control Maturity", value: scorecard.control_maturity_score, color: "bg-emerald-500/70" },
                    { label: "Threat Pressure",  value: scorecard.threat_pressure_score,  color: "bg-red-500/70" },
                    { label: "Exposure",          value: scorecard.exposure_score,          color: "bg-orange-500/70" },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="flex items-center gap-3">
                      <span className="w-32 shrink-0 text-[11px] text-neutral-400">{label}</span>
                      <div className="flex-1 h-1.5 rounded-full bg-neutral-800">
                        <div className={`h-full rounded-full ${color} transition-[width] duration-700`} style={{ width: `${value}%` }} />
                      </div>
                      <span className="w-8 shrink-0 text-right text-[11px] tabular-nums text-neutral-400">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
              {/* Contributing factors */}
              {scorecard.contributing_factors.length > 0 && (
                <ul className="space-y-1">
                  {scorecard.contributing_factors.map((f) => (
                    <li key={f} className="flex items-start gap-2 text-xs text-neutral-400">
                      <span className="mt-0.5 text-neutral-600">›</span>
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </section>
      )}

      {/* Top Threat Signatures */}
      <section className="space-y-3">
        <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">
          Top Threat Signatures
        </h2>
        {threatsUnavailable ? (
          <p className="text-sm text-neutral-600">Threat data unavailable.</p>
        ) : threats.length === 0 ? (
          <p className="text-sm text-neutral-500">No threat signatures recorded.</p>
        ) : (
          <div className="overflow-hidden rounded-xl border border-neutral-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-800 bg-neutral-900/60 text-left text-[11px] uppercase tracking-[0.18em] text-neutral-500">
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Count</th>
                  <th className="px-4 py-3">Hash</th>
                  <th className="px-4 py-3">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((t) => (
                  <tr
                    key={t.signature_hash}
                    className="border-b border-neutral-800/60 bg-neutral-900/20 last:border-0"
                  >
                    <td className="px-4 py-3">
                      <CategoryBadge category={t.top_category} />
                    </td>
                    <td className="px-4 py-3 tabular-nums text-xs text-neutral-300">
                      {t.count}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-neutral-400">
                        {t.signature_hash.slice(0, 8)}&hellip;
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-neutral-400">
                      {new Date(t.last_seen_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Recent campaigns table */}
      <section className="space-y-3">
        <h2 className="text-xs font-medium uppercase tracking-wide text-neutral-500">
          Recent Campaigns
        </h2>
        {recent.length === 0 ? (
          <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 px-6 py-8 text-center">
            <p className="text-sm text-neutral-400">No campaigns yet.</p>
            <p className="mt-1.5 text-xs text-neutral-600">
              Seed sample data from the{" "}
              <a href="/admin" className="text-blue-500 hover:text-blue-400 underline underline-offset-2">
                Admin panel
              </a>
              , or run your first campaign from the{" "}
              <a href="/" className="text-blue-500 hover:text-blue-400 underline underline-offset-2">
                home page
              </a>
              .
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-neutral-800">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-800 bg-neutral-900/60 text-left text-[11px] uppercase tracking-[0.18em] text-neutral-500">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Progress</th>
                  <th className="px-4 py-3">Max Risk</th>
                  <th className="px-4 py-3">Avg Risk</th>
                  <th className="px-4 py-3">Created</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((c) => (
                  <tr
                    key={c.id}
                    className="border-b border-neutral-800/60 bg-neutral-900/20 last:border-0"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-neutral-200">#{c.id}</span>
                        <button
                          onClick={() => navigator.clipboard.writeText(String(c.id))}
                          className="text-[10px] text-neutral-600 hover:text-neutral-400 transition-colors"
                          title="Copy ID"
                        >
                          copy
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={c.status} />
                    </td>
                    <td className="px-4 py-3 tabular-nums text-xs text-neutral-300">
                      {Math.round(c.progress * 100)}%
                    </td>
                    <td className="px-4 py-3 tabular-nums text-xs text-neutral-300">
                      {c.max_risk}
                    </td>
                    <td className="px-4 py-3 tabular-nums text-xs text-neutral-300">
                      {c.avg_risk.toFixed(1)}
                    </td>
                    <td className="px-4 py-3 text-xs text-neutral-400">
                      {new Date(c.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
