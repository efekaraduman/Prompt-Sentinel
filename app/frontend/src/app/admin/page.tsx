"use client";

import React, { useEffect, useState } from "react";
import {
  createAdminUser,
  deactivateUser,
  getAdminAnalytics,
  getAdminUsers,
  getAdminUsersUsage,
  rotateUserKey,
  getWebhookConfig,
  setWebhookConfig,
} from "../../../lib/api";
import type { AdminGlobalAnalyticsResponse, AdminUserUsageItem, UserSafe, WebhookConfig } from "../../../lib/types";

type Tab = "users" | "usage" | "analytics" | "webhook";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function PlanBadge({ plan }: { plan: string }) {
  const isPro = plan === "pro";
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${
        isPro
          ? "bg-indigo-500/20 text-indigo-300"
          : "bg-neutral-700/40 text-neutral-400"
      }`}
    >
      {plan}
    </span>
  );
}

function QuotaBar({
  used,
  limit,
  remaining,
}: {
  used: number;
  limit: number;
  remaining: number;
}) {
  const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  const exhausted = remaining === 0 && limit > 0;
  return (
    <div className="flex items-center gap-2 min-w-0">
      <div className="h-1.5 w-20 shrink-0 rounded-full bg-neutral-800">
        <div
          className={`h-full rounded-full transition-all ${
            exhausted ? "bg-red-500" : "bg-indigo-500"
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[11px] tabular-nums text-neutral-400">
        {used.toLocaleString()}&nbsp;/&nbsp;{limit.toLocaleString()}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Usage tab
// ---------------------------------------------------------------------------

function UsageTab() {
  const [items, setItems] = useState<AdminUserUsageItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const apiKey = localStorage.getItem("apiKey") ?? undefined;
    getAdminUsersUsage(50, apiKey)
      .then(setItems)
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load usage");
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-neutral-700 border-t-indigo-500" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-800/70 bg-red-950/50 px-3 py-2 text-xs text-red-200">
        {error}
      </div>
    );
  }

  if (items.length === 0) {
    return <p className="text-sm text-neutral-500">No users found.</p>;
  }

  return (
    <div className="overflow-hidden rounded-xl border border-neutral-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-neutral-800 bg-neutral-900/60 text-left text-[11px] uppercase tracking-[0.18em] text-neutral-500">
            <th className="px-4 py-3">Email</th>
            <th className="px-4 py-3">Plan</th>
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3">Guard Scans</th>
            <th className="px-4 py-3">Campaign Iters</th>
            <th className="px-4 py-3">Period</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              key={item.id}
              className="border-b border-neutral-800/60 bg-neutral-900/20 last:border-0"
            >
              <td className="px-4 py-3 font-mono text-xs text-neutral-200">
                {item.email}
              </td>
              <td className="px-4 py-3">
                <PlanBadge plan={item.plan} />
              </td>
              <td className="px-4 py-3">
                <span
                  className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                    item.is_active
                      ? "bg-emerald-500/15 text-emerald-400"
                      : "bg-neutral-700/40 text-neutral-500"
                  }`}
                >
                  {item.is_active ? "Active" : "Inactive"}
                </span>
              </td>
              <td className="px-4 py-3">
                <QuotaBar
                  used={item.guard_scans_used}
                  limit={item.guard_scans_limit}
                  remaining={item.guard_scans_remaining}
                />
              </td>
              <td className="px-4 py-3">
                <QuotaBar
                  used={item.campaign_iterations_used}
                  limit={item.campaign_iterations_limit}
                  remaining={item.campaign_iterations_remaining}
                />
              </td>
              <td className="px-4 py-3 text-[11px] text-neutral-500">
                {item.period_ym}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Analytics tab
// ---------------------------------------------------------------------------

function AnalyticsStatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-4">
      <p className="text-[11px] font-medium uppercase tracking-[0.18em] text-neutral-500">{label}</p>
      <p className="mt-1.5 text-2xl font-bold tabular-nums text-neutral-100">{value}</p>
      {sub && <p className="mt-0.5 text-xs text-neutral-600">{sub}</p>}
    </div>
  );
}

function AnalyticsTab() {
  const [data, setData] = useState<AdminGlobalAnalyticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const apiKey = localStorage.getItem("apiKey") ?? undefined;
    getAdminAnalytics(apiKey)
      .then(setData)
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load analytics");
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-neutral-700 border-t-indigo-500" />
      </div>
    );
  }

  if (error) {
    return (
      <p className="text-sm text-red-400">
        {error === "Invalid API key" ? "Admin key required." : error}
      </p>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-6">
      {/* Users */}
      <div>
        <h3 className="mb-3 text-[11px] font-medium uppercase tracking-[0.18em] text-neutral-500">Users</h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <AnalyticsStatCard label="Total" value={data.total_users} />
          <AnalyticsStatCard label="Active" value={data.active_users} />
          <AnalyticsStatCard label="Pro" value={data.pro_users} />
        </div>
      </div>
      {/* Campaigns */}
      <div>
        <h3 className="mb-3 text-[11px] font-medium uppercase tracking-[0.18em] text-neutral-500">Campaigns</h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <AnalyticsStatCard label="Total" value={data.total_campaigns} />
          <AnalyticsStatCard label="Completed" value={data.campaigns_completed} />
          <AnalyticsStatCard label="Failed" value={data.campaigns_failed} />
        </div>
      </div>
      {/* Guard */}
      <div>
        <h3 className="mb-3 text-[11px] font-medium uppercase tracking-[0.18em] text-neutral-500">Guard Scans</h3>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <AnalyticsStatCard label="Total" value={data.guard_total_scans} />
          <AnalyticsStatCard label="Blocks" value={data.guard_blocks} />
          <AnalyticsStatCard label="Warns" value={data.guard_warns} />
          <AnalyticsStatCard label="Avg latency" value={`${Math.round(data.avg_guard_latency_ms)} ms`} />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Users tab (existing content)
// ---------------------------------------------------------------------------

function UsersTab() {
  const [users, setUsers] = useState<UserSafe[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newKeys, setNewKeys] = useState<Record<number, string>>({});
  const [actionLoading, setActionLoading] = useState<Record<number, string>>({});
  const [newUserEmail, setNewUserEmail] = useState("");
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createdKey, setCreatedKey] = useState<{ email: string; api_key: string } | null>(null);

  useEffect(() => {
    const apiKey = localStorage.getItem("apiKey") ?? undefined;
    getAdminUsers(apiKey)
      .then(setUsers)
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load users");
      })
      .finally(() => setLoading(false));
  }, []);

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault();
    const email = newUserEmail.trim();
    if (!email) return;
    setCreateError(null);
    setCreatedKey(null);
    setCreateLoading(true);
    try {
      const apiKey = localStorage.getItem("apiKey") ?? undefined;
      const result = await createAdminUser(email, apiKey);
      setCreatedKey(result);
      setNewUserEmail("");
      getAdminUsers(apiKey).then(setUsers).catch(() => {});
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Create failed";
      setCreateError(msg === "Invalid API key" ? "Admin key required." : msg);
    } finally {
      setCreateLoading(false);
    }
  }

  async function handleRotate(id: number) {
    setActionLoading((prev) => ({ ...prev, [id]: "rotate" }));
    try {
      const apiKey = localStorage.getItem("apiKey") ?? undefined;
      const result = await rotateUserKey(id, apiKey);
      setNewKeys((prev) => ({ ...prev, [id]: result.api_key }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Rotate failed");
    } finally {
      setActionLoading((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }
  }

  async function handleDeactivate(id: number) {
    setActionLoading((prev) => ({ ...prev, [id]: "deactivate" }));
    try {
      const apiKey = localStorage.getItem("apiKey") ?? undefined;
      const updated = await deactivateUser(id, apiKey);
      setUsers((prev) => prev.map((u) => (u.id === id ? { ...u, is_active: updated.is_active } : u)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Deactivate failed");
    } finally {
      setActionLoading((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-neutral-700 border-t-indigo-500" />
      </div>
    );
  }

  const isAuthError = error === "Invalid API key";

  if (isAuthError || (error && users.length === 0)) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 py-12">
        <p className="text-sm text-red-400">
          {isAuthError ? "Admin key required. Set your API key in the header." : error}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Create user form */}
      <form onSubmit={handleCreateUser} className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <label className="text-xs font-medium uppercase tracking-[0.18em] text-neutral-400">
            New User Email
          </label>
          <input
            type="email"
            value={newUserEmail}
            onChange={(e) => setNewUserEmail(e.target.value)}
            placeholder="user@example.com"
            className="w-64 rounded-lg border border-neutral-800 bg-neutral-950/80 px-3 py-2 text-sm text-neutral-100 outline-none transition-colors focus:border-neutral-400 focus:ring-1 focus:ring-neutral-500"
          />
        </div>
        <button
          type="submit"
          disabled={createLoading}
          className="inline-flex items-center justify-center rounded-lg border border-emerald-500/70 bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-300 transition-colors hover:bg-emerald-500/20 hover:text-emerald-100 disabled:cursor-not-allowed disabled:border-neutral-700 disabled:bg-neutral-800 disabled:text-neutral-400"
        >
          {createLoading ? "Creating…" : "Create"}
        </button>
      </form>

      {createError && (
        <div className="rounded-lg border border-red-800/70 bg-red-950/50 px-3 py-2 text-xs text-red-200">
          {createError}
        </div>
      )}

      {createdKey && (
        <div className="space-y-2 rounded-lg border border-emerald-800/50 bg-emerald-950/20 px-4 py-3">
          <p className="text-xs font-medium text-emerald-400">
            User <span className="font-mono">{createdKey.email}</span> created — save this key
            now, it won&apos;t be shown again.
          </p>
          <div className="flex items-center gap-3">
            <code className="flex-1 break-all rounded bg-neutral-900 px-2 py-1 font-mono text-[11px] text-emerald-300">
              {createdKey.api_key}
            </code>
            <button
              onClick={() => navigator.clipboard.writeText(createdKey.api_key)}
              className="shrink-0 rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-300 transition-colors hover:border-neutral-500"
            >
              Copy
            </button>
            <button
              onClick={() => setCreatedKey(null)}
              className="shrink-0 text-[11px] text-neutral-600 hover:text-neutral-400"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-800/70 bg-red-950/50 px-3 py-2 text-xs text-red-200">
          {error}
        </div>
      )}

      {users.length === 0 ? (
        <p className="text-sm text-neutral-500">No users found.</p>
      ) : (
        <div className="overflow-hidden rounded-xl border border-neutral-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-neutral-800 bg-neutral-900/60 text-left text-[11px] uppercase tracking-[0.18em] text-neutral-500">
                <th className="px-4 py-3">Email</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <React.Fragment key={user.id}>
                  <tr
                    className="border-b border-neutral-800/60 bg-neutral-900/20 last:border-0"
                  >
                    <td className="px-4 py-3 font-mono text-xs text-neutral-200">{user.email}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                          user.is_active
                            ? "bg-emerald-500/15 text-emerald-400"
                            : "bg-neutral-700/40 text-neutral-500"
                        }`}
                      >
                        {user.is_active ? "Active" : "Inactive"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-neutral-400">
                      {new Date(user.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        <button
                          onClick={() => handleRotate(user.id)}
                          disabled={!!actionLoading[user.id]}
                          className="rounded border border-neutral-700 px-2 py-1 text-[11px] font-medium text-neutral-300 transition-colors hover:border-neutral-500 hover:text-neutral-100 disabled:cursor-not-allowed disabled:text-neutral-600"
                        >
                          {actionLoading[user.id] === "rotate" ? "Rotating…" : "Rotate Key"}
                        </button>
                        {user.is_active && (
                          <button
                            onClick={() => handleDeactivate(user.id)}
                            disabled={!!actionLoading[user.id]}
                            className="rounded border border-red-800/60 px-2 py-1 text-[11px] font-medium text-red-400 transition-colors hover:border-red-600 hover:text-red-300 disabled:cursor-not-allowed disabled:text-neutral-600"
                          >
                            {actionLoading[user.id] === "deactivate" ? "Deactivating…" : "Deactivate"}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                  {newKeys[user.id] && (
                    <tr key={`${user.id}-key`} className="border-b border-neutral-800/60 bg-indigo-950/20 last:border-0">
                      <td colSpan={4} className="px-4 py-2">
                        <div className="flex items-center gap-3">
                          <span className="text-[11px] text-neutral-400">New key:</span>
                          <code className="flex-1 rounded bg-neutral-900 px-2 py-1 font-mono text-[11px] text-indigo-300 break-all">
                            {newKeys[user.id]}
                          </code>
                          <button
                            onClick={() => navigator.clipboard.writeText(newKeys[user.id])}
                            className="shrink-0 rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-300 transition-colors hover:border-neutral-500"
                          >
                            Copy
                          </button>
                          <button
                            onClick={() =>
                              setNewKeys((prev) => {
                                const next = { ...prev };
                                delete next[user.id];
                                return next;
                              })
                            }
                            className="shrink-0 text-[11px] text-neutral-600 hover:text-neutral-400"
                          >
                            ✕
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Phase 3.14 — Webhook Tab
// ---------------------------------------------------------------------------

// PHASE 2.21 — helper to normalise 401/403 messages
function webhookErrMsg(e: unknown): string {
  const raw = e instanceof Error ? e.message : "Unknown error";
  if (raw.includes("401") || raw.includes("403") || raw.toLowerCase().includes("invalid api key")) {
    return "Org admin required";
  }
  return raw;
}

function WebhookTab() {
  const [config, setConfig] = useState<WebhookConfig | null>(null);
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [isActive, setIsActive] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);  // PHASE 2.21
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);  // PHASE 2.21
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    getWebhookConfig()
      .then((c) => {
        setConfig(c);
        setUrl(c.url);
        setIsActive(c.is_active);
      })
      .catch((e: unknown) => setLoadError(webhookErrMsg(e)));  // PHASE 2.21
  }, []);

  async function handleSave() {
    if (!url) return;
    setLoading(true);
    setStatus(null);
    try {
      const updated = await setWebhookConfig({ url, secret, is_active: isActive });
      setConfig(updated);
      setStatus({ ok: true, msg: "Saved." });
    } catch (e) {
      setStatus({ ok: false, msg: webhookErrMsg(e) });  // PHASE 2.21
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-6 space-y-4">
      <h2 className="text-lg font-semibold text-white">SIEM / Webhook</h2>
      <p className="text-sm text-neutral-400">
        Send guard events (warn/block) to your SIEM or SOAR via signed HTTP POST.
      </p>

      {/* PHASE 2.21 — load-error banner (401/403 → "Org admin required") */}
      {loadError && (
        <div className="rounded-lg border border-red-800/70 bg-red-950/50 px-3 py-2 text-xs text-red-300">
          {loadError}
        </div>
      )}

      <div className="space-y-3 max-w-lg">
        <label className="block text-sm text-neutral-300">
          Webhook URL
          <input
            className="mt-1 w-full rounded-lg border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://your-siem.example.com/ingest"
          />
        </label>
        <label className="block text-sm text-neutral-300">
          Signing Secret
          <input
            className="mt-1 w-full rounded-lg border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="Leave blank to keep existing secret"
          />
        </label>
        <label className="flex items-center gap-2 text-sm text-neutral-300 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={isActive}
            onChange={(e) => setIsActive(e.target.checked)}
            className="rounded border-neutral-600 bg-neutral-800 text-indigo-500 focus:ring-indigo-500"
          />
          Active
        </label>
        <button
          onClick={handleSave}
          disabled={loading}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
        >
          {loading ? "Saving…" : "Save Webhook"}
        </button>
        {/* PHASE 2.21 — coloured save banner: green=ok, red=error */}
        {status && (
          <p className={`text-sm ${status.ok ? "text-emerald-400" : "text-red-400"}`}>
            {status.msg}
          </p>
        )}
      </div>

      {config && (
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm text-neutral-400 max-w-lg pt-2 border-t border-neutral-800">
          <dt>Last sent</dt>
          <dd className="text-neutral-200">{config.last_sent_at ?? "—"}</dd>
          <dt>Last error</dt>
          <dd className="text-red-400 break-all">{config.last_error ?? "—"}</dd>
        </dl>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>("users");
  const [seedLoading, setSeedLoading] = useState(false);
  const [seedBanner, setSeedBanner] = useState<{ ok: boolean; msg: string } | null>(null);

  async function handleSeedDemo() {
    setSeedLoading(true);
    setSeedBanner(null);
    try {
      const apiKey = localStorage.getItem("apiKey") ?? "";
      const res = await fetch("/api/admin/demo/seed", {
        method: "POST",
        headers: apiKey ? { "X-API-Key": apiKey } : {},
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({})) as { error?: { message: string } };
        throw new Error(errData.error?.message ?? `Error ${res.status}`);
      }
      const data: { ok?: boolean; created?: number } = await res.json();
      const created = data.created ?? 0;
      setSeedBanner({
        ok: true,
        msg: created > 0
          ? `Demo data loaded — ${created} campaigns created.`
          : "Demo data already present (skipped).",
      });
    } catch (err: unknown) {
      setSeedBanner({ ok: false, msg: err instanceof Error ? err.message : "Seed failed" });
    } finally {
      setSeedLoading(false);
    }
  }

  return (
    <main className="mx-auto max-w-5xl space-y-6 px-6 py-10">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <h1 className="text-xl font-semibold text-neutral-100">Admin</h1>
        <div className="flex items-center gap-3 flex-wrap">
          {/* Seed demo button */}
          <button
            onClick={handleSeedDemo}
            disabled={seedLoading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-1.5 text-xs font-medium text-neutral-300 transition-colors hover:border-neutral-500 hover:text-neutral-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {seedLoading ? "Seeding…" : "⚡ Seed demo data"}
          </button>
          {/* Tab switcher */}
          <div className="flex rounded-lg border border-neutral-800 bg-neutral-900/60 p-0.5 text-sm">
            {(["users", "usage", "analytics", "webhook"] as Tab[]).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`rounded-md px-4 py-1.5 text-sm font-medium capitalize transition-colors ${
                  tab === t
                    ? "bg-neutral-800 text-neutral-100"
                    : "text-neutral-500 hover:text-neutral-300"
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>
      </div>

      {seedBanner && (
        <div
          className={`rounded-lg border px-4 py-2 text-sm flex items-center justify-between gap-3 ${
            seedBanner.ok
              ? "border-emerald-800/50 bg-emerald-950/30 text-emerald-300"
              : "border-red-800/60 bg-red-950/40 text-red-300"
          }`}
        >
          <span>{seedBanner.msg}</span>
          <button
            onClick={() => setSeedBanner(null)}
            className="text-xs text-neutral-500 hover:text-neutral-300 shrink-0"
          >
            ✕
          </button>
        </div>
      )}

      {tab === "users" ? <UsersTab /> : tab === "usage" ? <UsageTab /> : tab === "analytics" ? <AnalyticsTab /> : <WebhookTab />}
    </main>
  );
}
