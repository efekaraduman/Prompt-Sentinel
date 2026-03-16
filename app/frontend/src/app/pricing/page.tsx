"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { startProCheckout, createPortalSession, getMe, safeExternalRedirect } from "../../../lib/api";
import type { MeResponse } from "../../../lib/types";

// ---------------------------------------------------------------------------
// Plan data
// ---------------------------------------------------------------------------

const PLANS = [
  {
    name: "Free",
    price: "$0",
    description: "Good for personal exploration and small projects.",
    features: [
      "50 guard scans / month",
      "500 campaign iterations / month",
      "Basic analytics",
      "Community support",
    ],
    cta: null, // no button — current tier
    highlight: false,
  },
  {
    name: "Pro",
    price: "$29 / mo",
    description: "For teams that need higher throughput and advanced controls.",
    features: [
      "5 000 guard scans / month",
      "50 000 campaign iterations / month",
      "Guard analytics & audit log",
      "allow_medium policy option",
      "Stripe billing portal",
      "Priority support",
    ],
    cta: "Upgrade to Pro",
    highlight: true,
  },
] as const;

// ---------------------------------------------------------------------------
// Feature row
// ---------------------------------------------------------------------------

function Feature({ text }: { text: string }) {
  return (
    <li className="flex items-start gap-2 text-sm text-neutral-300">
      <span className="mt-0.5 text-emerald-500">✓</span>
      {text}
    </li>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function PricingPage() {
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [me, setMe] = useState<MeResponse | null>(null);
  const [meError, setMeError] = useState<string | null>(null);

  useEffect(() => {
    const key = localStorage.getItem("apiKey");
    setApiKey(key);
    if (key) {
      getMe(key)
        .then(setMe)
        .catch((e: unknown) =>
          setMeError(e instanceof Error ? e.message : "Unable to load plan"),
        );
    }
  }, []);

  async function handleUpgrade() {
    if (!apiKey) {
      setError("API key required");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const { checkout_url } = await startProCheckout(apiKey);
      safeExternalRedirect(checkout_url);
    } catch (e: unknown) {
      const raw = e instanceof Error ? e.message : "Checkout failed";
      if (raw === "already_pro" || raw.toLowerCase().includes("already")) {
        setError("You're already Pro 🎉");
      } else if (
        raw.includes("401") ||
        raw.toLowerCase().includes("unauthorized") ||
        raw.toLowerCase().includes("api key")
      ) {
        setError("API key required");
      } else {
        setError(raw);
      }
      setLoading(false);
    }
  }

  async function handleManageBilling() {
    if (!apiKey) return;
    setLoading(true);
    setError(null);
    try {
      const { url } = await createPortalSession(apiKey);
      safeExternalRedirect(url);
    } catch (e: unknown) {
      const raw = e instanceof Error ? e.message : "";
      if (raw.toLowerCase().includes("not configured") || raw.toLowerCase().includes("not available") || raw.toLowerCase().includes("not installed")) {
        setError("Billing is not available on this server.");
      } else if (raw.toLowerCase().includes("no billing account") || raw.toLowerCase().includes("no stripe customer")) {
        setError("No billing account found. Please contact support.");
      } else {
        setError(raw || "Billing portal unavailable.");
      }
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto max-w-3xl px-6 py-16 space-y-10">
      <div className="text-center space-y-2">
        <h1 className="text-2xl font-bold text-neutral-100">Plans &amp; Pricing</h1>
        <p className="text-sm text-neutral-400">
          Simple, transparent pricing. Upgrade or cancel any time.
        </p>
      </div>

      {/* Current plan badge */}
      {apiKey && me && (
        <div className="flex justify-center">
          <span
            className={`rounded-full px-3 py-1 text-xs font-medium ${
              me.plan === "pro"
                ? "bg-emerald-500/15 text-emerald-400"
                : me.plan === "free"
                  ? "bg-indigo-500/15 text-indigo-400"
                  : "bg-neutral-700/40 text-neutral-500"
            }`}
          >
            Current plan:{" "}
            {me.plan === "pro" ? "Pro" : me.plan === "free" ? "Free" : "Public"}
          </span>
        </div>
      )}
      {meError && (
        <p className="text-center text-xs text-red-400">{meError}</p>
      )}

      {/* Plan cards */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
        {PLANS.map((plan) => (
          <div
            key={plan.name}
            className={`rounded-xl border p-6 space-y-5 ${
              plan.highlight
                ? "border-indigo-600 bg-indigo-950/30"
                : "border-neutral-800 bg-neutral-900"
            }`}
          >
            {/* Header */}
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <h2 className="text-base font-semibold text-neutral-100">{plan.name}</h2>
                {plan.highlight && (
                  <span className="rounded-full bg-indigo-600 px-2 py-0.5 text-[10px] font-medium text-white">
                    Popular
                  </span>
                )}
              </div>
              <p className="text-2xl font-bold text-neutral-100">{plan.price}</p>
              <p className="text-xs text-neutral-500">{plan.description}</p>
            </div>

            {/* Features */}
            <ul className="space-y-2">
              {plan.features.map((f) => (
                <Feature key={f} text={f} />
              ))}
            </ul>

            {/* CTA */}
            {plan.cta && (
              <div className="space-y-2">
                {apiKey === null ? (
                  /* still detecting localStorage — render nothing to avoid flash */
                  null
                ) : apiKey ? (
                  me?.plan === "pro" ? (
                    <button
                      onClick={handleManageBilling}
                      disabled={loading}
                      className="w-full rounded-lg bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 px-4 py-2 text-sm font-medium text-white transition-colors"
                    >
                      {loading ? "Redirecting…" : "Manage billing"}
                    </button>
                  ) : (
                    <button
                      onClick={handleUpgrade}
                      disabled={loading}
                      className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 px-4 py-2 text-sm font-medium text-white transition-colors"
                    >
                      {loading ? "Redirecting…" : "Upgrade to Pro"}
                    </button>
                  )
                ) : (
                  <Link
                    href="/login?returnTo=/pricing"
                    className="block w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2 text-center text-sm font-medium text-white transition-colors"
                  >
                    Login to upgrade
                  </Link>
                )}
                {error && <p className="text-xs text-red-400">{error}</p>}
              </div>
            )}
          </div>
        ))}
      </div>

      <p className="text-center text-xs text-neutral-600">
        Payments are handled securely by Stripe. You can manage or cancel your subscription at any
        time from the billing portal in your dashboard.
      </p>
    </main>
  );
}
