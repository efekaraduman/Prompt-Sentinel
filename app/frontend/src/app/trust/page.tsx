"use client";

import { useEffect, useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TrustStatus {
  service_status: string;
  guard_enabled: boolean;
  billing_configured: boolean;
  rate_limit_mode: string;
  supported_capabilities: string[];
  version: string;
}

interface CapabilityItem {
  name: string;
  description: string;
}

// ---------------------------------------------------------------------------
// Static protection explanations (rendered without fetching)
// ---------------------------------------------------------------------------

const WHAT_WE_PROTECT: { heading: string; body: string }[] = [
  {
    heading: "Prompt Injection",
    body: "Attackers craft inputs that override your system prompt, silently altering the model's behaviour. PromptSentinel detects and blocks these attempts before they reach production.",
  },
  {
    heading: "Data & PII Leakage",
    body: "Sensitive data — names, emails, secrets — can be coaxed out of a model that has seen it. Our guard pipeline identifies leakage patterns in both inputs and outputs.",
  },
  {
    heading: "RAG Poisoning",
    body: "Documents injected into retrieval pipelines can redirect model responses. PromptSentinel scans retrieved context for embedded adversarial instructions.",
  },
  {
    heading: "Tool & Function Abuse",
    body: "LLMs with tool-use capabilities can be tricked into calling unintended functions. PromptSentinel enforces policy on tool invocations at the guard layer.",
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function StatusBadge({ status }: { status: string }) {
  const ok = status === "ok";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${
        ok
          ? "bg-emerald-500/15 text-emerald-400"
          : "bg-amber-500/15 text-amber-400"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-emerald-400" : "bg-amber-400"}`}
      />
      {ok ? "All systems operational" : "Degraded"}
    </span>
  );
}

function CapabilityBadge({ name }: { name: string }) {
  const label = name.replace(/_/g, " ");
  return (
    <span className="rounded-full bg-indigo-500/10 px-2.5 py-0.5 text-xs font-medium text-indigo-300 border border-indigo-500/20">
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function TrustPage() {
  const [status, setStatus] = useState<TrustStatus | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(false);

  useEffect(() => {
    // Always use the Next.js proxy (/api/*) — never call the backend directly
    // from client components; direct calls break CSP (connect-src 'self') and
    // CORS on Vercel deployments.
    Promise.allSettled([
      fetch(`/api/trust/status`).then((r) => r.ok ? r.json() : Promise.reject(new Error(`status ${r.status}`))),
      fetch(`/api/trust/capabilities`).then((r) => r.ok ? r.json() : Promise.reject(new Error(`status ${r.status}`))),
    ])
      .then(([statusResult, capResult]) => {
        if (statusResult.status === "fulfilled") setStatus(statusResult.value as TrustStatus);
        if (capResult.status === "fulfilled") {
          setCapabilities((capResult.value as { capabilities: CapabilityItem[] }).capabilities ?? []);
        }
        if (statusResult.status === "rejected" && capResult.status === "rejected") {
          setFetchError(true); // only show error when both fail
        }
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <main className="mx-auto max-w-3xl px-6 py-16 space-y-14">

      {/* Hero */}
      <div className="space-y-3">
        <h1 className="text-2xl font-bold text-neutral-100">Trust Center</h1>
        <p className="text-sm text-neutral-400 max-w-xl">
          PromptSentinel helps teams ship LLM-powered products safely by simulating
          prompt-injection attacks and surfacing risk before it reaches production.
          This page is public and contains no tenant-specific data.
        </p>
      </div>

      {/* Service status */}
      <section className="space-y-3">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-500">
          Service Status
        </h2>
        {loading ? (
          <p className="text-xs text-neutral-600">Loading…</p>
        ) : fetchError ? (
          <p className="text-xs text-neutral-500">Live status unavailable — service data could not be retrieved.</p>
        ) : status ? (
          <div className="rounded-xl border border-neutral-800 bg-neutral-900 p-5 space-y-4">
            <StatusBadge status={status.service_status} />
            <dl className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm sm:grid-cols-3">
              <div>
                <dt className="text-neutral-500 text-xs mb-0.5">Guard engine</dt>
                <dd className="text-neutral-100 font-medium">
                  {status.guard_enabled ? "Enabled" : "Disabled"}
                </dd>
              </div>
              <div>
                <dt className="text-neutral-500 text-xs mb-0.5">Rate limiting</dt>
                <dd className="text-neutral-100 font-medium capitalize">
                  {status.rate_limit_mode}
                </dd>
              </div>
              <div>
                <dt className="text-neutral-500 text-xs mb-0.5">Billing</dt>
                <dd className="text-neutral-100 font-medium">
                  {status.billing_configured ? "Configured" : "Not configured"}
                </dd>
              </div>
              <div>
                <dt className="text-neutral-500 text-xs mb-0.5">Version</dt>
                <dd className="text-neutral-100 font-medium">{status.version}</dd>
              </div>
            </dl>
          </div>
        ) : (
          <p className="text-xs text-neutral-600">Status unavailable.</p>
        )}
      </section>

      {/* Supported capabilities */}
      <section className="space-y-4">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-500">
          Supported Protections
        </h2>
        {capabilities.length > 0 ? (
          <ul className="space-y-3">
            {capabilities.map((cap) => (
              <li
                key={cap.name}
                className="rounded-xl border border-neutral-800 bg-neutral-900 p-4 flex flex-col gap-1.5"
              >
                <CapabilityBadge name={cap.name} />
                <p className="text-sm text-neutral-300">{cap.description}</p>
              </li>
            ))}
          </ul>
        ) : (
          /* Fallback to static badges when API unavailable */
          <div className="flex flex-wrap gap-2">
            {["prompt_injection", "pii", "hallucination", "rag_injection", "tool_abuse", "threat_analytics"].map(
              (n) => <CapabilityBadge key={n} name={n} />,
            )}
          </div>
        )}
      </section>

      {/* What we protect against */}
      <section className="space-y-4">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-neutral-500">
          What PromptSentinel Protects Against
        </h2>
        <div className="grid gap-4 sm:grid-cols-2">
          {WHAT_WE_PROTECT.map((item) => (
            <div
              key={item.heading}
              className="rounded-xl border border-neutral-800 bg-neutral-900 p-5 space-y-2"
            >
              <h3 className="text-sm font-semibold text-neutral-100">{item.heading}</h3>
              <p className="text-xs text-neutral-400 leading-relaxed">{item.body}</p>
            </div>
          ))}
        </div>
      </section>

      <p className="text-center text-xs text-neutral-700">
        No authentication required · No tenant data displayed · Public endpoint
      </p>
    </main>
  );
}
