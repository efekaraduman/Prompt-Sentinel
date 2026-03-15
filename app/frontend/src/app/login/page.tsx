"use client";

import { useEffect, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";

// ---------------------------------------------------------------------------
// Inner component — uses useSearchParams (requires Suspense boundary)
// ---------------------------------------------------------------------------

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const returnTo = searchParams.get("returnTo") || "/dashboard";

  // ── API key section ─────────────────────────────────────────────────────
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [apiKeyError, setApiKeyError] = useState<string | null>(null);
  const [apiKeySet, setApiKeySet] = useState(false);

  useEffect(() => {
    setApiKeySet(!!localStorage.getItem("apiKey"));
  }, []);

  function handleSaveApiKey() {
    const trimmed = apiKeyInput.trim();
    if (trimmed.length < 10) {
      setApiKeyError("API key must be at least 10 characters");
      return;
    }
    setApiKeyError(null);
    localStorage.setItem("apiKey", trimmed);
    setApiKeySet(true);
    router.push(returnTo);
  }

  function handleClearApiKey() {
    localStorage.removeItem("apiKey");
    setApiKeyInput("");
    setApiKeySet(false);
  }

  // ── Magic-link section ──────────────────────────────────────────────────
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [devToken, setDevToken] = useState<string | null>(null);
  const [manualToken, setManualToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [autoRedeeming, setAutoRedeeming] = useState(false);

  // ── Auto-redeem token from URL query param (?token=…) ──────────────────
  useEffect(() => {
    const urlToken = searchParams.get("token");
    if (!urlToken) return;
    setAutoRedeeming(true);
    redeem(urlToken).finally(() => setAutoRedeeming(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Helpers ────────────────────────────────────────────────────────────
  async function sendLink() {
    if (!email.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      const data: { ok?: boolean; dev_token?: string; error?: { type: string; message: string } } =
        await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message ?? `Error ${res.status}`);
      }
      setSent(true);
      if (data.dev_token) setDevToken(data.dev_token);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function redeem(token: string) {
    if (!token.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/redeem", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token.trim() }),
      });
      const data: { api_key?: string; email?: string; plan?: string; error?: { message: string } } =
        await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message ?? `Error ${res.status}`);
      }
      if (data.api_key) {
        localStorage.setItem("apiKey", data.api_key);
        router.push(returnTo);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  // ── UI ─────────────────────────────────────────────────────────────────
  if (autoRedeeming) {
    return (
      <div className="flex items-center justify-center min-h-[calc(100vh-60px)]">
        <p className="text-neutral-400 text-sm">Signing you in…</p>
      </div>
    );
  }

  return (
    <main className="flex items-center justify-center min-h-[calc(100vh-60px)] px-4">
      <div className="w-full max-w-sm space-y-4">

        {/* ── API key login card ──────────────────────────────────────────── */}
        <div className="p-6 bg-neutral-900 rounded-lg border border-neutral-800 space-y-4">
          <div>
            <h1 className="text-lg font-semibold text-neutral-100">Sign in with API key</h1>
            <p className="text-xs text-neutral-500 mt-0.5">Paste your API key to authenticate.</p>
          </div>

          {apiKeySet && (
            <p className="text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-800/40 rounded px-3 py-2">
              ✓ API key saved — you are signed in.
            </p>
          )}

          {apiKeyError && (
            <p className="text-sm text-red-400 bg-red-950/40 border border-red-800 rounded px-3 py-2">
              {apiKeyError}
            </p>
          )}

          <input
            type="password"
            placeholder="Paste API key…"
            value={apiKeyInput}
            onChange={(e) => { setApiKeyInput(e.target.value); setApiKeyError(null); }}
            onKeyDown={(e) => e.key === "Enter" && handleSaveApiKey()}
            className="w-full px-3 py-2 rounded bg-neutral-800 border border-neutral-700 text-sm text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-blue-500"
          />

          <div className="flex gap-2">
            <button
              onClick={handleSaveApiKey}
              disabled={!apiKeyInput.trim()}
              className="flex-1 py-2 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-sm font-medium text-white transition-colors"
            >
              Save &amp; continue
            </button>
            {apiKeySet && (
              <button
                onClick={handleClearApiKey}
                className="px-3 py-2 rounded border border-neutral-700 hover:border-red-700 text-sm text-neutral-400 hover:text-red-400 transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* ── Divider ────────────────────────────────────────────────────── */}
        <div className="flex items-center gap-3">
          <div className="flex-1 border-t border-neutral-800" />
          <span className="text-xs text-neutral-600">or sign in with email</span>
          <div className="flex-1 border-t border-neutral-800" />
        </div>

        {/* ── Magic-link card ─────────────────────────────────────────────── */}
        <div className="p-6 bg-neutral-900 rounded-lg border border-neutral-800 space-y-4">
          <div>
            <h2 className="text-base font-semibold text-neutral-100">Magic link</h2>
            <p className="text-xs text-neutral-500 mt-0.5">We&apos;ll email you a one-time sign-in link.</p>
          </div>

          {error && (
            <p className="text-sm text-red-400 bg-red-950/40 border border-red-800 rounded px-3 py-2">
              {error}
            </p>
          )}

          {!sent ? (
            /* ── Step 1: enter email ── */
            <>
              <input
                type="email"
                placeholder="your@email.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && sendLink()}
                className="w-full px-3 py-2 rounded bg-neutral-800 border border-neutral-700 text-sm text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={sendLink}
                disabled={loading || !email.trim()}
                className="w-full py-2 rounded bg-neutral-700 hover:bg-neutral-600 disabled:opacity-50 text-sm font-medium text-white transition-colors"
              >
                {loading ? "Sending…" : "Send magic link"}
              </button>
            </>
          ) : (
            /* ── Step 2: awaiting token ── */
            <>
              {devToken ? (
                /* dev mode: token returned in response */
                <div className="space-y-2">
                  <p className="text-sm text-neutral-400">
                    Dev mode — token returned (no email sent):
                  </p>
                  <code className="block text-xs text-green-400 break-all bg-neutral-800 p-2 rounded">
                    {devToken}
                  </code>
                  <button
                    onClick={() => redeem(devToken)}
                    disabled={loading}
                    className="w-full py-2 rounded bg-green-700 hover:bg-green-600 disabled:opacity-50 text-sm font-medium text-white transition-colors"
                  >
                    {loading ? "Signing in…" : "Redeem & sign in"}
                  </button>
                </div>
              ) : (
                <p className="text-sm text-neutral-400">
                  Check your inbox — a sign-in link is on its way.
                </p>
              )}

              {/* manual paste fallback (always shown after send) */}
              <div className="pt-2 border-t border-neutral-700 space-y-2">
                <p className="text-xs text-neutral-500">Or paste a token manually:</p>
                <input
                  type="text"
                  placeholder="Paste token…"
                  value={manualToken}
                  onChange={(e) => setManualToken(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && redeem(manualToken)}
                  className="w-full px-3 py-2 rounded bg-neutral-800 border border-neutral-700 text-sm text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-blue-500"
                />
                <button
                  onClick={() => redeem(manualToken)}
                  disabled={loading || !manualToken.trim()}
                  className="w-full py-2 rounded bg-neutral-700 hover:bg-neutral-600 disabled:opacity-50 text-sm font-medium text-white transition-colors"
                >
                  {loading ? "Signing in…" : "Redeem"}
                </button>
              </div>
            </>
          )}
        </div>

      </div>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Page export — wraps inner component in Suspense (required for useSearchParams)
// ---------------------------------------------------------------------------

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center min-h-[calc(100vh-60px)]">
          <p className="text-neutral-400 text-sm">Loading…</p>
        </div>
      }
    >
      <LoginContent />
    </Suspense>
  );
}
