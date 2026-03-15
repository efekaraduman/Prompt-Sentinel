"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { getMe } from "../../../../lib/api";

const MAX_ATTEMPTS = 10;
const INTERVAL_MS = 1000;

export default function BillingSuccessPage() {
  const router = useRouter();
  const [status, setStatus] = useState<"checking" | "active" | "syncing">("checking");
  const attempts = useRef(0);

  useEffect(() => {
    const apiKey = localStorage.getItem("apiKey");
    if (!apiKey) {
      setStatus("syncing");
      return;
    }

    let cancelled = false;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    const poll = async () => {
      if (cancelled) return;
      attempts.current += 1;
      try {
        const me = await getMe(apiKey);
        if (me.plan === "pro") {
          if (!cancelled) setStatus("active");
          return; // stop — plan confirmed
        }
      } catch {
        // network hiccup; keep trying
      }
      if (attempts.current >= MAX_ATTEMPTS) {
        if (!cancelled) setStatus("syncing");
        return;
      }
      timeoutId = setTimeout(poll, INTERVAL_MS);
    };

    poll();
    return () => {
      cancelled = true;
      if (timeoutId !== null) clearTimeout(timeoutId);
    };
  }, []);

  return (
    <main className="flex min-h-[70vh] items-center justify-center">
      <div className="w-full max-w-sm rounded-xl border border-emerald-700/40 bg-emerald-950/30 px-8 py-10 text-center space-y-4">
        <div className="text-3xl">🎉</div>
        <h1 className="text-lg font-semibold text-neutral-100">Payment successful</h1>
        <p className="text-sm">
          {status === "checking" && (
            <span className="text-neutral-400">Checking plan…</span>
          )}
          {status === "active" && (
            <span className="text-emerald-400 font-medium">Pro is active ✅</span>
          )}
          {status === "syncing" && (
            <span className="text-neutral-400">
              Still syncing…{" "}
              <span className="text-neutral-500">It may take a few more seconds.</span>
            </span>
          )}
        </p>
        <button
          onClick={() => router.push("/dashboard?billing=success")}
          className="w-full rounded-lg bg-emerald-700 hover:bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition-colors"
        >
          Go to Dashboard
        </button>
      </div>
    </main>
  );
}
