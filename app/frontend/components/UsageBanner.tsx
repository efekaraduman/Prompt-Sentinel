"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getUsageStatus } from "../lib/api";
import type { UsageStatus } from "../lib/types";

export default function UsageBanner() {
  const [usage, setUsage] = useState<UsageStatus | null>(null);
  const router = useRouter();

  useEffect(() => {
    const key = localStorage.getItem("apiKey") ?? undefined;
    getUsageStatus(key)
      .then(setUsage)
      .catch(() => {}); // silent on auth/network error
  }, []);

  if (!usage) return null;
  if (usage.plan === "pro") return null;

  const limit = usage.limits.guard_scans;
  const remaining = usage.remaining.guard_scans;

  if (limit === null || remaining === null) return null;

  const low = remaining <= 10 || remaining / limit <= 0.2;
  if (!low) return null;

  return (
    <div className="bg-amber-900/60 border-b border-amber-700 px-6 py-2 flex items-center justify-between text-sm">
      <span className="text-amber-200">
        You have <strong>{remaining}</strong> guard scan{remaining !== 1 ? "s" : ""} remaining
        this month.
      </span>
      <button
        onClick={() => router.push("/pricing")}
        className="ml-4 px-3 py-1 rounded bg-amber-500 hover:bg-amber-400 text-neutral-950 font-semibold text-xs transition-colors"
      >
        Upgrade
      </button>
    </div>
  );
}
