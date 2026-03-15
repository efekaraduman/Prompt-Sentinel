"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

export default function BillingCancelPage() {
  const router = useRouter();

  return (
    <main className="flex min-h-[70vh] items-center justify-center">
      <div className="w-full max-w-sm rounded-xl border border-neutral-800 bg-neutral-900 px-8 py-10 text-center space-y-4">
        <div className="text-3xl">↩︎</div>
        <h1 className="text-lg font-semibold text-neutral-100">Checkout cancelled</h1>
        <p className="text-sm text-neutral-400">
          No charge was made. You can upgrade whenever you&apos;re ready.
        </p>
        <div className="flex flex-col gap-2 pt-1">
          <Link
            href="/pricing"
            className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors text-center"
          >
            Back to Pricing
          </Link>
          <button
            onClick={() => router.push("/dashboard?billing=cancel")}
            className="w-full rounded-lg border border-neutral-700 hover:border-neutral-500 px-4 py-2 text-sm text-neutral-300 hover:text-neutral-100 transition-colors"
          >
            Go to Dashboard
          </button>
        </div>
      </div>
    </main>
  );
}