"use client";

import { useEffect } from "react";

interface ErrorPageProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function ErrorBoundary({ error, reset }: ErrorPageProps) {
  useEffect(() => {
    // Log to console for debugging; swap for a real error tracking service in prod
    console.error("[PromptSentinel] Unhandled error:", error);
  }, [error]);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-6 bg-neutral-950 px-6 text-center">
      <div className="space-y-2">
        <h1 className="text-xl font-semibold text-neutral-100">Something went wrong</h1>
        <p className="max-w-sm text-sm text-neutral-400">
          An unexpected error occurred. If the problem persists, try refreshing the page.
        </p>
        {error.digest && (
          <p className="text-xs text-neutral-600">Error ID: {error.digest}</p>
        )}
      </div>
      <button
        onClick={reset}
        className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500 active:bg-indigo-700"
      >
        Try again
      </button>
    </main>
  );
}
