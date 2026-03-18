import type { Metadata } from "next";
import Link from "next/link";
import ApiKeyControl from "../../components/ApiKeyControl";
import NavAuthControl from "../../components/NavAuthControl";
import UsageBanner from "../../components/UsageBanner";
import "./globals.css";

export const metadata: Metadata = {
  title: "PromptSentinel · LLM Security Testing",
  description:
    "PromptSentinel simulates prompt-injection attacks against LLM system prompts and surfaces leakage and override risk.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-neutral-950 text-neutral-100 antialiased">
        <header className="border-b border-neutral-800 px-6 py-3 flex items-center gap-6">
          <span className="text-sm font-semibold tracking-wide text-neutral-100">
            PromptSentinel
          </span>
          <nav className="flex gap-4 text-sm">
            <Link
              href="/"
              className="text-neutral-400 hover:text-neutral-100 transition-colors"
            >
              Testing
            </Link>
            <Link
              href="/dashboard"
              className="text-neutral-400 hover:text-neutral-100 transition-colors"
            >
              Dashboard
            </Link>
            <Link
              href="/diff"
              className="text-neutral-400 hover:text-neutral-100 transition-colors"
            >
              Diff
            </Link>
            <Link
              href="/pricing"
              className="text-neutral-400 hover:text-neutral-100 transition-colors"
            >
              Pricing
            </Link>
            <Link
              href="/trust"
              className="text-neutral-400 hover:text-neutral-100 transition-colors"
            >
              Trust
            </Link>
            <Link
              href="/admin"
              className="text-neutral-400 hover:text-neutral-100 transition-colors"
            >
              Admin
            </Link>
            <NavAuthControl />
          </nav>
          <ApiKeyControl />
        </header>
        <UsageBanner />
        {process.env.NEXT_PUBLIC_DEMO_MODE === "1" && (
          <div className="bg-amber-500/10 border-b border-amber-500/30 px-4 py-2 text-center text-xs text-amber-400">
            <span className="font-semibold">Demo Mode</span>
            {" — "}Read-only preview. Campaign creation, sign-up, and billing are disabled.
            {" "}
            <a
              href="https://github.com/your-org/promptsentinel"
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-2 hover:text-amber-300 transition-colors"
            >
              Deploy your own instance →
            </a>
          </div>
        )}
        {children}
      </body>
    </html>
  );
}
