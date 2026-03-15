"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { login } from "../../../lib/api";

const inputCls =
  "w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm text-neutral-100 outline-none placeholder:text-neutral-600 focus:border-neutral-500 transition-colors";

function isSignedIn() {
  return !!(localStorage.getItem("token") || localStorage.getItem("apiKey"));
}

export default function SignInPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const router = useRouter();

  useEffect(() => {
    setSignedIn(isSignedIn());
  }, []);

  async function handleSignIn() {
    setError("");
    if (!email.trim() || !password) return;
    setLoading(true);
    try {
      const { token } = await login(email.trim(), password);
      localStorage.setItem("token", token);
      router.push("/dashboard");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign in failed");
    } finally {
      setLoading(false);
    }
  }

  function handleClear() {
    localStorage.removeItem("token");
    localStorage.removeItem("apiKey");
    setSignedIn(false);
    setEmail("");
    setPassword("");
    setError("");
  }

  if (signedIn) {
    return (
      <main className="flex min-h-[calc(100vh-49px)] items-center justify-center px-4">
        <div className="w-full max-w-sm rounded-xl border border-neutral-800 bg-neutral-900 p-8 text-center">
          <p className="mb-1 text-sm font-medium text-emerald-400">
            You are signed in
          </p>
          <p className="mb-6 text-xs text-neutral-500">
            Credentials are saved in your browser.
          </p>
          <div className="flex flex-col gap-3">
            <Link
              href="/dashboard"
              className="rounded-lg bg-neutral-100 px-4 py-2 text-sm font-medium text-neutral-950 hover:bg-white transition-colors text-center"
            >
              Go to Dashboard
            </Link>
            <button
              onClick={handleClear}
              className="text-xs text-neutral-500 hover:text-neutral-300 transition-colors"
            >
              Sign out
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="flex min-h-[calc(100vh-49px)] items-center justify-center px-4">
      <div className="w-full max-w-sm rounded-xl border border-neutral-800 bg-neutral-900 p-8">
        <h1 className="mb-1 text-base font-semibold text-neutral-100">
          Sign in
        </h1>
        <p className="mb-6 text-xs text-neutral-500">
          Enter your email and password to continue.
        </p>
        <div className="flex flex-col gap-4">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSignIn()}
            placeholder="Email"
            autoFocus
            className={inputCls}
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSignIn()}
            placeholder="Password"
            className={inputCls}
          />
          {error && (
            <p className="text-xs text-red-400">{error}</p>
          )}
          <button
            onClick={handleSignIn}
            disabled={loading || !email.trim() || !password}
            className="rounded-lg bg-neutral-100 px-4 py-2 text-sm font-medium text-neutral-950 hover:bg-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading ? "Signing in…" : "Sign In"}
          </button>
          <button
            onClick={handleClear}
            className="text-xs text-neutral-500 hover:text-neutral-300 transition-colors"
          >
            Clear saved credentials
          </button>
        </div>
      </div>
    </main>
  );
}
