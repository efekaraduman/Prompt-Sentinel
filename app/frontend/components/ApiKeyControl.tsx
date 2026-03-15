"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";

export default function ApiKeyControl() {
  const [value, setValue] = useState("");
  const [isSet, setIsSet] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    const stored = localStorage.getItem("apiKey") ?? "";
    setValue(stored);
    setIsSet(!!stored);
  }, []);

  // Hide on the login page for a clean UI
  if (pathname === "/login") return null;

  function handleSave() {
    const trimmed = value.trim();
    localStorage.setItem("apiKey", trimmed);
    setIsSet(!!trimmed);
  }

  function handleLogout() {
    if (!confirm("Log out?")) return;
    localStorage.removeItem("apiKey");
    setValue("");
    setIsSet(false);
  }

  return (
    <div className="ml-auto flex items-center gap-2">
      <span className="text-[11px] text-neutral-500">Session</span>
      <input
        type="password"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && handleSave()}
        placeholder="API key"
        className="w-32 rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs text-neutral-100 outline-none placeholder:text-neutral-600 focus:border-neutral-500"
      />
      <button
        onClick={handleSave}
        className="rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-300 transition-colors hover:border-neutral-500 hover:text-neutral-100"
      >
        Save
      </button>
      {isSet && (
        <button
          onClick={handleLogout}
          className="rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-400 transition-colors hover:border-red-700 hover:text-red-400"
        >
          Logout
        </button>
      )}
      <span className={`text-[11px] ${isSet ? "text-emerald-500" : "text-neutral-500"}`}>
        {isSet ? "Logged in" : "Not logged in"}
      </span>
    </div>
  );
}
