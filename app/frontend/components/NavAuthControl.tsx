"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

const linkCls = "text-neutral-400 hover:text-neutral-100 transition-colors";

function isSignedIn() {
  return !!(localStorage.getItem("token") || localStorage.getItem("apiKey"));
}

export default function NavAuthControl() {
  const [isSet, setIsSet] = useState(false);
  const router = useRouter();

  useEffect(() => {
    setIsSet(isSignedIn());
  }, []);

  function handleSignOut() {
    localStorage.removeItem("token");
    localStorage.removeItem("apiKey");
    setIsSet(false);
    router.push("/login");
  }

  if (isSet) {
    return (
      <button onClick={handleSignOut} className={linkCls}>
        Sign Out
      </button>
    );
  }

  return (
    <Link href="/login" className={linkCls}>
      Sign In
    </Link>
  );
}
