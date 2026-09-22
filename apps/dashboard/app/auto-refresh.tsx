"use client";

import { useEffect, useState, useTransition } from "react";
import { useRouter } from "next/navigation";

export function AutoRefresh({ checkedAt }: { checkedAt?: string }) {
  const router = useRouter();
  const [now, setNow] = useState<number | null>(null);
  const [pending, startTransition] = useTransition();

  useEffect(() => {
    const clock = setInterval(() => setNow(Date.now()), 1_000);
    return () => clearInterval(clock);
  }, []);

  useEffect(() => {
    const refresh = () => {
      if (!pending && document.visibilityState === "visible") {
        startTransition(() => router.refresh());
      }
    };
    const timer = setInterval(refresh, 10_000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [pending, router]);

  const observed = checkedAt ? Date.parse(checkedAt) : NaN;
  const stale = now !== null && (!Number.isFinite(observed) || now - observed > 30_000 || observed - now > 5_000);
  return (
    <p role="status" className={`mb-5 text-sm ${stale ? "text-amber-200" : "text-zinc-400"}`}>
      {stale
        ? "Monitoring data is stale or unavailable. Current network readiness is unknown."
        : "Monitoring refreshes every 10 seconds while this tab is visible."}
    </p>
  );
}
