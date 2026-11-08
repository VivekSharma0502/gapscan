"use client";

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";

type ApiStatus = "checking" | "ok" | "unreachable";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TIMEOUT_MS = 5000;

const STATUS_TEXT: Record<ApiStatus, string> = {
  checking: "Checking…",
  ok: "OK",
  unreachable: "Unreachable",
};

export default function Home() {
  const [status, setStatus] = useState<ApiStatus>("checking");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    async function checkHealth() {
      let next: ApiStatus = "unreachable";
      try {
        const response = await fetch(`${API_URL}/api/health`, {
          signal: controller.signal,
        });
        const body = (await response.json()) as { status?: unknown };
        if (response.ok && body.status === "ok") next = "ok";
      } catch {
        // Network error, CORS block, timeout or bad JSON: all "unreachable".
      }
      clearTimeout(timeout);
      if (!cancelled) setStatus(next);
    }

    checkHealth();

    return () => {
      cancelled = true;
      clearTimeout(timeout);
      controller.abort();
    };
  }, [attempt]);

  function retry() {
    setStatus("checking");
    setAttempt((current) => current + 1);
  }

  return (
    <main className="flex flex-1 flex-col items-center justify-center gap-4 p-8">
      <h1 className="text-3xl font-semibold tracking-tight">ScanKit</h1>
      <p aria-live="polite" className="text-lg">
        API status: <strong>{STATUS_TEXT[status]}</strong>
      </p>
      {status === "unreachable" && <Button onClick={retry}>Try again</Button>}
    </main>
  );
}
