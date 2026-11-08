"use client";

import { useQuery } from "@tanstack/react-query";
import { LoaderCircle, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { ScanLog } from "@/components/scan/scan-log";
import { Button, buttonVariants } from "@/components/ui/button";
import { useStartScan } from "@/hooks/use-start-scan";
import { ApiError, getScan, type Scan } from "@/lib/api";

const POLL_MS = 1000;
const REVEAL_MS = 40;
// How long the finished log stays up, in reveal ticks, before the results replace it.
const PAUSE_TICKS = 15;

function isFinished(scan: Scan | undefined): boolean {
  return scan?.status === "done" || scan?.status === "failed";
}

// A request that was wrong won't become right by repeating it.
function isClientError(error: unknown): boolean {
  return error instanceof ApiError && error.status >= 400 && error.status < 500;
}

// Counts up to target one tick at a time. Checks finish together between two polls,
// so without this the log would jump straight from the network steps to the results.
function useRevealCount(target: number): number {
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (count >= target) return;
    const timer = setTimeout(() => setCount((value) => value + 1), REVEAL_MS);
    return () => clearTimeout(timer);
  }, [count, target]);

  return count;
}

function Notice({
  title,
  children,
  action,
}: {
  title: string;
  children: React.ReactNode;
  action: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-xl bg-card p-6 ring-1 ring-foreground/10">
      <TriangleAlert className="size-5 text-muted-foreground" aria-hidden />
      <div>
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{children}</p>
      </div>
      {action}
    </div>
  );
}

const newScanLink = (
  <Link href="/" className={buttonVariants({ variant: "outline" })}>
    Scan a site
  </Link>
);

function ScanFailed({ target }: { target: string }) {
  const startScan = useStartScan();
  const busy = startScan.isPending || startScan.isSuccess;

  return (
    <Notice
      title="This scan couldn't finish"
      action={
        <div className="flex flex-col items-start gap-2">
          <Button onClick={() => startScan.mutate(target)} disabled={busy}>
            {busy ? "Starting…" : "Scan again"}
          </Button>
          {startScan.error && (
            <p role="alert" className="text-sm text-destructive">
              {startScan.error.message}
            </p>
          )}
        </div>
      }
    >
      Something went wrong while scanning {target}. It usually works on a second
      try.
    </Notice>
  );
}

export function ScanView({ id }: { id: string }) {
  const query = useQuery({
    queryKey: ["scan", id],
    queryFn: ({ signal }) => getScan(id, signal),
    refetchInterval: ({ state }) => {
      if (isFinished(state.data)) return false;
      // A scan that never loaded isn't worth polling. A blip during a live scan is.
      if (state.data === undefined && state.status === "error") return false;
      return POLL_MS;
    },
    retry: (failures, error) => !isClientError(error) && failures < 2,
  });
  const scan = query.data;
  const finished = isFinished(scan);
  const steps = scan?.progress.steps ?? [];

  // Set while rendering, as React recommends for state derived from new props. A scan
  // that was already finished on arrival has no live log to play back.
  const [sawRunning, setSawRunning] = useState(false);
  if (scan && !finished && !sawRunning) setSawRunning(true);

  const revealed = useRevealCount(
    finished ? steps.length + PAUSE_TICKS : steps.length,
  );
  const logFinished = !sawRunning || revealed >= steps.length + PAUSE_TICKS;

  if (query.isError && !scan) {
    return isClientError(query.error) ? (
      <Notice title="Scan not found" action={newScanLink}>
        This link doesn&apos;t match a scan. It may have been mistyped.
      </Notice>
    ) : (
      <Notice
        title="We couldn't load this scan"
        action={
          <Button variant="outline" onClick={() => query.refetch()}>
            Try again
          </Button>
        }
      >
        {query.error.message}
      </Notice>
    );
  }

  if (!scan) return <ScanLoading />;

  if (!finished || !logFinished) {
    return (
      <div className="flex flex-col gap-3">
        <ScanLog
          target={scan.target}
          steps={steps.slice(0, revealed)}
          total={scan.progress.total}
        />
        {query.isRefetchError && (
          <p role="status" className="text-sm text-muted-foreground">
            Lost contact with the scanner. Still trying…
          </p>
        )}
      </div>
    );
  }

  if (scan.status === "failed") return <ScanFailed target={scan.target} />;

  return <p>Score: {scan.score ?? "none"}</p>;
}

export function ScanLoading() {
  return (
    <div
      role="status"
      className="flex items-center gap-2 text-sm text-muted-foreground"
    >
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      Loading scan…
    </div>
  );
}
