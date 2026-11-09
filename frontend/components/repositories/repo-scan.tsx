"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle, ScanSearch } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  startRepoScan,
  type RepoLatestScan,
  type SeverityCounts,
} from "@/lib/api";
import { timeAgo } from "@/lib/format";
import { SEVERITIES, SEVERITY_STYLES } from "@/lib/severity";

export const REPO_POLL_MS = 3_000;

export function isScanning(scan: RepoLatestScan | null): boolean {
  return scan?.status === "queued" || scan?.status === "running";
}

export function ScanNowButton({
  repoId,
  scanning,
  variant,
}: {
  repoId: string;
  scanning: boolean;
  variant?: "outline";
}) {
  const queryClient = useQueryClient();
  const scan = useMutation({
    mutationFn: () => startRepoScan(repoId),
    // Also after a failure, because a refusal can mean the repo's state has changed.
    onSettled: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: ["repos"] }),
        queryClient.invalidateQueries({ queryKey: ["repo-findings", repoId] }),
      ]),
  });
  const busy = scan.isPending || scanning;

  return (
    <div className="flex flex-col items-start gap-1.5">
      <Button
        variant={variant}
        size="sm"
        disabled={busy}
        onClick={() => scan.mutate()}
      >
        {busy ? (
          <LoaderCircle className="animate-spin" aria-hidden />
        ) : (
          <ScanSearch aria-hidden />
        )}
        {busy ? "Scanning…" : "Scan now"}
      </Button>
      {scan.isError && (
        <p role="alert" className="text-xs text-destructive">
          {scan.error.message}
        </p>
      )}
    </div>
  );
}

export function RepoScanStatus({ scan }: { scan: RepoLatestScan | null }) {
  if (scan === null) {
    return <span className="text-muted-foreground">Not scanned yet</span>;
  }
  if (isScanning(scan)) {
    return (
      <span role="status" className="text-muted-foreground">
        Scanning this repository…
      </span>
    );
  }
  if (scan.status === "failed") {
    return (
      <span className="text-destructive">
        {scan.incomplete_reason ?? "The last scan didn't finish."}
      </span>
    );
  }
  if (scan.result_status !== "complete" && scan.incomplete_reason) {
    return <span className="text-destructive">{scan.incomplete_reason}</span>;
  }
  return (
    <span className="text-muted-foreground">
      Scanned {timeAgo(scan.finished_at ?? scan.created_at)}
    </span>
  );
}

export function SeverityChips({ counts }: { counts: SeverityCounts }) {
  const present = SEVERITIES.filter((severity) => counts[severity] > 0);
  if (present.length === 0) return null;

  return (
    <ul className="flex flex-wrap gap-1.5">
      {present.map((severity) => {
        const style = SEVERITY_STYLES[severity];
        return (
          <li
            key={severity}
            className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs ${style.badge}`}
          >
            <span
              className={`size-1.5 rounded-full ${style.dot}`}
              aria-hidden
            />
            {counts[severity]} {style.label.toLowerCase()}
          </li>
        );
      })}
    </ul>
  );
}
