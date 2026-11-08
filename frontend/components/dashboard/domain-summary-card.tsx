"use client";

import {
  BadgeCheck,
  CircleDashed,
  LoaderCircle,
  Minus,
  TrendingDown,
  TrendingUp,
} from "lucide-react";
import Link from "next/link";

import { ScanHistory } from "@/components/dashboard/scan-history";
import { ScoreHistory } from "@/components/dashboard/score-history";
import {
  RunFullScanButton,
  useFullScan,
} from "@/components/domains/run-full-scan-button";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import type { DashboardDomain, ScanSummary } from "@/lib/api";
import { gradeColor, timeAgo } from "@/lib/format";

function Trend({ change }: { change: number }) {
  const Icon = change > 0 ? TrendingUp : change < 0 ? TrendingDown : Minus;
  const text =
    change === 0
      ? "No change"
      : change > 0
        ? `Up ${change}`
        : `Down ${Math.abs(change)}`;

  return (
    <span className="flex items-center gap-1 text-xs text-muted-foreground">
      <Icon className="size-3.5" aria-hidden />
      {text} vs previous scan
    </span>
  );
}

function Grade({
  scan,
  trend,
}: {
  scan: ScanSummary;
  trend: number | null;
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <Link
        href={`/scan/${scan.id}`}
        aria-label={`Open the report, grade ${scan.grade}`}
        className="text-5xl font-semibold tracking-tight"
        style={{ color: gradeColor(scan.grade) }}
      >
        {scan.grade}
      </Link>
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="text-sm tabular-nums">
          {scan.score === null ? "No score" : `${scan.score} / 100`}
        </span>
        {trend !== null && <Trend change={trend} />}
        {scan.mode === "quick" && (
          <span className="text-xs text-pretty text-muted-foreground">
            Quick scan, verify for full checks
          </span>
        )}
        {scan.score_label && (
          <span className="text-xs text-pretty text-muted-foreground">
            {scan.score_label}
          </span>
        )}
      </div>
    </div>
  );
}

function LastScan({ scan }: { scan: ScanSummary }) {
  if (scan.status === "queued" || scan.status === "running") {
    return (
      <Link
        href={`/scan/${scan.id}`}
        className="flex items-center gap-1.5 text-xs text-muted-foreground underline-offset-2 hover:underline"
      >
        <LoaderCircle className="size-3 animate-spin" aria-hidden />
        Scan in progress
      </Link>
    );
  }
  return (
    <p className="text-xs text-muted-foreground">
      {scan.status === "failed" ? "Last scan failed" : "Last scanned"}{" "}
      {timeAgo(scan.created_at)}
    </p>
  );
}

export function DomainSummaryCard({ domain }: { domain: DashboardDomain }) {
  const scan = useFullScan(domain.id);
  const { latest, last_scan: lastScan, trend, verified } = domain;

  return (
    <article className="flex min-w-0 flex-col gap-4 rounded-xl bg-card p-5 ring-1 ring-foreground/10 sm:p-6">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="min-w-0 font-mono text-base font-medium wrap-anywhere">
          {domain.hostname}
        </h2>
        <Badge variant="outline">
          {verified ? (
            <BadgeCheck aria-hidden />
          ) : (
            <CircleDashed aria-hidden />
          )}
          {verified ? "Verified" : "Not verified"}
        </Badge>
      </header>

      {latest ? (
        <Grade scan={latest} trend={trend} />
      ) : (
        <p className="text-sm text-pretty text-muted-foreground">
          {verified
            ? "No full scans yet. Run one to get a grade."
            : "Not scanned yet. Verify this domain to run a full scan."}
        </p>
      )}
      {lastScan && <LastScan scan={lastScan} />}

      {/* Full scans only: an unverified domain has no like-for-like history to chart. */}
      {verified && latest && (
        <>
          <ScoreHistory domainId={domain.id} latestId={latest.id} />
          <ScanHistory domainId={domain.id} newestId={lastScan?.id} />
        </>
      )}

      {scan.error && (
        <p role="alert" className="text-sm text-destructive">
          {scan.error.message}
        </p>
      )}

      <footer className="flex flex-wrap items-center gap-2">
        {verified ? (
          <RunFullScanButton scan={scan} />
        ) : (
          <Link href="/domains" className={buttonVariants()}>
            Verify domain
          </Link>
        )}
      </footer>
    </article>
  );
}
