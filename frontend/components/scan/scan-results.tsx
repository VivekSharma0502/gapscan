"use client";

import { TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { useAuth } from "@/components/auth/auth-provider";
import { CombinedFindings } from "@/components/combined/combined-findings";
import { FindingCard } from "@/components/scan/finding-card";
import { ScoreGauge } from "@/components/scan/score-gauge";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { useStartScan } from "@/hooks/use-start-scan";
import type { BotProtectionHelp, Finding, Platform, Scan } from "@/lib/api";
import { PRODUCT_NAME } from "@/lib/product";
import { SEVERITIES, SEVERITY_STYLES } from "@/lib/severity";
import { cn } from "@/lib/utils";

function counted(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

// Findings arrive most severe first, so if every finding shown is info-level, any
// hidden from the teaser are too.
function hasOnlyNotes(scan: Scan): boolean {
  return (
    scan.findings.length > 0 &&
    scan.findings.every((finding) => finding.severity === "info")
  );
}

function findingsSummary(scan: Scan): string {
  const checks = {
    full: "The full scan",
    quick: "Passive checks",
    backends: "The backend check",
  }[scan.mode];
  if (scan.total_findings === 0) return `${checks} found no issues.`;
  if (hasOnlyNotes(scan)) {
    return `No issues found · ${counted(scan.total_findings, "note")}`;
  }
  return `${checks} found ${counted(scan.total_findings, "issue")}.`;
}

// A check that couldn't run isn't a pass, so a full scan says which reasons applied.
function ActiveChecksNotice({ scan }: { scan: Scan }) {
  const reasons = [
    ...new Set(
      scan.skipped
        .filter(
          (item) =>
            item.check_id.startsWith("exposure.") && !item.not_applicable,
        )
        .map((item) => item.reason),
    ),
  ];
  if (scan.mode !== "full" || reasons.length === 0) return null;

  return (
    <section className="flex flex-col gap-2 rounded-xl bg-card p-6 ring-1 ring-foreground/10">
      <h2 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
        <TriangleAlert className="size-4 text-muted-foreground" aria-hidden />
        Some file exposure checks didn&apos;t finish
      </h2>
      {reasons.map((reason) => (
        <p key={reason} className="text-sm text-pretty text-muted-foreground">
          {reason}
        </p>
      ))}
    </section>
  );
}

function BotProtectionNotice({ help }: { help: BotProtectionHelp }) {
  const bot = `${PRODUCT_NAME.replace(" ", "")}Bot`;

  return (
    <section className="flex flex-col items-start gap-2 rounded-xl bg-card p-6 ring-1 ring-foreground/10">
      <h2 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
        <TriangleAlert className="size-4 text-muted-foreground" aria-hidden />
        {help.name}&apos;s bot protection stopped this scan
      </h2>
      <p className="text-sm text-pretty text-muted-foreground">
        We don&apos;t try to get past it, because that&apos;s your site&apos;s
        choice. To let scans through, add a firewall rule that allows requests
        whose user agent contains {bot}, then scan again.
      </p>
      <a
        href={help.help_url}
        target="_blank"
        rel="noreferrer"
        className="text-sm underline underline-offset-4"
      >
        How to allow {bot} on {help.name}
      </a>
    </section>
  );
}

function BackendCheckSummary({ scan }: { scan: Scan }) {
  const unanswered = [...new Set(scan.skipped.map((item) => item.reason))];

  return (
    <section className="flex flex-col gap-3 rounded-xl bg-card p-6 ring-1 ring-foreground/10">
      <p className="text-sm text-muted-foreground">Backend check for</p>
      <h1 className="text-2xl font-semibold tracking-tight wrap-anywhere">
        {scan.target}
      </h1>
      <p className="text-sm">{findingsSummary(scan)}</p>
      {unanswered.map((reason) => (
        <p key={reason} className="text-sm text-pretty text-muted-foreground">
          {reason}
        </p>
      ))}
      <p className="text-sm text-pretty text-muted-foreground">
        This only contacted the backends you confirmed, so it doesn&apos;t
        change your site&apos;s security score.
      </p>
      {scan.verification_note && (
        <aside
          role="note"
          className="flex gap-3 rounded-lg border border-severity-medium/40 bg-severity-medium/10 p-3 text-sm"
        >
          <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
          <p className="text-pretty">{scan.verification_note}</p>
        </aside>
      )}
    </section>
  );
}

function ScoreSummary({ scan }: { scan: Scan }) {
  const { score, grade, target } = scan;

  if (scan.mode === "backends" && scan.result_status !== "incomplete") {
    return <BackendCheckSummary scan={scan} />;
  }

  // The API sends no grade when too little could be checked to give an honest one.
  if (grade === null) {
    return (
      <section className="flex flex-col gap-3 rounded-xl bg-card p-6 ring-1 ring-foreground/10">
        <TriangleAlert className="size-5 text-muted-foreground" aria-hidden />
        <h1 className="text-2xl font-semibold tracking-tight wrap-anywhere">
          We couldn&apos;t fully check {target}
        </h1>
        {scan.incomplete_reason && (
          <p className="text-sm text-pretty">{scan.incomplete_reason}</p>
        )}
        <p className="text-sm text-muted-foreground">
          There is no score, because a grade based on so little would be
          misleading.
        </p>
      </section>
    );
  }

  return (
    <section className="flex flex-col items-center gap-6 rounded-xl bg-card p-6 ring-1 ring-foreground/10 sm:flex-row sm:gap-8">
      <div className="flex w-44 shrink-0 flex-col items-center gap-1">
        <ScoreGauge score={score} grade={grade} />
        {scan.grade_cap_reason && (
          <p className="text-center text-xs text-pretty text-muted-foreground">
            {scan.grade_cap_reason}
          </p>
        )}
      </div>
      <div className="flex w-full min-w-0 flex-col items-center gap-2 text-center sm:items-start sm:text-left">
        <p className="text-sm text-muted-foreground">
          {score === null ? "Security grade for" : "Security score for"}
        </p>
        <h1 className="max-w-full text-2xl font-semibold tracking-tight wrap-anywhere">
          {target}
        </h1>
        {scan.score_label && <Badge variant="outline">{scan.score_label}</Badge>}
        {scan.correlation_note && (
          <p className="text-sm text-pretty text-muted-foreground">
            {scan.correlation_note}
          </p>
        )}
        {scan.incomplete_reason && (
          <p className="text-sm text-pretty">{scan.incomplete_reason}</p>
        )}
        <p className="text-sm text-muted-foreground">{findingsSummary(scan)}</p>
      </div>
    </section>
  );
}

function FindingGroups({ findings }: { findings: Finding[] }) {
  // Held here so choosing a platform once applies to every finding.
  const [platform, setPlatform] = useState<Platform>("vercel");

  return (
    <div className="flex flex-col gap-8">
      {SEVERITIES.map((severity) => {
        const group = findings.filter((item) => item.severity === severity);
        if (group.length === 0) return null;
        const style = SEVERITY_STYLES[severity];

        return (
          <section key={severity} className="flex flex-col gap-3">
            <h3>
              <Badge
                variant="outline"
                className={cn("text-foreground", style.badge)}
              >
                <span
                  className={cn("size-1.5 rounded-full", style.dot)}
                  aria-hidden
                />
                {style.label}
                <span className="text-muted-foreground tabular-nums">
                  {group.length}
                </span>
              </Badge>
            </h3>
            {group.map((finding) => (
              <FindingCard
                key={finding.check_id}
                finding={finding}
                platform={platform}
                onPlatformChange={setPlatform}
              />
            ))}
          </section>
        );
      })}
    </div>
  );
}

const teaserPanel =
  "flex flex-col items-start gap-3 rounded-xl bg-card p-6 ring-1 ring-foreground/10";

function SignupTeaser({
  scanId,
  hidden,
  noun,
}: {
  scanId: string;
  hidden: number;
  noun: string;
}) {
  const next = encodeURIComponent(`/scan/${scanId}`);

  return (
    <section className={teaserPanel}>
      <h2 className="text-lg font-semibold tracking-tight">
        {hidden > 0
          ? `Sign up to see the other ${counted(hidden, noun)}`
          : "Sign up to keep this report"}
      </h2>
      <p className="text-sm text-pretty text-muted-foreground">
        The full report lists every finding with its fix. With an account you
        can also verify domains you own and run deeper checks.
      </p>
      <Link href={`/login?next=${next}`} className={buttonVariants()}>
        Sign up for the full report
      </Link>
    </section>
  );
}

// For someone signed in who opened another person's scan link. Scanning the site themselves
// gets them their own report.
function ScanItYourself({ target }: { target: string }) {
  const startScan = useStartScan();
  const busy = startScan.isPending;

  return (
    <section className={teaserPanel}>
      <h2 className="text-lg font-semibold tracking-tight">
        This report belongs to someone else
      </h2>
      <p className="text-sm text-pretty text-muted-foreground">
        Scan {target} yourself to get the full report with every finding and
        its fix.
      </p>
      <Button onClick={() => startScan.mutate(target)} disabled={busy}>
        {busy ? "Starting…" : "Scan this site"}
      </Button>
      {startScan.error && (
        <p role="alert" className="text-sm text-destructive">
          {startScan.error.message}
        </p>
      )}
    </section>
  );
}

export function ScanResults({ scan }: { scan: Scan }) {
  const shown = scan.findings.length;
  const hidden = scan.total_findings - shown;
  const { user } = useAuth();

  return (
    <div className="flex animate-in flex-col gap-10 duration-300 fade-in">
      <ScoreSummary scan={scan} />
      {scan.bot_protection && (
        <BotProtectionNotice help={scan.bot_protection} />
      )}
      <ActiveChecksNotice scan={scan} />
      {scan.domain_id && user && (
        <CombinedFindings scope={{ domainId: scan.domain_id }} />
      )}

      {shown > 0 && (
        <section
          aria-labelledby="findings-heading"
          className="flex flex-col gap-4"
        >
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
            <h2
              id="findings-heading"
              className="text-lg font-semibold tracking-tight"
            >
              Findings
            </h2>
            {hidden > 0 && (
              <p className="text-sm text-muted-foreground">
                Showing the top {shown} of {scan.total_findings}
              </p>
            )}
          </div>
          <FindingGroups findings={scan.findings} />
        </section>
      )}

      {scan.teaser &&
        (user ? (
          <ScanItYourself target={scan.target} />
        ) : (
          <SignupTeaser
            scanId={scan.id}
            hidden={hidden}
            noun={hasOnlyNotes(scan) ? "note" : "issue"}
          />
        ))}
    </div>
  );
}
