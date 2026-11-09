"use client";

import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  CircleCheck,
  LoaderCircle,
  Lock,
  TriangleAlert,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "@/components/auth/auth-provider";
import { RepoFindingCard } from "@/components/repositories/repo-finding-card";
import {
  isScanning,
  REPO_POLL_MS,
  RepoScanStatus,
  ScanNowButton,
  SeverityChips,
} from "@/components/repositories/repo-scan";
import { Button } from "@/components/ui/button";
import { getRepoFindings, type RepoFindings } from "@/lib/api";
import { SEVERITIES, SEVERITY_STYLES } from "@/lib/severity";

export function RepoFindingsLoading() {
  return (
    <div
      role="status"
      className="flex items-center gap-2 text-sm text-muted-foreground"
    >
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      Loading findings…
    </div>
  );
}

function Empty({ data }: { data: RepoFindings }) {
  const scan = data.latest_scan;
  // Security: only a finished, complete scan may say the repo is clean. A scan that hit a
  // limit or failed has looked at less, and "no findings" would give false reassurance.
  if (scan?.status === "done" && scan.result_status === "complete") {
    return (
      <p className="flex items-center gap-2 text-sm">
        <CircleCheck className="size-4 text-good" aria-hidden />
        No secrets found in this repository&apos;s history.
      </p>
    );
  }
  if (scan === null) {
    return (
      <p className="text-sm text-muted-foreground">
        This repository hasn&apos;t been scanned yet. Scan now to check its
        whole history.
      </p>
    );
  }
  return null;
}

function Findings({ data }: { data: RepoFindings }) {
  return (
    <>
      <aside
        role="note"
        className="flex gap-3 rounded-xl border border-severity-high/40 bg-severity-high/10 p-4 text-sm"
      >
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
        <p className="text-pretty">{data.history_warning}</p>
      </aside>
      {SEVERITIES.map((severity) => {
        const group = data.findings.filter(
          (finding) => finding.severity === severity,
        );
        if (group.length === 0) return null;
        const style = SEVERITY_STYLES[severity];
        return (
          <section key={severity} className="flex flex-col gap-3">
            <h2 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
              <span
                className={`size-2.5 rounded-full ${style.dot}`}
                aria-hidden
              />
              {style.label}
              <span className="text-sm font-normal text-muted-foreground">
                {group.length}
              </span>
            </h2>
            {group.map((finding) => (
              <RepoFindingCard key={finding.id} finding={finding} />
            ))}
          </section>
        );
      })}
    </>
  );
}

export function RepoFindingsView({ id }: { id: string }) {
  const router = useRouter();
  const { user, loading } = useAuth();
  const signedIn = Boolean(user);

  useEffect(() => {
    if (!loading && !signedIn) {
      const next = `/repositories/${encodeURIComponent(id)}`;
      router.replace(`/login?next=${encodeURIComponent(next)}`);
    }
  }, [loading, signedIn, id, router]);

  const findings = useQuery({
    queryKey: ["repo-findings", id],
    queryFn: ({ signal }) => getRepoFindings(id, signal),
    enabled: signedIn,
    // Only while a scan is running, so an idle page sends no traffic.
    refetchInterval: (query) =>
      isScanning(query.state.data?.latest_scan ?? null) ? REPO_POLL_MS : false,
  });

  if (!signedIn || findings.isPending) return <RepoFindingsLoading />;

  if (findings.isError) {
    return (
      <div className="flex flex-col items-start gap-2">
        <p role="alert" className="text-sm text-destructive">
          {findings.error.message}
        </p>
        <Button variant="outline" onClick={() => findings.refetch()}>
          Try again
        </Button>
      </div>
    );
  }

  const { data } = findings;
  const scanning = isScanning(data.latest_scan);

  return (
    <>
      <div className="flex flex-col gap-3">
        <Link
          href="/repositories"
          className="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-3.5" aria-hidden />
          Repositories
        </Link>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 flex-col gap-2">
            <h1 className="flex min-w-0 items-center gap-2 text-2xl font-semibold tracking-tight">
              <span className="min-w-0 break-all">{data.full_name}</span>
              {data.is_private && (
                <Lock
                  className="size-4 shrink-0 text-muted-foreground"
                  aria-label="Private repository"
                />
              )}
            </h1>
            <p className="text-sm">
              <RepoScanStatus scan={data.latest_scan} />
            </p>
            <SeverityChips counts={data.counts} />
          </div>
          <ScanNowButton repoId={data.id} scanning={scanning} />
        </div>
      </div>

      {data.findings.length > 0 ? (
        <Findings data={data} />
      ) : (
        !scanning && <Empty data={data} />
      )}
    </>
  );
}
