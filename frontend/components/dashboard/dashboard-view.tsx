"use client";

import { useQuery } from "@tanstack/react-query";
import { Globe, LoaderCircle } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "@/components/auth/auth-provider";
import { DomainSummaryCard } from "@/components/dashboard/domain-summary-card";
import { ScanRow } from "@/components/dashboard/scan-row";
import { Button, buttonVariants } from "@/components/ui/button";
import { getDashboard, type Dashboard, type ScanSummary } from "@/lib/api";

const POLL_MS = 5_000;

function inProgress(scan: ScanSummary | null): boolean {
  return scan?.status === "queued" || scan?.status === "running";
}

function hasScanInProgress(data: Dashboard | undefined): boolean {
  if (!data) return false;
  return (
    data.recent_scans.some(inProgress) ||
    data.domains.some((domain) => inProgress(domain.last_scan))
  );
}

function Loading() {
  return (
    <div
      role="status"
      className="flex items-center gap-2 text-sm text-muted-foreground"
    >
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      Loading your dashboard…
    </div>
  );
}

function NoDomains() {
  return (
    <section className="flex flex-col items-start gap-3 rounded-xl border border-dashed p-6">
      <Globe className="size-5 text-muted-foreground" aria-hidden />
      <div>
        <h2 className="text-base font-medium">No domains yet</h2>
        <p className="mt-1 text-sm text-pretty text-muted-foreground">
          Add a domain you own to track its security grade over time and unlock
          full scans.
        </p>
      </div>
      <Link href="/domains" className={buttonVariants()}>
        Add your first domain
      </Link>
    </section>
  );
}

function RecentScans({ scans }: { scans: ScanSummary[] }) {
  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-lg font-semibold tracking-tight">Recent scans</h2>
      {scans.length === 0 ? (
        <div className="flex flex-col items-start gap-3">
          <p className="text-sm text-muted-foreground">
            You haven&apos;t run any scans yet.
          </p>
          <Link href="/" className={buttonVariants({ variant: "outline" })}>
            Scan a site
          </Link>
        </div>
      ) : (
        <ul className="divide-y rounded-xl bg-card px-2 ring-1 ring-foreground/10 sm:px-3">
          {scans.map((scan) => (
            <ScanRow key={scan.id} scan={scan} showTarget />
          ))}
        </ul>
      )}
    </section>
  );
}

export function DashboardView() {
  const router = useRouter();
  const { user, loading } = useAuth();
  const signedIn = Boolean(user);

  useEffect(() => {
    if (!loading && !signedIn) router.replace("/login?next=/dashboard");
  }, [loading, signedIn, router]);

  const dashboard = useQuery({
    queryKey: ["dashboard"],
    queryFn: ({ signal }) => getDashboard(signal),
    enabled: signedIn,
    // Only while something is running, so an idle page sends no traffic.
    refetchInterval: (query) =>
      hasScanInProgress(query.state.data) ? POLL_MS : false,
  });

  if (!signedIn) return <Loading />;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-pretty text-muted-foreground">
            How your domains are doing, and what you&apos;ve scanned lately.
          </p>
        </div>
        {dashboard.data && dashboard.data.domains.length > 0 && (
          <Link
            href="/domains"
            className={buttonVariants({ variant: "outline" })}
          >
            Manage domains
          </Link>
        )}
      </div>

      {dashboard.isPending && <Loading />}
      {dashboard.isError && (
        <div className="flex flex-col items-start gap-2">
          <p role="alert" className="text-sm text-destructive">
            {dashboard.error.message}
          </p>
          <Button variant="outline" onClick={() => dashboard.refetch()}>
            Try again
          </Button>
        </div>
      )}

      {dashboard.data && (
        <>
          {dashboard.data.domains.length === 0 ? (
            <NoDomains />
          ) : (
            <div className="grid items-start gap-4 md:grid-cols-2">
              {dashboard.data.domains.map((domain) => (
                <DomainSummaryCard key={domain.id} domain={domain} />
              ))}
            </div>
          )}
          <RecentScans scans={dashboard.data.recent_scans} />
        </>
      )}
    </>
  );
}
