"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { FolderGit2, Lock, LoaderCircle } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "@/components/auth/auth-provider";
import {
  isScanning,
  REPO_POLL_MS,
  RepoScanStatus,
  ScanNowButton,
  SeverityChips,
} from "@/components/repositories/repo-scan";
import { Button, buttonVariants } from "@/components/ui/button";
import { getGithubInstallUrl, listRepos, type Repo } from "@/lib/api";

function Loading() {
  return (
    <div
      role="status"
      className="flex items-center gap-2 text-sm text-muted-foreground"
    >
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      Loading your repositories…
    </div>
  );
}

function ConnectButton({ hasRepos }: { hasRepos: boolean }) {
  const connect = useMutation({
    mutationFn: getGithubInstallUrl,
    onSuccess({ url }) {
      window.location.assign(url);
    },
  });

  return (
    <div className="flex flex-col items-start gap-2">
      <Button
        variant={hasRepos ? "outline" : undefined}
        onClick={() => connect.mutate()}
        disabled={connect.isPending}
      >
        {connect.isPending && (
          <LoaderCircle className="animate-spin" aria-hidden />
        )}
        {hasRepos ? "Add or remove repositories" : "Connect GitHub"}
      </Button>
      {connect.isError && (
        <p role="alert" className="text-sm text-destructive">
          {connect.error.message}
        </p>
      )}
    </div>
  );
}

function RepoCard({ repo }: { repo: Repo }) {
  return (
    <li className="flex flex-col gap-3 rounded-xl bg-card p-4 ring-1 ring-foreground/10 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex min-w-0 flex-col gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <FolderGit2
            className="size-4 shrink-0 text-muted-foreground"
            aria-hidden
          />
          <Link
            href={`/repositories/${repo.id}`}
            className="min-w-0 truncate font-mono text-sm font-medium hover:underline"
          >
            {repo.full_name}
          </Link>
          {repo.is_private && (
            <Lock
              className="size-3.5 shrink-0 text-muted-foreground"
              aria-label="Private repository"
            />
          )}
        </div>
        <p className="text-xs">
          <RepoScanStatus scan={repo.latest_scan} />
        </p>
        <SeverityChips counts={repo.counts} />
      </div>
      <div className="flex shrink-0 items-start gap-2">
        <Link
          href={`/repositories/${repo.id}`}
          className={buttonVariants({ variant: "ghost", size: "sm" })}
        >
          View findings
        </Link>
        <ScanNowButton
          repoId={repo.id}
          scanning={isScanning(repo.latest_scan)}
          variant="outline"
        />
      </div>
    </li>
  );
}

export function RepositoriesView() {
  const router = useRouter();
  const { user, loading } = useAuth();
  const signedIn = Boolean(user);

  useEffect(() => {
    if (!loading && !signedIn) router.replace("/login?next=/repositories");
  }, [loading, signedIn, router]);

  const repos = useQuery({
    queryKey: ["repos"],
    queryFn: ({ signal }) => listRepos(signal),
    enabled: signedIn,
    // Only while a scan is running, so an idle page sends no traffic.
    refetchInterval: (query) =>
      query.state.data?.some((repo) => isScanning(repo.latest_scan))
        ? REPO_POLL_MS
        : false,
  });

  if (!signedIn) return <Loading />;

  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Repositories</h1>
        <p className="text-sm text-pretty text-muted-foreground">
          Connect GitHub to check your repositories for leaked keys and
          passwords, including ones buried in old commits. New pushes are
          checked automatically.
        </p>
      </div>

      {repos.isPending && <Loading />}
      {repos.isError && (
        <div className="flex flex-col items-start gap-2">
          <p role="alert" className="text-sm text-destructive">
            {repos.error.message}
          </p>
          <Button variant="outline" onClick={() => repos.refetch()}>
            Try again
          </Button>
        </div>
      )}

      {repos.data && (
        <>
          <ConnectButton hasRepos={repos.data.length > 0} />
          {repos.data.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              You haven&apos;t connected any repositories yet.
            </p>
          ) : (
            <ul className="flex flex-col gap-3">
              {repos.data.map((repo) => (
                <RepoCard key={repo.id} repo={repo} />
              ))}
            </ul>
          )}
        </>
      )}
    </>
  );
}
