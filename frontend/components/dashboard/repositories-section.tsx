"use client";

import { useQuery } from "@tanstack/react-query";
import { FolderGit2 } from "lucide-react";
import Link from "next/link";

import {
  isScanning,
  REPO_POLL_MS,
  RepoScanStatus,
  SeverityChips,
} from "@/components/repositories/repo-scan";
import { buttonVariants } from "@/components/ui/button";
import { listRepos, type Repo } from "@/lib/api";

const SHOWN_REPOS = 5;

// Repos with the most serious findings are the ones worth seeing first.
function urgency(repo: Repo): number[] {
  const { critical, high, medium, low, info } = repo.counts;
  return [critical, high, medium, low, info];
}

function byUrgency(a: Repo, b: Repo): number {
  const [left, right] = [urgency(a), urgency(b)];
  const difference = left.findIndex((count, index) => count !== right[index]);
  return difference === -1 ? 0 : right[difference] - left[difference];
}

function NoRepos() {
  return (
    <div className="flex flex-col items-start gap-3 rounded-xl border border-dashed p-6">
      <FolderGit2 className="size-5 text-muted-foreground" aria-hidden />
      <p className="text-sm text-pretty text-muted-foreground">
        Connect GitHub to check your repositories for leaked keys and passwords.
      </p>
      <Link
        href="/repositories"
        className={buttonVariants({ variant: "outline" })}
      >
        Connect GitHub
      </Link>
    </div>
  );
}

export function RepositoriesSection() {
  const repos = useQuery({
    queryKey: ["repos"],
    queryFn: ({ signal }) => listRepos(signal),
    refetchInterval: (query) =>
      query.state.data?.some((repo) => isScanning(repo.latest_scan))
        ? REPO_POLL_MS
        : false,
  });

  // The dashboard has its own loading state, so this one just waits to appear.
  if (repos.isPending) return null;

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-lg font-semibold tracking-tight">Repositories</h2>
        {repos.data && repos.data.length > 0 && (
          <Link
            href="/repositories"
            className="text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground"
          >
            View all
          </Link>
        )}
      </div>

      {repos.isError && (
        <p role="alert" className="text-sm text-destructive">
          {repos.error.message}
        </p>
      )}
      {repos.data?.length === 0 && <NoRepos />}
      {repos.data && repos.data.length > 0 && (
        <ul className="divide-y rounded-xl bg-card px-3 ring-1 ring-foreground/10">
          {[...repos.data]
            .sort(byUrgency)
            .slice(0, SHOWN_REPOS)
            .map((repo) => (
              <li
                key={repo.id}
                className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 py-3"
              >
                <div className="flex min-w-0 flex-col gap-0.5">
                  <Link
                    href={`/repositories/${repo.id}`}
                    className="truncate font-mono text-sm hover:underline"
                  >
                    {repo.full_name}
                  </Link>
                  <span className="text-xs">
                    <RepoScanStatus scan={repo.latest_scan} />
                  </span>
                </div>
                <SeverityChips counts={repo.counts} />
              </li>
            ))}
        </ul>
      )}
    </section>
  );
}
