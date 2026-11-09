"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { FolderGit2, Lock, LoaderCircle } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "@/components/auth/auth-provider";
import { Button } from "@/components/ui/button";
import { getGithubInstallUrl, listRepos } from "@/lib/api";

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
      <Button onClick={() => connect.mutate()} disabled={connect.isPending}>
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
  });

  if (!signedIn) return <Loading />;

  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Repositories</h1>
        <p className="text-sm text-pretty text-muted-foreground">
          Connect GitHub to check your repositories for leaked keys and
          passwords, including ones buried in old commits.
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
            <ul className="divide-y rounded-xl bg-card px-3 ring-1 ring-foreground/10">
              {repos.data.map((repo) => (
                <li key={repo.id} className="flex items-center gap-2 py-3">
                  <FolderGit2
                    className="size-4 shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                  <span className="min-w-0 truncate font-mono text-sm">
                    {repo.full_name}
                  </span>
                  {repo.is_private && (
                    <Lock
                      className="size-3.5 shrink-0 text-muted-foreground"
                      aria-label="Private repository"
                    />
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </>
  );
}
