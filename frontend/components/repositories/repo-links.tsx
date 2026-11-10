"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, LoaderCircle } from "lucide-react";
import { useState, type FormEvent } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  createRepoLink,
  listDomains,
  listRepoLinks,
  removeRepoLink,
  setRepoLinkState,
  type Repo,
  type RepoLink,
  type RepoLinkAnswer,
} from "@/lib/api";

const LINKS_KEY = ["repo-links"];

const SELECT_CLASS =
  "h-8 w-full min-w-0 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50 dark:bg-input/30";

type LinkAction = RepoLinkAnswer | "remove";

function LinkRow({ link }: { link: RepoLink }) {
  const queryClient = useQueryClient();
  const change = useMutation({
    mutationFn: (action: LinkAction): Promise<unknown> =>
      action === "remove"
        ? removeRepoLink(link.id)
        : setRepoLinkState(link.id, action),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: LINKS_KEY }),
  });
  const pending = change.isPending ? change.variables : null;

  function actionButton(
    action: LinkAction,
    label: string,
    variant: "outline" | "ghost",
  ) {
    return (
      <Button
        variant={variant}
        size="sm"
        disabled={change.isPending}
        onClick={() => change.mutate(action)}
      >
        {pending === action && (
          <LoaderCircle className="animate-spin" aria-hidden />
        )}
        {label}
      </Button>
    );
  }

  return (
    <li className="flex flex-col gap-2 py-3">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <div className="flex min-w-0 flex-col gap-0.5">
          <span className="font-mono text-sm wrap-anywhere">
            {link.repo_full_name}
          </span>
          {/* Security: this name is user input, so it is only rendered as text. */}
          <span className="text-xs text-muted-foreground wrap-anywhere">
            {link.hostname}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {link.state === "suggested" && (
            <>
              {actionButton("confirmed", "Yes, link them", "outline")}
              {actionButton("dismissed", "Not related", "ghost")}
            </>
          )}
          {link.state === "confirmed" && (
            <>
              <Badge variant="outline">
                <BadgeCheck aria-hidden />
                Linked
              </Badge>
              {actionButton("remove", "Remove link", "ghost")}
            </>
          )}
          {link.state === "dismissed" && (
            <>
              <span className="text-xs text-muted-foreground">
                Marked as not related
              </span>
              {actionButton("remove", "Undo", "ghost")}
            </>
          )}
        </div>
      </div>
      {change.error && (
        <p role="alert" className="text-sm text-destructive">
          {change.error.message}
        </p>
      )}
    </li>
  );
}

function AddLink({
  repos,
  domains,
}: {
  repos: Repo[];
  domains: { id: string; hostname: string }[];
}) {
  const queryClient = useQueryClient();
  const [repoId, setRepoId] = useState("");
  const [domainId, setDomainId] = useState("");
  const add = useMutation({
    mutationFn: () => createRepoLink(repoId, domainId),
    onSuccess() {
      setRepoId("");
      setDomainId("");
      return queryClient.invalidateQueries({ queryKey: LINKS_KEY });
    },
  });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    add.mutate();
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-2 pt-2">
      <div className="flex flex-col gap-2 sm:flex-row">
        <select
          aria-label="Repository"
          className={SELECT_CLASS}
          value={repoId}
          onChange={(event) => setRepoId(event.target.value)}
        >
          <option value="">Choose a repository</option>
          {repos.map((repo) => (
            <option key={repo.id} value={repo.id}>
              {repo.full_name}
            </option>
          ))}
        </select>
        <select
          aria-label="Website"
          className={SELECT_CLASS}
          value={domainId}
          onChange={(event) => setDomainId(event.target.value)}
        >
          <option value="">Choose a verified website</option>
          {domains.map((domain) => (
            <option key={domain.id} value={domain.id}>
              {domain.hostname}
            </option>
          ))}
        </select>
        <Button
          type="submit"
          variant="outline"
          disabled={!repoId || !domainId || add.isPending}
        >
          {add.isPending && (
            <LoaderCircle className="animate-spin" aria-hidden />
          )}
          Link
        </Button>
      </div>
      {add.error && (
        <p role="alert" className="text-sm text-destructive">
          {add.error.message}
        </p>
      )}
    </form>
  );
}

export function RepoLinks({ repos }: { repos: Repo[] }) {
  const links = useQuery({
    queryKey: LINKS_KEY,
    queryFn: ({ signal }) => listRepoLinks(signal),
  });
  const domains = useQuery({
    queryKey: ["domains"],
    queryFn: ({ signal }) => listDomains(signal),
  });

  if (links.isError) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {links.error.message}
      </p>
    );
  }
  if (!links.data) return null;

  const verified = domains.data?.filter((domain) => domain.verified) ?? [];
  const suggested = links.data.filter((link) => link.state === "suggested");
  const answered = links.data.filter((link) => link.state !== "suggested");

  return (
    <section className="flex flex-col gap-2 border-t pt-4">
      <h2 className="text-sm font-medium">Repositories and your websites</h2>
      <p className="text-sm text-pretty text-muted-foreground">
        Tell GapScan which repository powers which website, so a key leaked in
        one and used by the other shows up as a single problem.
      </p>

      {suggested.length > 0 && (
        <div className="flex flex-col gap-1 pt-2">
          <h3 className="text-sm font-medium">Does this repository power this website?</h3>
          <p className="text-xs text-pretty text-muted-foreground">
            They use the same backend. &ldquo;Not related&rdquo; also hides any
            combined finding for the pair.
          </p>
          <ul className="divide-y">
            {suggested.map((link) => (
              <LinkRow key={link.id} link={link} />
            ))}
          </ul>
        </div>
      )}

      {answered.length > 0 && (
        <ul className="divide-y">
          {answered.map((link) => (
            <LinkRow key={link.id} link={link} />
          ))}
        </ul>
      )}

      {verified.length > 0 ? (
        <AddLink repos={repos} domains={verified} />
      ) : (
        domains.data && (
          <p className="text-xs text-muted-foreground">
            Verify a website on the Domains page to link it to a repository.
          </p>
        )
      )}
    </section>
  );
}
