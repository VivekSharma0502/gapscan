"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, ExternalLink, LoaderCircle } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  listCombinedFindings,
  markCombinedFindingRotated,
  type CombinedFinding,
  type CombinedFindingScope,
  type HistoryStep,
} from "@/lib/api";
import { shortDate } from "@/lib/format";
import { SEVERITY_STYLES } from "@/lib/severity";

const COMBINED_KEY = "combined-findings";
const LINK_CLASS =
  "inline-flex items-center gap-1 text-sm underline underline-offset-4";

function GuideLink({ href, label }: { href: string; label: string }) {
  // Security: noreferrer, so the provider's site doesn't learn which page sent someone.
  return (
    <a href={href} target="_blank" rel="noreferrer" className={LINK_CLASS}>
      {label}
      <ExternalLink className="size-3.5" aria-hidden />
    </a>
  );
}

function Steps({ steps }: { steps: string[] }) {
  return (
    <ol className="flex list-decimal flex-col gap-2 pl-5">
      {steps.map((step) => (
        <li key={step} className="text-pretty">
          {step}
        </li>
      ))}
    </ol>
  );
}

function FixTab({ finding }: { finding: CombinedFinding }) {
  return (
    <div className="flex flex-col gap-3">
      <Steps steps={finding.rotate_steps} />
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        <GuideLink
          href={finding.rotate_url}
          label={`Open ${finding.provider_name}`}
        />
        <GuideLink
          href={finding.docs_url}
          label={`${finding.provider_name}'s official instructions`}
        />
      </div>
    </div>
  );
}

function HistorySteps({
  steps,
  docsUrl,
}: {
  steps: HistoryStep[];
  docsUrl: string | null;
}) {
  return (
    <div className="flex flex-col gap-3">
      <ol className="flex list-decimal flex-col gap-3 pl-5">
        {steps.map((step) => (
          <li key={step.text} className="flex flex-col gap-1.5 text-pretty">
            {step.text}
            {step.command && (
              <code className="rounded-md bg-muted/50 px-3 py-2 font-mono text-xs break-all">
                {step.command}
              </code>
            )}
          </li>
        ))}
      </ol>
      {docsUrl && (
        <GuideLink href={docsUrl} label="GitHub's official instructions" />
      )}
    </div>
  );
}

function Originals({ finding }: { finding: CombinedFinding }) {
  if (finding.originals.length === 0) return null;
  return (
    <details className="text-sm">
      <summary className="cursor-pointer text-muted-foreground">
        Original findings ({finding.originals.length})
      </summary>
      <ul className="mt-2 divide-y">
        {finding.originals.map((original) => (
          <li key={original.id} className="flex flex-col gap-0.5 py-2">
            <span>{original.title}</span>
            {/* Security: these come from the scanned repo or site, so they are only rendered as text. */}
            <span className="font-mono text-xs break-all text-muted-foreground">
              {original.source === "repository" ? "Repository" : "Website"}
              {original.location ? `: ${original.location}` : ""}
            </span>
            <span className="font-mono text-xs break-all text-muted-foreground">
              {original.masked}
            </span>
          </li>
        ))}
      </ul>
    </details>
  );
}

function MarkRotated({ finding }: { finding: CombinedFinding }) {
  const queryClient = useQueryClient();
  const [asking, setAsking] = useState(false);
  const mark = useMutation({
    mutationFn: () => markCombinedFindingRotated(finding.id),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: [COMBINED_KEY] }),
  });

  if (!asking) {
    return (
      <div>
        <Button variant="outline" size="sm" onClick={() => setAsking(true)}>
          I&apos;ve rotated this key
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2 rounded-md bg-muted/50 p-3">
      <p className="text-pretty">
        Only confirm once the old key has been deleted or deactivated. GapScan
        can&apos;t check this for you, and this finding will drop to info.
      </p>
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          disabled={mark.isPending}
          onClick={() => mark.mutate()}
        >
          {mark.isPending && (
            <LoaderCircle className="animate-spin" aria-hidden />
          )}
          Yes, the old key no longer works
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={mark.isPending}
          onClick={() => setAsking(false)}
        >
          Cancel
        </Button>
      </div>
      {mark.error && (
        <p role="alert" className="text-destructive">
          {mark.error.message}
        </p>
      )}
    </div>
  );
}

function FindingBody({ finding }: { finding: CombinedFinding }) {
  const hasHistory = finding.history_steps.length > 0;
  const rotated = finding.rotated_at !== null;

  // Once it's replaced, cleaning up the history is the only thing left to do.
  if (rotated) {
    return (
      <HistorySteps
        steps={finding.history_steps}
        docsUrl={finding.history_docs_url}
      />
    );
  }
  if (!hasHistory) {
    return (
      <div className="flex flex-col gap-3">
        <p className="text-pretty">{finding.what_it_means}</p>
        <FixTab finding={finding} />
      </div>
    );
  }
  return (
    <Tabs defaultValue="fix">
      <TabsList className="w-full sm:w-fit">
        <TabsTrigger value="fix">Replace the key</TabsTrigger>
        <TabsTrigger value="history">Clean up git history</TabsTrigger>
        <TabsTrigger value="meaning">What it means</TabsTrigger>
      </TabsList>
      <TabsContent value="fix" className="pt-1">
        <FixTab finding={finding} />
      </TabsContent>
      <TabsContent value="history" className="pt-1">
        <HistorySteps
          steps={finding.history_steps}
          docsUrl={finding.history_docs_url}
        />
      </TabsContent>
      <TabsContent value="meaning" className="pt-1">
        <p className="text-pretty">{finding.what_it_means}</p>
      </TabsContent>
    </Tabs>
  );
}

function CombinedCard({ finding }: { finding: CombinedFinding }) {
  const style = SEVERITY_STYLES[finding.severity];
  const likely = finding.confidence === "likely";

  return (
    <article className="flex flex-col gap-3 rounded-xl bg-card p-4 text-sm ring-1 ring-foreground/10 sm:p-5">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className={style.badge}>
          {style.label}
          {likely && finding.rotated_at === null ? " (likely)" : ""}
        </Badge>
        {finding.rotated_at && (
          <Badge variant="outline">
            <BadgeCheck aria-hidden />
            Owner marked as rotated
          </Badge>
        )}
      </div>
      <h3 className="text-base font-medium tracking-tight text-balance break-words">
        {finding.title}
      </h3>
      {/* Security: these names come from a repo or a site, so they are only rendered as text. */}
      <dl className="grid gap-x-4 gap-y-1 rounded-md bg-muted/50 px-3 py-2 font-mono text-xs leading-5 text-muted-foreground sm:grid-cols-[auto_1fr]">
        <dt>Website</dt>
        <dd className="break-all text-foreground">{finding.hostname}</dd>
        <dt>Repository</dt>
        <dd className="break-all text-foreground">{finding.repo_full_name}</dd>
        <dt>Project</dt>
        <dd className="break-all text-foreground">{finding.identifier}</dd>
        <dt>First found</dt>
        <dd className="text-foreground">{shortDate(finding.first_seen_at)}</dd>
        {finding.rotated_at && (
          <>
            <dt>Marked rotated</dt>
            <dd className="text-foreground">
              {shortDate(finding.rotated_at)}
            </dd>
          </>
        )}
      </dl>
      {finding.note && (
        <p className="text-pretty text-muted-foreground">{finding.note}</p>
      )}
      <FindingBody finding={finding} />
      {finding.can_mark_rotated && <MarkRotated finding={finding} />}
      <Originals finding={finding} />
    </article>
  );
}

export function CombinedFindings({ scope }: { scope: CombinedFindingScope }) {
  const findings = useQuery({
    queryKey: [COMBINED_KEY, scope],
    queryFn: ({ signal }) => listCombinedFindings(scope, signal),
  });

  if (findings.isError) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {findings.error.message}
      </p>
    );
  }
  // Most sites have none, so an empty section would only be noise.
  if (!findings.data || findings.data.length === 0) return null;

  return (
    <section
      aria-labelledby="combined-heading"
      className="flex flex-col gap-3"
    >
      <div className="flex flex-col gap-1">
        <h2
          id="combined-heading"
          className="text-lg font-semibold tracking-tight"
        >
          Across your repository and website
        </h2>
        <p className="text-sm text-pretty text-muted-foreground">
          The same backend shows up on both sides, so these are shown as one
          problem as things stand now. The separate findings are still listed.
        </p>
      </div>
      {findings.data.map((finding) => (
        <CombinedCard key={finding.id} finding={finding} />
      ))}
    </section>
  );
}
