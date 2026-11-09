"use client";

import { ExternalLink } from "lucide-react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { RepoFinding, SecretGuide } from "@/lib/api";
import { shortDate } from "@/lib/format";

const SHORT_SHA_LENGTH = 8;
const LINK_CLASS =
  "inline-flex items-center gap-1 text-sm underline underline-offset-4";

function GuideLink({ href, label }: { href: string; label: string }) {
  // Security: noreferrer, so the provider's site doesn't learn which repo page sent someone.
  return (
    <a href={href} target="_blank" rel="noreferrer" className={LINK_CLASS}>
      {label}
      <ExternalLink className="size-3.5" aria-hidden />
    </a>
  );
}

function HowToReplace({ guide }: { guide: SecretGuide }) {
  return (
    <div className="flex flex-col gap-3">
      <ol className="flex list-decimal flex-col gap-2 pl-5">
        {guide.rotate_steps.map((step) => (
          <li key={step} className="text-pretty">
            {step}
          </li>
        ))}
      </ol>
      {(guide.rotate_url || guide.docs_url) && (
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {guide.rotate_url && (
            <GuideLink
              href={guide.rotate_url}
              label={`Open ${guide.provider_name}`}
            />
          )}
          {guide.docs_url && (
            <GuideLink
              href={guide.docs_url}
              label={`${guide.provider_name}'s official instructions`}
            />
          )}
        </div>
      )}
    </div>
  );
}

export function RepoFindingCard({ finding }: { finding: RepoFinding }) {
  const { guide } = finding;

  return (
    <article className="flex flex-col gap-3 rounded-xl bg-card p-4 text-sm ring-1 ring-foreground/10 sm:p-5">
      <h3 className="text-base font-medium tracking-tight text-balance">
        {finding.title}
      </h3>
      {/* Security: paths come from the scanned repo, so they are only ever rendered as text. */}
      <dl className="grid gap-x-4 gap-y-1 rounded-md bg-muted/50 px-3 py-2 font-mono text-xs leading-5 text-muted-foreground sm:grid-cols-[auto_1fr]">
        <dt>File</dt>
        <dd className="break-all text-foreground">
          {finding.file_path}:{finding.line}
        </dd>
        <dt>Commit</dt>
        <dd className="text-foreground">
          {finding.commit_sha.slice(0, SHORT_SHA_LENGTH)}
        </dd>
        <dt>Secret</dt>
        <dd className="text-foreground">{finding.masked}</dd>
        <dt>First found</dt>
        <dd className="text-foreground">{shortDate(finding.first_seen_at)}</dd>
      </dl>
      {finding.note && (
        <p className="text-pretty text-muted-foreground">{finding.note}</p>
      )}
      {guide && (
        <Tabs defaultValue="replace">
          <TabsList className="w-full sm:w-fit">
            <TabsTrigger value="replace">How to replace it</TabsTrigger>
            <TabsTrigger value="meaning">What it means</TabsTrigger>
          </TabsList>
          <TabsContent value="replace" className="pt-1">
            <HowToReplace guide={guide} />
          </TabsContent>
          <TabsContent value="meaning" className="pt-1">
            <p className="text-pretty">{guide.what_it_means}</p>
          </TabsContent>
        </Tabs>
      )}
    </article>
  );
}
