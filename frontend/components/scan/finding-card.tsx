"use client";

import { CopyButton } from "@/components/scan/copy-button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { Finding, Fix, Platform } from "@/lib/api";

export const PLATFORMS: { id: Platform; label: string }[] = [
  { id: "vercel", label: "Vercel" },
  { id: "netlify", label: "Netlify" },
  { id: "nginx", label: "nginx" },
  { id: "cloudflare", label: "Cloudflare" },
];

interface PlatformChoice {
  platform: Platform;
  onPlatformChange: (platform: Platform) => void;
}

function HowToFix({
  fix,
  platform,
  onPlatformChange,
}: { fix: Fix } & PlatformChoice) {
  const selected = fix.platforms[platform];
  const label = PLATFORMS.find(({ id }) => id === platform)?.label;

  return (
    <div className="flex flex-col gap-3">
      <p className="text-pretty">{fix.how_to_fix}</p>
      <Tabs
        value={platform}
        onValueChange={(value) => onPlatformChange(value as Platform)}
      >
        <TabsList aria-label="Platform" className="w-full sm:w-fit">
          {PLATFORMS.map(({ id, label: name }) => (
            <TabsTrigger key={id} value={id} className="text-xs sm:text-sm">
              {name}
            </TabsTrigger>
          ))}
        </TabsList>
        {/* One panel, because the selected platform's content is all that is shown. */}
        <TabsContent value={platform} className="flex flex-col gap-3 pt-1">
          <p className="text-pretty text-muted-foreground">
            {selected.instructions}
          </p>
          {selected.snippet !== null && (
            <div className="overflow-hidden rounded-lg border">
              <div className="flex items-center justify-between border-b bg-muted/40 py-1 pr-1 pl-3">
                <span className="text-xs text-muted-foreground">{label}</span>
                <CopyButton text={selected.snippet} />
              </div>
              <pre className="overflow-x-auto p-3 font-mono text-xs leading-5">
                <code>{selected.snippet}</code>
              </pre>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

export function FindingCard({
  finding,
  platform,
  onPlatformChange,
}: { finding: Finding } & PlatformChoice) {
  const { fix } = finding;

  return (
    <article className="flex flex-col gap-3 rounded-xl bg-card p-4 text-sm ring-1 ring-foreground/10 sm:p-5">
      <h4 className="text-base font-medium tracking-tight text-balance">
        {finding.title}
      </h4>
      {/* Security: evidence comes from the scanned site, so it is only ever rendered as text. */}
      {finding.evidence && (
        <p className="rounded-md bg-muted/50 px-3 py-2 font-mono text-xs leading-5 break-words text-muted-foreground">
          {finding.evidence}
        </p>
      )}
      {fix && (
        <Tabs defaultValue="meaning">
          <TabsList className="w-full sm:w-fit">
            <TabsTrigger value="meaning">What it means</TabsTrigger>
            <TabsTrigger value="fix">How to fix</TabsTrigger>
          </TabsList>
          <TabsContent value="meaning" className="pt-1">
            <p className="text-pretty">{fix.what_it_means}</p>
          </TabsContent>
          <TabsContent value="fix" className="pt-1">
            <HowToFix
              fix={fix}
              platform={platform}
              onPlatformChange={onPlatformChange}
            />
          </TabsContent>
        </Tabs>
      )}
    </article>
  );
}
