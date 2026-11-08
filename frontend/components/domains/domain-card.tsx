"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, CircleDashed, LoaderCircle, ScanSearch } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { CopyButton } from "@/components/scan/copy-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  deleteDomain,
  startFullScan,
  verifyDomain,
  type Domain,
  type VerificationMethod,
  type VerifyFailure,
} from "@/lib/api";

const DOMAINS_KEY = ["domains"];

const METHOD_NAMES: Record<VerificationMethod, string> = {
  dns: "DNS",
  file: "file",
};

function CopyField({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs text-muted-foreground">{label}</span>
        <CopyButton text={value} />
      </div>
      <code className="rounded-md bg-muted/50 px-3 py-2 font-mono text-xs leading-5 break-all">
        {value}
      </code>
    </div>
  );
}

function FailureNote({ failure }: { failure?: VerifyFailure }) {
  if (!failure) return null;
  return (
    <p role="alert" className="text-sm text-pretty text-destructive">
      {failure.message}
    </p>
  );
}

function DnsMethod({
  domain,
  failure,
}: {
  domain: Domain;
  failure?: VerifyFailure;
}) {
  const { txt_name, txt_value } = domain.instructions;

  return (
    <section className="flex flex-col gap-3">
      <h3 className="text-sm font-medium">Add a DNS TXT record</h3>
      {domain.shared_platform && (
        <p className="text-sm text-pretty text-muted-foreground">
          This is a shared platform address, so you probably can&apos;t edit
          its DNS. Use the file method instead.
        </p>
      )}
      <CopyField label="Name" value={txt_name} />
      <CopyField label="Value" value={txt_value} />
      <p className="text-xs text-pretty text-muted-foreground">
        Some DNS providers add your domain automatically, so enter only the part
        before it. New records can take a few minutes to appear.
      </p>
      <FailureNote failure={failure} />
    </section>
  );
}

function FileMethod({
  domain,
  failure,
}: {
  domain: Domain;
  failure?: VerifyFailure;
}) {
  const { file_url, file_content } = domain.instructions;

  return (
    <section className="flex flex-col gap-3">
      <h3 className="text-sm font-medium">Or upload a file</h3>
      <CopyField label="File location" value={file_url} />
      <CopyField label="File contents (nothing else)" value={file_content} />
      <p className="text-xs text-pretty text-muted-foreground">
        In most projects, this goes in{" "}
        <code>public/.well-known/scankit-verify.txt</code>. Then redeploy.
      </p>
      <FailureNote failure={failure} />
    </section>
  );
}

function VerificationMethods({
  domain,
  failures,
}: {
  domain: Domain;
  failures: VerifyFailure[];
}) {
  const dns = failures.find((item) => item.method === "dns");
  const file = failures.find((item) => item.method === "file");

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <DnsMethod domain={domain} failure={dns} />
      <FileMethod domain={domain} failure={file} />
    </div>
  );
}

function DeleteDomain({ domain }: { domain: Domain }) {
  const [confirming, setConfirming] = useState(false);
  const queryClient = useQueryClient();
  const remove = useMutation({
    mutationFn: () => deleteDomain(domain.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: DOMAINS_KEY }),
  });

  if (!confirming) {
    return (
      <Button variant="ghost" onClick={() => setConfirming(true)}>
        Delete
      </Button>
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-sm text-muted-foreground">
        Delete this domain? Past reports are kept.
      </span>
      <Button
        variant="destructive"
        disabled={remove.isPending}
        onClick={() => remove.mutate()}
      >
        {remove.isPending ? "Deleting…" : "Yes, delete"}
      </Button>
      <Button variant="ghost" onClick={() => setConfirming(false)}>
        Cancel
      </Button>
      {remove.error && (
        <p role="alert" className="w-full text-sm text-destructive">
          {remove.error.message}
        </p>
      )}
    </div>
  );
}

export function DomainCard({ domain }: { domain: Domain }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const verify = useMutation({
    mutationFn: () => verifyDomain(domain.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: DOMAINS_KEY }),
  });
  const scan = useMutation({
    mutationFn: () => startFullScan(domain.id),
    onSuccess: (created) => router.push(`/scan/${created.id}`),
    // The API refuses a domain that has since lost its verification, so show its real state.
    onError: () => queryClient.invalidateQueries({ queryKey: DOMAINS_KEY }),
  });
  const failures = verify.data?.failures ?? [];
  const scanBusy = scan.isPending || scan.isSuccess;

  const verifyButton = (variant: "default" | "outline") => (
    <Button
      variant={variant}
      disabled={verify.isPending}
      onClick={() => verify.mutate()}
    >
      {verify.isPending && <LoaderCircle className="animate-spin" aria-hidden />}
      {verify.isPending ? "Checking…" : domain.verified ? "Verify again" : "Verify"}
    </Button>
  );

  return (
    <article className="flex flex-col gap-5 rounded-xl bg-card p-5 ring-1 ring-foreground/10 sm:p-6">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-mono text-base font-medium wrap-anywhere">
          {domain.hostname}
        </h2>
        {domain.verified ? (
          <Badge variant="outline">
            <BadgeCheck aria-hidden />
            Verified
            {domain.verified_method &&
              ` by ${METHOD_NAMES[domain.verified_method]}`}
          </Badge>
        ) : (
          <Badge variant="outline">
            <CircleDashed aria-hidden />
            Not verified
          </Badge>
        )}
      </header>

      {domain.verified ? (
        <details className="flex flex-col gap-4 text-sm">
          <summary className="cursor-pointer text-muted-foreground">
            Verification details
          </summary>
          <div className="pt-4">
            <VerificationMethods domain={domain} failures={failures} />
          </div>
        </details>
      ) : (
        <VerificationMethods domain={domain} failures={failures} />
      )}

      {domain.verified && (
        <p className="text-xs text-pretty text-muted-foreground">
          Keep your DNS record or file in place. We check it again before every
          full scan.
        </p>
      )}

      {domain.verified && failures.length > 0 && (
        <p role="status" className="text-sm text-pretty text-muted-foreground">
          We couldn&apos;t re-confirm this just now, so it stays verified for
          the moment. Open the details above for the reasons.
        </p>
      )}

      {verify.error && (
        <p role="alert" className="text-sm text-destructive">
          {verify.error.message}
        </p>
      )}
      {scan.error && (
        <p role="alert" className="text-sm text-destructive">
          {scan.error.message}
        </p>
      )}

      <footer className="flex flex-wrap items-center gap-2">
        {domain.verified ? (
          <>
            <Button disabled={scanBusy} onClick={() => scan.mutate()}>
              {scanBusy ? (
                <LoaderCircle className="animate-spin" aria-hidden />
              ) : (
                <ScanSearch aria-hidden />
              )}
              {scanBusy ? "Starting…" : "Run full scan"}
            </Button>
            {verifyButton("outline")}
          </>
        ) : (
          verifyButton("default")
        )}
        <DeleteDomain domain={domain} />
      </footer>
    </article>
  );
}
