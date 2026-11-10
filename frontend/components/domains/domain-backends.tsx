"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, LoaderCircle } from "lucide-react";
import { useRouter } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  confirmBackend,
  listBackends,
  startBackendCheck,
  type BaasKind,
  type DomainBackend,
} from "@/lib/api";

const KIND_LABELS: Record<BaasKind, string> = {
  firebase_rtdb: "Firebase database",
  firebase_storage: "Firebase storage bucket",
  supabase: "Supabase project",
};

function backendsKey(domainId: string) {
  return ["domain-backends", domainId];
}

function BackendRow({
  domainId,
  backend,
}: {
  domainId: string;
  backend: DomainBackend;
}) {
  const queryClient = useQueryClient();
  const confirm = useMutation({
    mutationFn: (confirmed: boolean) =>
      confirmBackend(domainId, backend.id, confirmed),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: backendsKey(domainId) }),
  });

  return (
    <li className="flex flex-col gap-2 py-3">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <div className="flex min-w-0 flex-col gap-0.5">
          <span className="text-xs text-muted-foreground">
            {KIND_LABELS[backend.kind]}
          </span>
          {/* Security: this name comes from the scanned site, so it is only rendered as text. */}
          <span className="font-mono text-sm wrap-anywhere">
            {backend.identifier}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {backend.confirmed && (
            <Badge variant="outline">
              <BadgeCheck aria-hidden />
              Yours
            </Badge>
          )}
          <Button
            variant={backend.confirmed ? "ghost" : "outline"}
            size="sm"
            disabled={confirm.isPending}
            onClick={() => confirm.mutate(!backend.confirmed)}
          >
            {confirm.isPending && (
              <LoaderCircle className="animate-spin" aria-hidden />
            )}
            {backend.confirmed ? "Not mine" : "This is mine"}
          </Button>
        </div>
      </div>
      {confirm.error && (
        <p role="alert" className="text-sm text-destructive">
          {confirm.error.message}
        </p>
      )}
    </li>
  );
}

function CheckBackends({ domainId }: { domainId: string }) {
  const router = useRouter();
  const check = useMutation({
    mutationFn: () => startBackendCheck(domainId),
    onSuccess: (created) => router.push(`/scan/${created.id}`),
  });
  // Stays busy after success, until the page has moved on to the report.
  const busy = check.isPending || check.isSuccess;

  return (
    <div className="flex flex-col items-start gap-2 pt-2">
      <Button variant="outline" disabled={busy} onClick={() => check.mutate()}>
        {busy && <LoaderCircle className="animate-spin" aria-hidden />}
        {busy ? "Starting…" : "Check backends"}
      </Button>
      <p className="text-xs text-pretty text-muted-foreground">
        Only contacts your confirmed backends, so it can run even when your
        website&apos;s bot protection is blocking scans.
      </p>
      {check.error && (
        <p role="alert" className="text-sm text-destructive">
          {check.error.message}
        </p>
      )}
    </div>
  );
}

export function DomainBackends({ domainId }: { domainId: string }) {
  const backends = useQuery({
    queryKey: backendsKey(domainId),
    queryFn: ({ signal }) => listBackends(domainId, signal),
  });

  if (backends.isError) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {backends.error.message}
      </p>
    );
  }
  // Most sites use neither service, so an empty section would only be noise.
  if (!backends.data || backends.data.length === 0) return null;

  return (
    <section className="flex flex-col gap-2 border-t pt-4">
      <h3 className="text-sm font-medium">Backends your site uses</h3>
      <p className="text-sm text-pretty text-muted-foreground">
        A full scan found these in your site&apos;s code. Only confirm the ones
        you own or have permission to test, because code on your site can point
        at someone else&apos;s service. GapScan sends read-only checks to
        confirmed backends. It never writes to them and
        never stores your data.
      </p>
      <ul className="divide-y">
        {backends.data.map((backend) => (
          <BackendRow
            key={backend.id}
            domainId={domainId}
            backend={backend}
          />
        ))}
      </ul>
      {/* Supabase has no probes yet, so confirming only that wouldn't give this anything to do. */}
      {backends.data.some(
        (backend) => backend.confirmed && backend.kind !== "supabase",
      ) && <CheckBackends domainId={domainId} />}
    </section>
  );
}
