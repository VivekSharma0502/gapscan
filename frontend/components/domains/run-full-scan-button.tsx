"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle, ScanSearch } from "lucide-react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { startFullScan } from "@/lib/api";

export function useFullScan(domainId: string) {
  const router = useRouter();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => startFullScan(domainId),
    onSuccess: (created) => router.push(`/scan/${created.id}`),
    // The API refuses a domain that has since lost its verification, so show its real state.
    onError: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: ["domains"] }),
        queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
      ]),
  });
}

export function RunFullScanButton({
  scan,
}: {
  scan: ReturnType<typeof useFullScan>;
}) {
  // Stays busy after success, until the page has moved on to the new scan.
  const busy = scan.isPending || scan.isSuccess;

  return (
    <Button disabled={busy} onClick={() => scan.mutate()}>
      {busy ? (
        <LoaderCircle className="animate-spin" aria-hidden />
      ) : (
        <ScanSearch aria-hidden />
      )}
      {busy ? "Starting…" : "Run full scan"}
    </Button>
  );
}
