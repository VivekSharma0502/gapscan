"use client";

import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";

import { startQuickScan } from "@/lib/api";
import { saveClaim } from "@/lib/claims";

export function useStartScan() {
  const router = useRouter();

  return useMutation({
    mutationFn: startQuickScan,
    onSuccess(scan) {
      if (scan.claim_token) saveClaim(scan.id, scan.claim_token);
      router.push(`/scan/${scan.id}`);
    },
  });
}
