"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";

import { startQuickScan } from "@/lib/api";
import { saveClaim } from "@/lib/claims";

export function useStartScan() {
  const router = useRouter();
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: startQuickScan,
    onSuccess(scan) {
      if (scan.claim_token) saveClaim(scan.id, scan.claim_token);
      // A reused scan can be the one already on screen, now unlocked for this viewer.
      void queryClient.invalidateQueries({ queryKey: ["scan", scan.id] });
      router.push(`/scan/${scan.id}`);
    },
  });
}
