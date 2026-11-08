"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { useState } from "react";

import { ScanRow } from "@/components/dashboard/scan-row";
import { Button } from "@/components/ui/button";
import { listDomainScans, type ScanSummary } from "@/lib/api";

const PAGE_SIZE = 20;

// Also the keyboard and screen reader route to the scans plotted on the chart.
export function ScanHistory({
  domainId,
  newestId,
}: {
  domainId: string;
  newestId: string | undefined;
}) {
  const [open, setOpen] = useState(false);
  const history = useInfiniteQuery({
    // Keyed on the newest scan, so a new one reloads the list from the top.
    queryKey: ["domains", domainId, "scans", "history", newestId],
    queryFn: ({ pageParam, signal }) =>
      listDomainScans(
        domainId,
        { limit: PAGE_SIZE, offset: pageParam },
        signal,
      ),
    initialPageParam: 0,
    getNextPageParam: (last) => {
      const next = last.offset + last.limit;
      return next < last.total ? next : undefined;
    },
    enabled: open,
  });

  // A scan arriving between pages shifts the offsets, which can repeat a row.
  const scans = new Map<string, ScanSummary>();
  for (const page of history.data?.pages ?? []) {
    for (const scan of page.items) scans.set(scan.id, scan);
  }

  return (
    <details
      className="text-sm"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer text-muted-foreground">
        Scan history
      </summary>
      <div className="flex flex-col items-start gap-2 pt-2">
        {history.isLoading && (
          <p role="status" className="text-muted-foreground">
            Loading…
          </p>
        )}
        {history.isError && (
          <p role="alert" className="text-destructive">
            {history.error.message}
          </p>
        )}
        {scans.size > 0 && (
          <ul className="w-full divide-y">
            {[...scans.values()].map((scan) => (
              <ScanRow key={scan.id} scan={scan} />
            ))}
          </ul>
        )}
        {history.hasNextPage && (
          <Button
            variant="outline"
            size="sm"
            disabled={history.isFetchingNextPage}
            onClick={() => history.fetchNextPage()}
          >
            {history.isFetchingNextPage && (
              <LoaderCircle className="animate-spin" aria-hidden />
            )}
            Load more
          </Button>
        )}
      </div>
    </details>
  );
}
