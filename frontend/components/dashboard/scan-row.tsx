import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import type { ScanSummary } from "@/lib/api";
import { timeAgo } from "@/lib/format";

function outcome(scan: ScanSummary): string {
  if (scan.status === "queued" || scan.status === "running") return "Running";
  if (scan.status === "failed") return "Failed";
  if (scan.grade === null) return "No grade";
  return scan.score === null ? scan.grade : `${scan.grade} · ${scan.score}`;
}

export function ScanRow({
  scan,
  showTarget = false,
}: {
  scan: ScanSummary;
  showTarget?: boolean;
}) {
  return (
    <li>
      <Link
        href={`/scan/${scan.id}`}
        className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 rounded-md px-1 py-3 text-sm transition-colors hover:bg-muted/50"
      >
        <span className="flex min-w-0 items-center gap-2">
          {showTarget ? (
            <span className="truncate font-mono">{scan.target}</span>
          ) : (
            <span className="text-muted-foreground">
              {timeAgo(scan.created_at)}
            </span>
          )}
          <Badge variant="outline">
            {scan.mode === "full" ? "Full" : "Quick"}
          </Badge>
        </span>
        <span className="flex items-center gap-3">
          <span className="font-medium tabular-nums">{outcome(scan)}</span>
          {showTarget && (
            <span className="text-muted-foreground">
              {timeAgo(scan.created_at)}
            </span>
          )}
        </span>
      </Link>
    </li>
  );
}
