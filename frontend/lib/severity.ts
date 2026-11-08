import type { Severity } from "@/lib/api";

// Most serious first, which is also the order findings are shown in.
export const SEVERITIES: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

// Full class names, because Tailwind only generates classes it can find in the source.
export const SEVERITY_STYLES: Record<
  Severity,
  { label: string; dot: string; badge: string }
> = {
  critical: {
    label: "Critical",
    dot: "bg-severity-critical",
    badge: "bg-severity-critical/15 border-severity-critical/40",
  },
  high: {
    label: "High",
    dot: "bg-severity-high",
    badge: "bg-severity-high/15 border-severity-high/40",
  },
  medium: {
    label: "Medium",
    dot: "bg-severity-medium",
    badge: "bg-severity-medium/15 border-severity-medium/40",
  },
  low: {
    label: "Low",
    dot: "bg-severity-low",
    badge: "bg-severity-low/15 border-severity-low/40",
  },
  info: {
    label: "Info",
    dot: "bg-severity-info",
    badge: "bg-severity-info/15 border-severity-info/40",
  },
};
