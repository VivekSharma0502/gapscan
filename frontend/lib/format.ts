const RELATIVE = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const SHORT_DATE = new Intl.DateTimeFormat("en", {
  day: "numeric",
  month: "short",
});

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31_536_000],
  ["month", 2_592_000],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
];

export function timeAgo(iso: string): string {
  const seconds = (new Date(iso).getTime() - Date.now()) / 1000;
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) {
      return RELATIVE.format(Math.round(seconds / size), unit);
    }
  }
  return "just now";
}

export function shortDate(iso: string): string {
  return SHORT_DATE.format(new Date(iso));
}

const GRADE_COLORS: Record<string, string> = {
  F: "var(--severity-critical)",
  D: "var(--severity-high)",
  C: "var(--severity-medium)",
};

// A CSS color, for inline SVG. The same bands as the report's score gauge.
export function gradeColor(grade: string | null): string {
  if (grade === null) return "var(--muted-foreground)";
  return GRADE_COLORS[grade] ?? "var(--good)";
}
