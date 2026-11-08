// A 270 degree arc. pathLength makes the dash values simple percentages of the circle.
const SWEEP = 75;

function arcColor(grade: string): string {
  if (grade === "F") return "stroke-severity-critical";
  if (grade === "D") return "stroke-severity-high";
  if (grade === "C") return "stroke-severity-medium";
  return "stroke-good";
}

export function ScoreGauge({ score, grade }: { score: number; grade: string }) {
  const circle = {
    cx: 60,
    cy: 60,
    r: 52,
    pathLength: 100,
    fill: "none",
    strokeWidth: 7,
    strokeLinecap: "round" as const,
    // Starts at the lower left, so the gap in the ring sits at the bottom.
    transform: "rotate(135 60 60)",
  };

  return (
    <div
      role="img"
      aria-label={`Security score ${score} out of 100, grade ${grade}`}
      className="relative size-40 shrink-0"
    >
      <svg viewBox="0 0 120 120" className="size-full" aria-hidden>
        <circle
          {...circle}
          className="stroke-muted"
          strokeDasharray={`${SWEEP} 100`}
        />
        <circle
          {...circle}
          className={arcColor(grade)}
          style={{
            strokeDasharray: `${(score / 100) * SWEEP} 100`,
            animation: "gauge-fill 900ms ease-out",
          }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-5xl font-semibold tracking-tight">{grade}</span>
        <span className="mt-1 text-sm text-muted-foreground tabular-nums">
          {score} / 100
        </span>
      </div>
    </div>
  );
}
