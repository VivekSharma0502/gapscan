"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Button } from "@/components/ui/button";
import { listDomainScans, type ScanSummary } from "@/lib/api";
import { gradeColor, shortDate } from "@/lib/format";

const MAX_POINTS = 30;
const MAX_HIT_RADIUS = 16;
const MIN_HIT_RADIUS = 5;
// Roughly the room the Y axis and margins take from the chart's width.
const AXIS_WIDTH = 48;

const TICK = { fill: "var(--muted-foreground)", fontSize: 11 };

interface Point {
  position: number;
  score: number;
  scan: ScanSummary;
}

function ChartTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: readonly { payload?: Point }[];
}) {
  const point = payload?.[0]?.payload;
  if (!active || !point) return null;

  return (
    <div className="rounded-md bg-popover px-2.5 py-1.5 text-xs text-popover-foreground shadow-md ring-1 ring-foreground/10">
      <p className="font-medium tabular-nums">
        {point.scan.grade} · {point.score} / 100
      </p>
      <p className="text-muted-foreground">
        {shortDate(point.scan.created_at)}
      </p>
      {point.scan.score_label && (
        <p className="text-muted-foreground">{point.scan.score_label}</p>
      )}
    </div>
  );
}

function ScorePoint({
  cx,
  cy,
  point,
  hitRadius,
  onOpen,
}: {
  cx?: number;
  cy?: number;
  point: Point;
  hitRadius: number;
  onOpen: (id: string) => void;
}) {
  if (cx === undefined || cy === undefined) return <g />;
  const color = gradeColor(point.scan.grade);
  // Hollow when checks were skipped, so a generous score doesn't read like the others.
  const partial = point.scan.result_status === "partial";

  return (
    <g className="cursor-pointer" onClick={() => onOpen(point.scan.id)}>
      {/* Bigger than the dot for fingers, but never over the next point. */}
      <circle cx={cx} cy={cy} r={hitRadius} fill="transparent" />
      <circle
        cx={cx}
        cy={cy}
        r={4}
        fill={partial ? "var(--card)" : color}
        stroke={color}
        strokeWidth={2}
      />
    </g>
  );
}

function Chart({ points }: { points: Point[] }) {
  const router = useRouter();
  const [width, setWidth] = useState(0);
  const spacing =
    points.length > 1 ? (width - AXIS_WIDTH) / (points.length - 1) : Infinity;
  const hitRadius = Math.max(
    MIN_HIT_RADIUS,
    Math.min(MAX_HIT_RADIUS, spacing / 2),
  );
  const latest = points[points.length - 1];

  return (
    <figure className="flex flex-col gap-1">
      <figcaption className="sr-only">
        Score history: {points.length} full{" "}
        {points.length === 1 ? "scan" : "scans"}, latest score {latest.score}{" "}
        out of 100. Every scan is also listed under Scan history.
      </figcaption>
      <div className="h-40 w-full min-w-0" aria-hidden>
        <ResponsiveContainer
          width="100%"
          height="100%"
          onResize={(nextWidth) => setWidth(nextWidth)}
        >
          {/* No keyboard layer: Scan history is the accessible route to these scans. */}
          <LineChart
            data={points}
            accessibilityLayer={false}
            margin={{ top: 12, right: 12, bottom: 0, left: 0 }}
          >
            <CartesianGrid vertical={false} stroke="var(--border)" />
            <XAxis
              dataKey="position"
              tick={TICK}
              tickLine={false}
              axisLine={false}
              minTickGap={32}
              tickFormatter={(position: number) =>
                points[position] ? shortDate(points[position].scan.created_at) : ""
              }
            />
            <YAxis
              domain={[0, 100]}
              ticks={[0, 50, 100]}
              tick={TICK}
              tickLine={false}
              axisLine={false}
              width={32}
            />
            <Tooltip
              content={<ChartTooltip />}
              cursor={{ stroke: "var(--border)" }}
            />
            <Line
              dataKey="score"
              stroke="var(--muted-foreground)"
              strokeWidth={1.5}
              isAnimationActive={false}
              // Off, because a hover dot would sit on top and swallow the click.
              activeDot={false}
              dot={({ cx, cy, index }) => (
                <ScorePoint
                  key={points[index].scan.id}
                  cx={cx}
                  cy={cy}
                  point={points[index]}
                  hitRadius={hitRadius}
                  onOpen={(id) => router.push(`/scan/${id}`)}
                />
              )}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
      {points.length === 1 && (
        <p className="text-xs text-pretty text-muted-foreground">
          Run another full scan to start seeing a trend.
        </p>
      )}
    </figure>
  );
}

export function ScoreHistory({
  domainId,
  latestId,
}: {
  domainId: string;
  latestId: string;
}) {
  const history = useQuery({
    // Keyed on the newest result, so the chart reloads when a scan finishes.
    queryKey: ["domains", domainId, "scans", "chart", latestId],
    queryFn: ({ signal }) =>
      listDomainScans(
        domainId,
        { limit: MAX_POINTS, scoredOnly: true },
        signal,
      ),
  });

  if (history.isPending) {
    return (
      <div
        role="status"
        aria-label="Loading score history"
        className="h-40 w-full animate-pulse rounded-md bg-muted/40"
      />
    );
  }
  if (history.isError) {
    return (
      <div className="flex flex-col items-start gap-2">
        <p role="alert" className="text-sm text-destructive">
          {history.error.message}
        </p>
        <Button variant="outline" size="sm" onClick={() => history.refetch()}>
          Try again
        </Button>
      </div>
    );
  }
  // Possible when the only graded scan couldn't be read, so it has a grade but no score.
  if (history.data.items.length === 0) return null;

  const points = [...history.data.items]
    .reverse()
    .map((scan, position) => ({
      position,
      score: scan.score as number,
      scan,
    }));

  return <Chart points={points} />;
}
