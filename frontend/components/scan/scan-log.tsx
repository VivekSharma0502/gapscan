"use client";

import { useEffect, useRef } from "react";

import type { ProgressStep } from "@/lib/api";
import { stepLabel } from "@/lib/step-labels";

interface ScanLogProps {
  target: string;
  steps: ProgressStep[];
  total: number;
}

export function ScanLog({ target, steps, total }: ScanLogProps) {
  const panel = useRef<HTMLDivElement>(null);
  const done = steps.filter((step) => step.status === "done").length;

  // Keeps the newest line in view as the log grows.
  useEffect(() => {
    if (panel.current) panel.current.scrollTop = panel.current.scrollHeight;
  }, [steps.length]);

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight wrap-anywhere">
          Scanning {target}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Results appear here when the scan finishes.
        </p>
      </div>

      <div
        role="progressbar"
        aria-label="Scan progress"
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={done}
        className="h-1 overflow-hidden rounded-full bg-muted"
      >
        <div
          className="h-full rounded-full bg-foreground transition-[width] duration-200"
          style={{ width: `${total ? (done / total) * 100 : 0}%` }}
        />
      </div>

      {/* Focusable so keyboard users can scroll it. */}
      <div
        ref={panel}
        tabIndex={0}
        aria-label="Scan log"
        role="region"
        className="max-h-96 overflow-y-auto rounded-xl bg-card p-4 font-mono text-xs leading-6 ring-1 ring-foreground/10 outline-none focus-visible:ring-2 focus-visible:ring-ring sm:text-[13px]"
      >
        <p className="text-muted-foreground">
          <span aria-hidden>$ </span>scan {target}
        </p>
        {steps.length === 0 && (
          <p className="animate-pulse text-muted-foreground">
            Waiting for a free scanner…
          </p>
        )}
        <ol>
          {steps.map((step, index) => (
            <li
              key={`${index}-${step.name}`}
              className="flex animate-in gap-3 duration-150 fade-in"
            >
              {/*
                Security: plain text with no tick and no green. A tick would read as "passed",
                and this log must look the same whether or not a check found something.
              */}
              <span
                className={
                  step.status === "running"
                    ? "w-14 shrink-0 animate-pulse text-foreground"
                    : "w-14 shrink-0 text-muted-foreground"
                }
              >
                {step.status}
              </span>
              <span className="min-w-0 break-words">
                {stepLabel(step.name)}
              </span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
