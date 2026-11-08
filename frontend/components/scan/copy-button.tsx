"use client";

import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";

const RESET_MS = 2000;
const LABELS = { idle: "Copy", copied: "Copied", failed: "Couldn't copy" };

export function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<keyof typeof LABELS>("idle");
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  async function copy() {
    let next: keyof typeof LABELS = "copied";
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // The browser refused clipboard access. The snippet can still be selected by hand.
      next = "failed";
    }
    setState(next);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), RESET_MS);
  }

  return (
    <Button variant="ghost" size="xs" onClick={copy}>
      {state === "copied" ? <Check aria-hidden /> : <Copy aria-hidden />}
      <span aria-live="polite">{LABELS[state]}</span>
    </Button>
  );
}
