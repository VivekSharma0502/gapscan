"use client";

import { ArrowRight, LoaderCircle } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useStartScan } from "@/hooks/use-start-scan";

const ERROR_ID = "scan-form-error";

export function ScanForm() {
  const [target, setTarget] = useState("");
  const startScan = useStartScan();
  // Stays busy after success too, until the next page takes over.
  const busy = startScan.isPending || startScan.isSuccess;
  const error = startScan.error?.message;

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = target.trim();
    // Only an empty check here. The API decides what can be scanned, and its
    // SSRF rules shouldn't be copied into code a visitor can edit.
    if (trimmed && !busy) startScan.mutate(trimmed);
  }

  return (
    <form onSubmit={submit} noValidate className="w-full max-w-lg">
      <div className="flex flex-col gap-2 sm:flex-row">
        <Input
          name="target"
          aria-label="Website domain"
          placeholder="yoursite.com"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
          inputMode="url"
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          maxLength={2048}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? ERROR_ID : undefined}
          className="h-11 px-3.5 font-mono md:text-sm"
        />
        <Button
          type="submit"
          disabled={busy || !target.trim()}
          className="h-11 px-5"
        >
          {busy ? (
            <LoaderCircle className="animate-spin" aria-hidden />
          ) : (
            <ArrowRight aria-hidden />
          )}
          {busy ? "Starting…" : "Scan site"}
        </Button>
      </div>
      {error && (
        <p id={ERROR_ID} role="alert" className="mt-2 text-sm text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}
