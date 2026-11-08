"use client";

import { LoaderCircle, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { buttonVariants } from "@/components/ui/button";
import { clearNextPath, readNextPath } from "@/lib/auth-redirect";
import { redeemStoredClaims } from "@/lib/claims";
import { getSupabase } from "@/lib/supabase";

export function AuthCallback() {
  const router = useRouter();
  const [retryHref, setRetryHref] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function finish() {
      // The client exchanges the code in the URL itself, and this waits for that to end.
      const session = (await getSupabase()?.auth.getSession())?.data.session;
      if (cancelled) return;
      const next = readNextPath();

      // Security: the provider's error text in the URL is not shown. Anyone can craft that
      // URL, so displaying it would let them put their own message on this site.
      if (!session) {
        setRetryHref(`/login?next=${encodeURIComponent(next)}`);
        return;
      }

      // Finished before moving on, so the next page opens on the full report. A failure
      // keeps the tokens for another try and shouldn't stop the sign-in.
      await redeemStoredClaims().catch(() => undefined);
      if (cancelled) return;
      clearNextPath();
      router.replace(next);
    }

    void finish();
    return () => {
      cancelled = true;
    };
  }, [router]);

  if (retryHref) {
    return (
      <div className="flex flex-col items-start gap-3 rounded-xl bg-card p-6 ring-1 ring-foreground/10">
        <TriangleAlert className="size-5 text-muted-foreground" aria-hidden />
        <div>
          <h1 className="text-lg font-semibold tracking-tight">
            We couldn&apos;t sign you in
          </h1>
          <p className="mt-1 text-sm text-pretty text-muted-foreground">
            Sign-in links expire, and only work in the browser that asked for
            them. Please request a new one here.
          </p>
        </div>
        <Link href={retryHref} className={buttonVariants({ variant: "outline" })}>
          Back to sign in
        </Link>
      </div>
    );
  }

  return (
    <div
      role="status"
      className="flex items-center gap-2 text-sm text-muted-foreground"
    >
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      Signing you in…
    </div>
  );
}
