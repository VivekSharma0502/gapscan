"use client";

import { LoaderCircle, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { buttonVariants } from "@/components/ui/button";
import {
  clearSignIn,
  readNextPath,
  readSignInMethod,
  signInFailureKind,
  type SignInMethod,
} from "@/lib/auth-redirect";
import { redeemStoredClaims } from "@/lib/claims";
import { getSupabase } from "@/lib/supabase";

const FAILURE_TEXT: Record<SignInMethod, string> = {
  github: "Sign-in with GitHub failed, please try again.",
  email:
    "Sign-in links expire, and only work in the browser that asked for them. Please request a new one here.",
};

// Supabase reports errors in the query string or the fragment, depending on the flow.
function callbackParams(): URLSearchParams {
  const params = new URLSearchParams(window.location.search);
  new URLSearchParams(window.location.hash.slice(1)).forEach((value, key) => {
    params.set(key, value);
  });
  return params;
}

interface Failure {
  kind: SignInMethod;
  retryHref: string;
}

export function AuthCallback() {
  const router = useRouter();
  const [failure, setFailure] = useState<Failure | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function finish() {
      // Read first, since the Supabase client may clean up the URL while it works.
      const params = callbackParams();
      // The client exchanges the code in the URL itself, and this waits for that to end.
      const session = (await getSupabase()?.auth.getSession())?.data.session;
      if (cancelled) return;
      const next = readNextPath();

      // Security: the provider's error text in the URL is not shown on the page. Anyone can
      // craft that URL, so displaying it would let them put their own message on this site.
      if (!session) {
        const description = params.get("error_description");
        if (description && process.env.NODE_ENV === "development") {
          console.error("Sign-in failed:", description);
        }
        setFailure({
          kind: signInFailureKind(params, readSignInMethod()),
          retryHref: `/login?next=${encodeURIComponent(next)}`,
        });
        return;
      }

      // Finished before moving on, so the next page opens on the full report. A failure
      // keeps the tokens for another try and shouldn't stop the sign-in.
      await redeemStoredClaims().catch(() => undefined);
      if (cancelled) return;
      clearSignIn();
      router.replace(next);
    }

    void finish();
    return () => {
      cancelled = true;
    };
  }, [router]);

  if (failure) {
    return (
      <div className="flex flex-col items-start gap-3 rounded-xl bg-card p-6 ring-1 ring-foreground/10">
        <TriangleAlert className="size-5 text-muted-foreground" aria-hidden />
        <div>
          <h1 className="text-lg font-semibold tracking-tight">
            We couldn&apos;t sign you in
          </h1>
          <p className="mt-1 text-sm text-pretty text-muted-foreground">
            {FAILURE_TEXT[failure.kind]}
          </p>
        </div>
        <Link
          href={failure.retryHref}
          className={buttonVariants({ variant: "outline" })}
        >
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
