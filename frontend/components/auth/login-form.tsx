"use client";

import { LoaderCircle, MailCheck } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

import { useAuth } from "@/components/auth/auth-provider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  authCallbackUrl,
  rememberSignIn,
  safeNextPath,
} from "@/lib/auth-redirect";
import { getSupabase, isAuthConfigured } from "@/lib/supabase";

const ERROR_ID = "login-error";
const GENERIC_ERROR = "We couldn't start sign-in. Please try again.";
const RATE_LIMIT_ERROR =
  "Too many sign-in emails were sent. Wait a few minutes and try again.";

type Status = "idle" | "github" | "email" | "sent";

export function LoginForm() {
  const router = useRouter();
  const next = safeNextPath(useSearchParams().get("next"));
  const { user } = useAuth();
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const busy = status === "github" || status === "email";

  // Also moves this tab along when the magic link finishes in another one.
  useEffect(() => {
    if (user) router.replace(next);
  }, [user, next, router]);

  async function signInWithGitHub() {
    const supabase = getSupabase();
    if (!supabase || busy) return;
    setError(null);
    setStatus("github");
    rememberSignIn(next, "github");
    // No extra scopes: login needs an identity, and repo access is the GitHub App's job.
    const { error: failure } = await supabase.auth.signInWithOAuth({
      provider: "github",
      options: { redirectTo: authCallbackUrl() },
    });
    if (failure) {
      setStatus("idle");
      setError(GENERIC_ERROR);
    }
  }

  async function sendMagicLink(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const supabase = getSupabase();
    const address = email.trim();
    if (!supabase || busy || !address) return;
    setError(null);
    setStatus("email");
    rememberSignIn(next, "email");
    const { error: failure } = await supabase.auth.signInWithOtp({
      email: address,
      options: { emailRedirectTo: authCallbackUrl() },
    });
    if (failure) {
      setStatus("idle");
      setError(failure.status === 429 ? RATE_LIMIT_ERROR : GENERIC_ERROR);
      return;
    }
    setStatus("sent");
  }

  if (!isAuthConfigured) {
    return (
      <p className="text-sm text-muted-foreground">
        Sign-in isn&apos;t set up on this server yet.
      </p>
    );
  }

  if (status === "sent") {
    return (
      <div role="status" className="flex flex-col items-start gap-3">
        <MailCheck className="size-5 text-muted-foreground" aria-hidden />
        <p className="text-sm text-pretty wrap-anywhere">
          We sent a sign-in link to <strong>{email.trim()}</strong>.
        </p>
        <p className="text-sm text-pretty text-muted-foreground">
          Open it in this browser on this device. Links opened anywhere else
          won&apos;t work.
        </p>
        <Button variant="outline" onClick={() => setStatus("idle")}>
          Use a different email
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <Button onClick={signInWithGitHub} disabled={busy} className="h-11">
        {status === "github" && (
          <LoaderCircle className="animate-spin" aria-hidden />
        )}
        Continue with GitHub
      </Button>

      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        <span className="h-px flex-1 bg-border" />
        or
        <span className="h-px flex-1 bg-border" />
      </div>

      <form onSubmit={sendMagicLink} className="flex flex-col gap-2">
        <Input
          type="email"
          name="email"
          required
          aria-label="Email address"
          placeholder="you@example.com"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          autoComplete="email"
          maxLength={320}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? ERROR_ID : undefined}
          className="h-11 px-3.5"
        />
        <Button
          type="submit"
          variant="outline"
          disabled={busy || !email.trim()}
          className="h-11"
        >
          {status === "email" && (
            <LoaderCircle className="animate-spin" aria-hidden />
          )}
          Email me a sign-in link
        </Button>
      </form>

      {error && (
        <p id={ERROR_ID} role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
