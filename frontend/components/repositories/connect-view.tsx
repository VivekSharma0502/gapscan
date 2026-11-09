"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef } from "react";

import { useAuth } from "@/components/auth/auth-provider";
import { buttonVariants } from "@/components/ui/button";
import { linkGithubInstallation } from "@/lib/api";

const BAD_LINK_MESSAGE =
  "This link is missing the details we need. Please start again from the Repositories page.";

function Failure({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-start gap-3">
      <p role="alert" className="text-sm text-pretty text-destructive">
        {message}
      </p>
      <Link href="/repositories" className={buttonVariants()}>
        Back to Repositories
      </Link>
    </div>
  );
}

export function ConnectView() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const params = useSearchParams();
  const { user, loading } = useAuth();
  const signedIn = Boolean(user);

  const installationId = Number(params.get("installation_id"));
  const state = params.get("state");
  const validLink = Number.isSafeInteger(installationId) && installationId > 0 && Boolean(state);
  const query = params.toString();

  const { mutate, error } = useMutation({
    mutationFn: linkGithubInstallation,
    async onSuccess() {
      await queryClient.invalidateQueries({ queryKey: ["repos"] });
      // Replaced so the used link leaves the address bar and history.
      router.replace("/repositories");
    },
  });

  // The state value works once, and React runs effects twice in development.
  const sent = useRef(false);

  useEffect(() => {
    if (loading) return;
    if (!signedIn) {
      const next = `/repositories/connect?${query}`;
      router.replace(`/login?next=${encodeURIComponent(next)}`);
      return;
    }
    if (validLink && state && !sent.current) {
      sent.current = true;
      mutate({ installation_id: installationId, state });
    }
  }, [loading, signedIn, validLink, state, installationId, query, router, mutate]);

  if (!loading && signedIn && !validLink) {
    return <Failure message={BAD_LINK_MESSAGE} />;
  }
  if (error) return <Failure message={error.message} />;

  return (
    <div
      role="status"
      className="flex items-center gap-2 text-sm text-muted-foreground"
    >
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      Confirming your GitHub account…
    </div>
  );
}
