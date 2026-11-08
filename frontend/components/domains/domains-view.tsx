"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle, Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { useAuth } from "@/components/auth/auth-provider";
import { DomainCard } from "@/components/domains/domain-card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { addDomain, listDomains } from "@/lib/api";

const DOMAINS_KEY = ["domains"];
const ERROR_ID = "add-domain-error";

function AddDomainForm() {
  const [hostname, setHostname] = useState("");
  const queryClient = useQueryClient();
  const add = useMutation({
    mutationFn: addDomain,
    onSuccess() {
      setHostname("");
      return queryClient.invalidateQueries({ queryKey: DOMAINS_KEY });
    },
  });
  const error = add.error?.message;

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = hostname.trim();
    if (trimmed && !add.isPending) add.mutate(trimmed);
  }

  return (
    <form onSubmit={submit} noValidate className="w-full max-w-lg">
      <div className="flex flex-col gap-2 sm:flex-row">
        <Input
          name="hostname"
          aria-label="Domain to add"
          placeholder="yoursite.com"
          value={hostname}
          onChange={(event) => setHostname(event.target.value)}
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
          disabled={add.isPending || !hostname.trim()}
          className="h-11 px-5"
        >
          {add.isPending ? (
            <LoaderCircle className="animate-spin" aria-hidden />
          ) : (
            <Plus aria-hidden />
          )}
          Add domain
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

function Loading() {
  return (
    <div
      role="status"
      className="flex items-center gap-2 text-sm text-muted-foreground"
    >
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      Loading your domains…
    </div>
  );
}

export function DomainsView() {
  const router = useRouter();
  const { user, loading } = useAuth();
  const signedIn = Boolean(user);

  useEffect(() => {
    if (!loading && !signedIn) router.replace("/login?next=/domains");
  }, [loading, signedIn, router]);

  const domains = useQuery({
    queryKey: DOMAINS_KEY,
    queryFn: ({ signal }) => listDomains(signal),
    enabled: signedIn,
  });

  if (!signedIn) return <Loading />;

  return (
    <>
      <div className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">My domains</h1>
        <p className="text-sm text-pretty text-muted-foreground">
          Prove you own a domain to unlock full scans, which look for exposed
          files like <code>.env</code> and <code>.git</code>.
        </p>
      </div>

      <AddDomainForm />

      {domains.isPending && <Loading />}
      {domains.isError && (
        <div className="flex flex-col items-start gap-2">
          <p role="alert" className="text-sm text-destructive">
            {domains.error.message}
          </p>
          <Button variant="outline" onClick={() => domains.refetch()}>
            Try again
          </Button>
        </div>
      )}
      {domains.data?.length === 0 && (
        <p className="text-sm text-muted-foreground">
          You haven&apos;t added a domain yet.
        </p>
      )}
      {domains.data && domains.data.length > 0 && (
        <div className="flex flex-col gap-4">
          {domains.data.map((domain) => (
            <DomainCard key={domain.id} domain={domain} />
          ))}
        </div>
      )}
    </>
  );
}
