import type { Metadata } from "next";
import { Suspense } from "react";

import {
  RepoFindingsLoading,
  RepoFindingsView,
} from "@/components/repositories/repo-findings-view";

export const metadata: Metadata = {
  title: "Repository findings",
  // Security: this page describes leaked secrets, so search engines shouldn't index it, and
  // links out of it shouldn't reveal its address.
  referrer: "no-referrer",
  robots: { index: false, follow: false },
};

type RepoPageProps = PageProps<"/repositories/[id]">;

async function RepoFromParams({ params }: Pick<RepoPageProps, "params">) {
  const { id } = await params;
  return <RepoFindingsView id={id} />;
}

export default function RepoPage({ params }: RepoPageProps) {
  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-8 px-4 py-10 sm:py-14">
      {/* Cache Components needs a boundary because the id is only known per request. */}
      <Suspense fallback={<RepoFindingsLoading />}>
        <RepoFromParams params={params} />
      </Suspense>
    </main>
  );
}
