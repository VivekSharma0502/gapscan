import type { Metadata } from "next";

import { RepositoriesView } from "@/components/repositories/repositories-view";

export const metadata: Metadata = {
  title: "Repositories",
  robots: { index: false, follow: false },
};

export default function RepositoriesPage() {
  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-8 px-4 py-10 sm:py-14">
      <RepositoriesView />
    </main>
  );
}
