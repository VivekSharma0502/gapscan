import type { Metadata } from "next";

import { DomainsView } from "@/components/domains/domains-view";

export const metadata: Metadata = {
  title: "My domains",
  robots: { index: false, follow: false },
};

export default function DomainsPage() {
  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-8 px-4 py-10 sm:py-14">
      <DomainsView />
    </main>
  );
}
