import type { Metadata } from "next";
import { Suspense } from "react";

import { ConnectView } from "@/components/repositories/connect-view";

export const metadata: Metadata = {
  title: "Connect GitHub",
  // Security: this URL carries a one-time value, so it must not reach other sites.
  referrer: "no-referrer",
  robots: { index: false, follow: false },
};

export default function ConnectPage() {
  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-8 px-4 py-10 sm:py-14">
      <h1 className="text-2xl font-semibold tracking-tight">Connect GitHub</h1>
      {/* The view reads the URL's query, which is only known per request. */}
      <Suspense>
        <ConnectView />
      </Suspense>
    </main>
  );
}
