import type { Metadata } from "next";
import { Suspense } from "react";

import { ScanLoading, ScanView } from "@/components/scan/scan-view";

export const metadata: Metadata = {
  title: "Scan results | ScanKit",
  // Security: a report lists a site's weaknesses, so search engines shouldn't index it.
  robots: { index: false, follow: false },
};

type ScanPageProps = PageProps<"/scan/[id]">;

async function ScanFromParams({ params }: Pick<ScanPageProps, "params">) {
  const { id } = await params;
  return <ScanView id={id} />;
}

export default function ScanPage({ params }: ScanPageProps) {
  return (
    <main className="mx-auto w-full max-w-4xl flex-1 px-4 py-10 sm:py-14">
      {/* Cache Components needs a boundary because the id is only known per request. */}
      <Suspense fallback={<ScanLoading />}>
        <ScanFromParams params={params} />
      </Suspense>
    </main>
  );
}
