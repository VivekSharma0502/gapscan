import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { UserMenu } from "@/components/auth/user-menu";
import { ThemeToggle } from "@/components/theme-toggle";

export function SiteHeader() {
  return (
    <header className="border-b">
      <div className="mx-auto flex h-14 w-full max-w-4xl items-center justify-between px-4">
        <Link
          href="/"
          className="flex items-center gap-2 text-sm font-semibold tracking-tight"
        >
          <ShieldCheck className="size-4" aria-hidden />
          ScanKit
        </Link>
        <div className="flex items-center gap-1">
          {/* The menu reads the path, which on a scan page is only known per request. */}
          <Suspense>
            <UserMenu />
          </Suspense>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
