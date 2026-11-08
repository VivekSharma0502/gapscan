import type { Metadata } from "next";

import { AuthCallback } from "@/components/auth/auth-callback";

export const metadata: Metadata = {
  title: "Signing in",
  robots: { index: false, follow: false },
};

export default function AuthCallbackPage() {
  return (
    <main className="mx-auto w-full max-w-sm flex-1 px-4 py-10 sm:py-14">
      <AuthCallback />
    </main>
  );
}
