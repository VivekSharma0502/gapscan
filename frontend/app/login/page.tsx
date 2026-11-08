import type { Metadata } from "next";
import { Suspense } from "react";

import { LoginForm } from "@/components/auth/login-form";
import { PRODUCT_NAME } from "@/lib/product";

export const metadata: Metadata = {
  title: "Sign in",
  robots: { index: false, follow: false },
};

export default function LoginPage() {
  return (
    <main className="mx-auto flex w-full max-w-sm flex-1 flex-col gap-6 px-4 py-10 sm:py-14">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Sign in to {PRODUCT_NAME}
        </h1>
        <p className="mt-1 text-sm text-pretty text-muted-foreground">
          New here? Signing in creates your account and unlocks your full
          reports.
        </p>
      </div>
      {/* The return path is in the query string, which is only known per request. */}
      <Suspense>
        <LoginForm />
      </Suspense>
    </main>
  );
}
