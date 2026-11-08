// Browser-only Supabase client, used for sign-in and nothing else. App data goes through
// the FastAPI backend, which verifies the access token itself.

import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const PUBLISHABLE_KEY = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

// Anonymous scanning keeps working on a machine that hasn't set up Supabase.
export const isAuthConfigured = Boolean(SUPABASE_URL && PUBLISHABLE_KEY);

let client: SupabaseClient | null = null;

export function getSupabase(): SupabaseClient | null {
  if (!SUPABASE_URL || !PUBLISHABLE_KEY || typeof window === "undefined") {
    return null;
  }
  // Security: PKCE means a code intercepted from a redirect is useless without the
  // verifier held in this browser, unlike tokens placed directly in the URL.
  client ??= createClient(SUPABASE_URL, PUBLISHABLE_KEY, {
    auth: { flowType: "pkce" },
  });
  return client;
}

export async function getAccessToken(): Promise<string | null> {
  const result = await getSupabase()?.auth.getSession();
  return result?.data.session?.access_token ?? null;
}

// Local scope ends this browser's session without signing the user out everywhere else.
export async function signOut(): Promise<void> {
  await getSupabase()?.auth.signOut({ scope: "local" });
}
