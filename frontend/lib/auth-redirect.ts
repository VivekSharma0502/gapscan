// Where to send someone once sign-in finishes.
//
// The path is kept in localStorage, not added to the redirect URL, so Supabase's allowlist
// can stay one exact URL. localStorage rather than sessionStorage because a magic link
// opens in a new tab.

const STORAGE_KEY = "gapscan.auth_next";
const METHOD_KEY = "gapscan.auth_method";
const BASE = "https://gapscan.invalid";
const DEFAULT_PATH = "/dashboard";

export type SignInMethod = "github" | "email";

// Security: only paths on this site, so a crafted link can't use sign-in to bounce someone
// to a lookalike. Parsing handles the forms a prefix check misses, such as "/\evil.com".
export function safeNextPath(value: string | null | undefined): string {
  if (!value?.startsWith("/")) return DEFAULT_PATH;
  try {
    const url = new URL(value, BASE);
    return url.origin === BASE
      ? `${url.pathname}${url.search}${url.hash}`
      : DEFAULT_PATH;
  } catch {
    return DEFAULT_PATH;
  }
}

export function authCallbackUrl(): string {
  return `${window.location.origin}/auth/callback`;
}

export function rememberSignIn(path: string, method: SignInMethod): void {
  try {
    localStorage.setItem(STORAGE_KEY, path);
    localStorage.setItem(METHOD_KEY, method);
  } catch {
    // Storage is blocked. Sign-in still works and lands on the dashboard.
  }
}

export function readSignInMethod(): SignInMethod | null {
  try {
    const method = localStorage.getItem(METHOD_KEY);
    return method === "github" || method === "email" ? method : null;
  } catch {
    return null;
  }
}

// Picks the message for a failed callback. The URL's error code wins, because the stored
// method can be left over from an abandoned attempt. With neither, a callback with no error
// is a magic link opened in another browser, the one case that arrives with nothing stored.
export function signInFailureKind(
  params: URLSearchParams,
  method: SignInMethod | null,
): SignInMethod {
  if (params.get("error_code")?.startsWith("otp_")) return "email";
  return method ?? (params.has("error") ? "github" : "email");
}

export function readNextPath(): string {
  try {
    return safeNextPath(localStorage.getItem(STORAGE_KEY));
  } catch {
    return DEFAULT_PATH;
  }
}

export function clearSignIn(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(METHOD_KEY);
  } catch {
    // Nothing to clear if storage is blocked.
  }
}
