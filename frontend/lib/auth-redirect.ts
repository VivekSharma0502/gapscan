// Where to send someone once sign-in finishes.
//
// The path is kept in localStorage, not added to the redirect URL, so Supabase's allowlist
// can stay one exact URL. localStorage rather than sessionStorage because a magic link
// opens in a new tab.

const STORAGE_KEY = "scankit.auth_next";
const BASE = "https://scankit.invalid";

// Security: only paths on this site, so a crafted link can't use sign-in to bounce someone
// to a lookalike. Parsing handles the forms a prefix check misses, such as "/\evil.com".
export function safeNextPath(value: string | null | undefined): string {
  if (!value?.startsWith("/")) return "/";
  try {
    const url = new URL(value, BASE);
    return url.origin === BASE ? `${url.pathname}${url.search}${url.hash}` : "/";
  } catch {
    return "/";
  }
}

export function authCallbackUrl(): string {
  return `${window.location.origin}/auth/callback`;
}

export function rememberNextPath(path: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, path);
  } catch {
    // Storage is blocked. Sign-in still works and lands on the home page.
  }
}

export function readNextPath(): string {
  try {
    return safeNextPath(localStorage.getItem(STORAGE_KEY));
  } catch {
    return "/";
  }
}

export function clearNextPath(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to clear if storage is blocked.
  }
}
