// Keeps the claim tokens from anonymous scans, so Phase 2 can attach them to a new account.
//
// Security: localStorage can be read by any script on this origin, so XSS could steal a
// token. That is acceptable here because a token can only claim one anonymous passive scan
// of a public site. It grants no account access. Tokens are never logged or put in a URL.

const STORAGE_KEY = "scankit.claims";
const MAX_CLAIMS = 20;

interface StoredClaim {
  token: string;
  savedAt: number;
}

type Claims = Record<string, StoredClaim>;

function readClaims(): Claims {
  try {
    const parsed: unknown = JSON.parse(
      localStorage.getItem(STORAGE_KEY) ?? "{}",
    );
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Claims)
      : {};
  } catch {
    return {};
  }
}

export function saveClaim(scanId: string, token: string): void {
  const claims: Claims = {
    ...readClaims(),
    [scanId]: { token, savedAt: Date.now() },
  };
  const newestFirst = Object.entries(claims)
    .sort(([, a], [, b]) => b.savedAt - a.savedAt)
    .slice(0, MAX_CLAIMS);
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify(Object.fromEntries(newestFirst)),
    );
  } catch {
    // Storage is blocked or full. The scan still works, it just can't be claimed later.
  }
}
