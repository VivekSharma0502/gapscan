// Keeps the claim tokens from anonymous scans, and redeems them once the visitor signs in.
//
// Security: localStorage can be read by any script on this origin, so XSS could steal a
// token. That is acceptable here because a token can only claim one anonymous passive scan
// of a public site. It grants no account access. Tokens are never logged or put in a URL.

import { claimScans } from "@/lib/api";

const STORAGE_KEY = "gapscan.claims";
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

function writeClaims(claims: Claims): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(claims));
  } catch {
    // Storage is blocked or full. The scan still works, it just can't be claimed later.
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
  writeClaims(Object.fromEntries(newestFirst));
}

async function redeem(): Promise<string[]> {
  const sent = new Set(
    Object.values(readClaims())
      .map((claim) => claim?.token)
      .filter((token) => typeof token === "string" && token.length > 0),
  );
  if (sent.size === 0) return [];

  // Throws if the server didn't answer, which leaves the tokens here for the next visit.
  const { claimed } = await claimScans([...sent].slice(0, MAX_CLAIMS));

  // The server has now ruled on each token, and one it refused will never work. Read
  // again rather than reusing the list above, in case a new scan was saved meanwhile.
  const remaining = Object.entries(readClaims()).filter(
    ([, claim]) => !sent.has(claim?.token),
  );
  writeClaims(Object.fromEntries(remaining));
  return claimed;
}

let inFlight: Promise<string[]> | null = null;

// The callback page and the auth provider can both ask at once. One request serves both.
export function redeemStoredClaims(): Promise<string[]> {
  inFlight ??= redeem().finally(() => {
    inFlight = null;
  });
  return inFlight;
}
