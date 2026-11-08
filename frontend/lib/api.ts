// Typed client for the scan API. Types mirror backend/app/api/scans.py.

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TIMEOUT_MS = 15_000;
const UNREACHABLE_MESSAGE =
  "We couldn't reach the scanner. Check your connection and try again.";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Platform = "vercel" | "netlify" | "nginx" | "cloudflare";
export type ScanJobStatus = "queued" | "running" | "done" | "failed";
export type ResultStatus = "complete" | "partial" | "incomplete";

export interface PlatformFix {
  instructions: string;
  // Null when the platform has no config for this fix.
  snippet: string | null;
}

export interface Fix {
  what_it_means: string;
  how_to_fix: string;
  platforms: Record<Platform, PlatformFix>;
}

export interface Finding {
  check_id: string;
  category: string;
  severity: Severity;
  title: string;
  evidence: string;
  // Null only if the finding's check has since been removed.
  fix: Fix | null;
}

export interface ProgressStep {
  name: string;
  status: "done" | "running";
}

export interface Scan {
  id: string;
  target: string;
  status: ScanJobStatus;
  progress: {
    completed: number;
    total: number;
    current: string | null;
    steps: ProgressStep[];
  };
  result_status: ResultStatus | null;
  score: number | null;
  grade: string | null;
  score_label: string | null;
  incomplete_reason: string | null;
  findings: Finding[];
  total_findings: number;
  teaser: boolean;
}

export interface QuickScanCreated {
  id: string;
  status: ScanJobStatus;
  reused: boolean;
  claim_token: string | null;
}

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

// The API has three error shapes: FastAPI's `detail` string, Pydantic's `detail`
// list, and the rate limiter's `error`, whose text isn't written for visitors.
function errorMessage(status: number, body: unknown): string {
  if (isRecord(body)) {
    const { detail } = body;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && isRecord(detail[0])) {
      const { msg } = detail[0];
      if (typeof msg === "string") return msg.replace(/^Value error, /, "");
    }
  }
  if (status === 429) {
    return "Too many scans from your network. Wait a minute and try again.";
  }
  return "Something went wrong. Please try again.";
}

async function request<T>(
  path: string,
  init: RequestInit & { signal?: AbortSignal } = {},
): Promise<T> {
  const timeout = AbortSignal.timeout(TIMEOUT_MS);
  const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      signal,
      cache: "no-store",
    });
  } catch (error) {
    // The caller cancelled, so this isn't a failure to report.
    if (init.signal?.aborted) throw error;
    throw new ApiError(UNREACHABLE_MESSAGE, 0);
  }

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(errorMessage(response.status, body), response.status);
  }
  return body as T;
}

export function startQuickScan(target: string): Promise<QuickScanCreated> {
  return request("/api/scans/quick", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
}

export function getScan(id: string, signal?: AbortSignal): Promise<Scan> {
  return request(`/api/scans/${encodeURIComponent(id)}`, { signal });
}
