// Typed client for the scan API. Types mirror backend/app/api/scans.py.

import { getAccessToken, signOut } from "@/lib/supabase";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const TIMEOUT_MS = 15_000;
// Verifying waits on the site and on DNS, each of which the backend allows 20 seconds.
const VERIFY_TIMEOUT_MS = 30_000;
// Linking makes several calls to Supabase and GitHub, one after another.
const GITHUB_LINK_TIMEOUT_MS = 60_000;
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

export interface BackendFix {
  label: string;
  snippet: string | null;
  docs_url: string | null;
}

export interface Fix {
  what_it_means: string;
  how_to_fix: string;
  // Empty when the fix doesn't depend on hosting, and backend is set instead.
  platforms: Partial<Record<Platform, PlatformFix>>;
  backend: BackendFix | null;
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

export interface SkippedCheck {
  check_id: string;
  reason: string;
  not_applicable: boolean;
}

export interface BotProtectionHelp {
  name: string;
  help_url: string;
}

export interface Scan {
  id: string;
  target: string;
  mode: "quick" | "full" | "backends";
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
  grade_cap_reason: string | null;
  score_label: string | null;
  incomplete_reason: string | null;
  // Set when a platform's bot protection stopped part of the scan.
  bot_protection: BotProtectionHelp | null;
  // Set when a backend check relied on an earlier verification.
  verification_note: string | null;
  findings: Finding[];
  total_findings: number;
  skipped: SkippedCheck[];
  teaser: boolean;
  // Only on a full report for its owner.
  domain_id: string | null;
}

export type VerificationMethod = "dns" | "file";

export interface Domain {
  id: string;
  hostname: string;
  verified: boolean;
  verified_at: string | null;
  verified_method: VerificationMethod | null;
  // True for hosts like foo.vercel.app, where the owner can't edit DNS.
  shared_platform: boolean;
  instructions: {
    txt_name: string;
    txt_value: string;
    file_url: string;
    file_content: string;
  };
  // True when a record or file published under the old scankit-verify names still counts.
  legacy_names_accepted: boolean;
  created_at: string;
}

export type BaasKind = "firebase_rtdb" | "firebase_storage" | "supabase";

export type TableAccess = "readable" | "no_rows" | "refused";

export interface BackendTable {
  id: string;
  name: string;
  access: TableAccess;
  meant_to_be_public: boolean;
  last_seen_at: string;
}

export interface DomainBackend {
  id: string;
  kind: BaasKind;
  identifier: string;
  // Nothing is sent to a backend until its domain's owner has confirmed it's theirs.
  confirmed: boolean;
  first_seen_at: string;
  last_seen_at: string;
  tables: BackendTable[];
}

export type RepoLinkState = "suggested" | "confirmed" | "dismissed";

export type RepoLinkAnswer = "confirmed" | "dismissed";

export interface RepoLink {
  id: string;
  repo_id: string;
  repo_full_name: string;
  domain_id: string;
  hostname: string;
  state: RepoLinkState;
  origin: "manual" | "automatic";
  updated_at: string;
}

export interface HistoryStep {
  text: string;
  command: string | null;
}

export interface CombinedOriginal {
  id: string;
  source: "repository" | "website";
  title: string;
  masked: string;
  location: string | null;
  first_seen_at: string;
}

export interface CombinedFinding {
  id: string;
  kind: "supabase_admin" | "firebase_admin" | "firebase_config";
  severity: Severity;
  confidence: "confirmed" | "likely";
  identifier: string;
  domain_id: string;
  hostname: string;
  repo_id: string;
  repo_full_name: string;
  title: string;
  note: string | null;
  what_it_means: string;
  provider_name: string;
  rotate_steps: string[];
  rotate_url: string;
  docs_url: string;
  history_steps: HistoryStep[];
  history_docs_url: string | null;
  can_mark_rotated: boolean;
  rotated_at: string | null;
  first_seen_at: string;
  last_seen_at: string;
  originals: CombinedOriginal[];
}

export type CombinedFindingScope = { domainId: string } | { repoId: string };

export interface VerifyFailure {
  method: VerificationMethod;
  code: string;
  message: string;
}

export interface VerifyResult {
  domain: Domain;
  // Empty when verification succeeded.
  failures: VerifyFailure[];
}

export interface FullScanCreated {
  id: string;
  status: ScanJobStatus;
  reused: boolean;
}

export interface QuickScanCreated {
  id: string;
  status: ScanJobStatus;
  reused: boolean;
  claim_token: string | null;
}

export interface ScanSummary {
  id: string;
  target: string;
  mode: "quick" | "full" | "backends";
  status: ScanJobStatus;
  result_status: ResultStatus | null;
  // Null when the site couldn't be read, which can still earn a grade.
  score: number | null;
  grade: string | null;
  score_label: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface DashboardDomain {
  id: string;
  hostname: string;
  verified: boolean;
  created_at: string;
  // The newest graded scan: full if verified, otherwise quick.
  latest: ScanSummary | null;
  // The newest attempt of that kind, in any state.
  last_scan: ScanSummary | null;
  // Score change from the previous scan. Null when there's nothing fair to compare.
  trend: number | null;
}

export interface Dashboard {
  domains: DashboardDomain[];
  recent_scans: ScanSummary[];
}

export type SeverityCounts = Record<Severity, number>;

export interface RepoLatestScan extends ScanSummary {
  incomplete_reason: string | null;
}

export interface Repo {
  id: string;
  full_name: string;
  is_private: boolean;
  account_login: string;
  created_at: string;
  // Null until the repo has been scanned.
  latest_scan: RepoLatestScan | null;
  counts: SeverityCounts;
}

export interface RepoScanCreated {
  id: string;
  status: ScanJobStatus;
  reused: boolean;
}

export interface SecretGuide {
  provider: string;
  provider_name: string;
  what_it_means: string;
  rotate_steps: string[];
  // Null when it depends on which service the key belongs to.
  rotate_url: string | null;
  docs_url: string | null;
}

export interface RepoFinding {
  id: string;
  severity: Severity;
  title: string;
  rule_id: string;
  file_path: string;
  line: number;
  commit_sha: string;
  masked: string;
  first_seen_at: string;
  note: string | null;
  // Null only if the finding's guide has since been removed.
  guide: SecretGuide | null;
}

export interface RepoFindings {
  id: string;
  full_name: string;
  is_private: boolean;
  history_warning: string;
  latest_scan: RepoLatestScan | null;
  counts: SeverityCounts;
  findings: RepoFinding[];
}

export interface GithubLinkResult {
  account_login: string;
  repositories: number;
}

export interface ScanPage {
  items: ScanSummary[];
  total: number;
  limit: number;
  offset: number;
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

async function send(
  path: string,
  init: RequestInit,
  token: string | null,
  timeoutMs: number,
): Promise<Response> {
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);

  try {
    return await fetch(`${API_URL}${path}`, {
      ...init,
      headers,
      signal,
      cache: "no-store",
    });
  } catch (error) {
    // The caller cancelled, so this isn't a failure to report.
    if (init.signal?.aborted) throw error;
    throw new ApiError(UNREACHABLE_MESSAGE, 0);
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  timeoutMs: number = TIMEOUT_MS,
): Promise<T> {
  const token = await getAccessToken();
  let response = await send(path, init, token, timeoutMs);

  // Supabase refreshes tokens before they expire, so a refusal means this session is
  // really dead. End it and carry on as a visitor. The API refuses before doing any
  // work, so sending the request again can't start a second scan.
  if (response.status === 401 && token) {
    await signOut();
    response = await send(path, init, null, timeoutMs);
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

export function listDomains(signal?: AbortSignal): Promise<Domain[]> {
  return request("/api/domains", { signal });
}

export function addDomain(hostname: string): Promise<Domain> {
  return request("/api/domains", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hostname }),
  });
}

export function deleteDomain(id: string): Promise<void> {
  return request(`/api/domains/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function verifyDomain(id: string): Promise<VerifyResult> {
  return request(
    `/api/domains/${encodeURIComponent(id)}/verify`,
    { method: "POST" },
    VERIFY_TIMEOUT_MS,
  );
}

export function listBackends(
  domainId: string,
  signal?: AbortSignal,
): Promise<DomainBackend[]> {
  return request(`/api/domains/${encodeURIComponent(domainId)}/backends`, {
    signal,
  });
}

export function confirmBackend(
  domainId: string,
  backendId: string,
  confirmed: boolean,
): Promise<DomainBackend> {
  return request(
    `/api/domains/${encodeURIComponent(domainId)}/backends/${encodeURIComponent(backendId)}/confirm`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirmed }),
    },
  );
}

export function setTablePublic(
  domainId: string,
  backendId: string,
  tableId: string,
  meantToBePublic: boolean,
): Promise<BackendTable> {
  return request(
    `/api/domains/${encodeURIComponent(domainId)}/backends/${encodeURIComponent(backendId)}/tables/${encodeURIComponent(tableId)}/public`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ meant_to_be_public: meantToBePublic }),
    },
  );
}

export function startBackendCheck(id: string): Promise<FullScanCreated> {
  return request(`/api/domains/${encodeURIComponent(id)}/check-backends`, {
    method: "POST",
  });
}

export function startFullScan(id: string): Promise<FullScanCreated> {
  return request(`/api/domains/${encodeURIComponent(id)}/scan`, {
    method: "POST",
  });
}

export function getGithubInstallUrl(): Promise<{ url: string }> {
  return request("/api/github/install-url", { method: "POST" });
}

export function linkGithubInstallation(link: {
  installation_id: number;
  state: string;
}): Promise<GithubLinkResult> {
  return request(
    "/api/github/installations/link",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(link),
    },
    GITHUB_LINK_TIMEOUT_MS,
  );
}

export function listRepos(signal?: AbortSignal): Promise<Repo[]> {
  return request("/api/repos", { signal });
}

export function startRepoScan(id: string): Promise<RepoScanCreated> {
  return request(`/api/repos/${encodeURIComponent(id)}/scan`, {
    method: "POST",
  });
}

export function getRepoFindings(
  id: string,
  signal?: AbortSignal,
): Promise<RepoFindings> {
  return request(`/api/repos/${encodeURIComponent(id)}/findings`, { signal });
}

export function listRepoLinks(signal?: AbortSignal): Promise<RepoLink[]> {
  return request("/api/repo-links", { signal });
}

export function createRepoLink(
  repoId: string,
  domainId: string,
): Promise<RepoLink> {
  return request("/api/repo-links", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_id: repoId, domain_id: domainId }),
  });
}

export function setRepoLinkState(
  id: string,
  state: RepoLinkAnswer,
): Promise<RepoLink> {
  return request(`/api/repo-links/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ state }),
  });
}

export function removeRepoLink(id: string): Promise<void> {
  return request(`/api/repo-links/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function listCombinedFindings(
  scope: CombinedFindingScope,
  signal?: AbortSignal,
): Promise<CombinedFinding[]> {
  const query =
    "domainId" in scope
      ? `domain_id=${encodeURIComponent(scope.domainId)}`
      : `repo_id=${encodeURIComponent(scope.repoId)}`;
  return request(`/api/combined-findings?${query}`, { signal });
}

export function markCombinedFindingRotated(
  id: string,
): Promise<CombinedFinding> {
  return request(`/api/combined-findings/${encodeURIComponent(id)}/rotated`, {
    method: "POST",
  });
}

export function getDashboard(signal?: AbortSignal): Promise<Dashboard> {
  return request("/api/dashboard", { signal });
}

export function listDomainScans(
  id: string,
  options: { limit: number; offset?: number; scoredOnly?: boolean },
  signal?: AbortSignal,
): Promise<ScanPage> {
  const query = new URLSearchParams({
    limit: String(options.limit),
    offset: String(options.offset ?? 0),
    scored_only: String(options.scoredOnly ?? false),
  });
  return request(`/api/domains/${encodeURIComponent(id)}/scans?${query}`, {
    signal,
  });
}

export function claimScans(tokens: string[]): Promise<{ claimed: string[] }> {
  return request("/api/scans/claim", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tokens }),
  });
}

export function getScan(id: string, signal?: AbortSignal): Promise<Scan> {
  return request(`/api/scans/${encodeURIComponent(id)}`, { signal });
}
