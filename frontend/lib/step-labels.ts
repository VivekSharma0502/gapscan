// Readable names for scan steps.
//
// Security: check ids such as "tls.cert_expired" name the problem a check looks for, so
// next to "done" they would read like a finding on every site. These labels name only
// what was examined. A step missing here falls back to its id.
const STEP_LABELS: Record<string, string> = {
  tls_probe: "Connect over TLS",
  https_fetch: "Load the homepage over HTTPS",
  http_fetch: "Load the homepage over HTTP",
  dns_lookup: "Look up DNS records",

  "tls.no_https": "HTTPS availability",
  "tls.cert_expired": "Certificate validity dates",
  "tls.cert_untrusted": "Certificate trust chain",
  "tls.cert_expiring": "Certificate renewal window",
  "tls.legacy_version": "TLS protocol version",
  "tls.no_http_redirect": "HTTP to HTTPS redirect",
  "tls.hsts_missing": "HSTS header",
  "tls.hsts_weak": "HSTS settings",

  "headers.csp_missing": "Content Security Policy header",
  "headers.csp_weak": "Content Security Policy rules",
  "headers.clickjacking": "Framing protection",
  "headers.content_type_options": "X-Content-Type-Options header",
  "headers.referrer_policy": "Referrer-Policy header",
  "headers.permissions_policy": "Permissions-Policy header",
  "headers.server_version": "Server version header",

  "cookies.secure": "Cookie Secure flag",
  "cookies.httponly": "Cookie HttpOnly flag",
  "cookies.samesite": "Cookie SameSite flag",

  "dns.spf_missing": "SPF record",
  "dns.spf_weak": "SPF policy",
  "dns.dmarc_missing": "DMARC record",
  "dns.dmarc_weak": "DMARC policy",
  "dns.caa_missing": "CAA record",
  "dns.shared_platform_domain": "Shared platform domain",

  "cms.wordpress_version": "WordPress version",

  ownership_check: "Confirm domain ownership",
  active_probes: "Request sensitive paths",
  baas_discovery: "Read the site's scripts",
  baas_probes: "Check confirmed backends",

  "baas.supabase_service_key": "Supabase keys in scripts",
  "baas.backends_found": "Backends used by the site",
  "baas.scripts_unread": "Scripts that couldn't be read",
  "baas.firebase_rtdb_public": "Firebase database rules",
  "baas.firebase_storage_listable": "Firebase storage rules",
  "baas.firebase_rtdb_protected": "Firebase database access",
  "baas.firebase_storage_protected": "Firebase storage access",

  "exposure.env_file": "Environment files",
  "exposure.git_directory": "Git folder",
  "exposure.ds_store": "Folder index files",
  "exposure.backup_file": "Backup files",
  "exposure.source_maps": "JavaScript source maps",
  "exposure.directory_listing": "Directory listings",
};

export function stepLabel(step: string): string {
  return STEP_LABELS[step] ?? step;
}
