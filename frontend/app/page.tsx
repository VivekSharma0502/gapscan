import { Cookie, Layers, Lock, Mail, ShieldCheck } from "lucide-react";

import { ScanForm } from "@/components/scan-form";

const CHECK_GROUPS = [
  {
    icon: Lock,
    name: "HTTPS and TLS",
    detail: "Certificate expiry, TLS version, redirects and HSTS.",
  },
  {
    icon: ShieldCheck,
    name: "Security headers",
    detail: "CSP, clickjacking protection, referrer and permissions policies.",
  },
  {
    icon: Cookie,
    name: "Cookies",
    detail: "Secure, HttpOnly and SameSite flags.",
  },
  {
    icon: Mail,
    name: "DNS and email",
    detail: "SPF, DMARC and CAA records.",
  },
  {
    icon: Layers,
    name: "CMS",
    detail: "Whether your WordPress version is on show.",
  },
];

export default function Home() {
  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col px-4">
      <section className="flex flex-col items-start gap-6 py-16 sm:py-24">
        <h1 className="max-w-2xl text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
          Find the security gaps in your website
        </h1>
        <p className="max-w-xl text-base text-pretty text-muted-foreground sm:text-lg">
          Enter a domain to get a security score, findings in plain language and
          copy-paste fixes for Vercel, Netlify, nginx and Cloudflare. No account
          needed.
        </p>
        <ScanForm />
        <p className="max-w-lg text-sm text-muted-foreground">
          Quick scans are passive. We only read what your site already shows any
          visitor.
        </p>
      </section>

      <section aria-labelledby="checks-heading" className="border-t py-12">
        <h2
          id="checks-heading"
          className="text-sm font-medium text-muted-foreground"
        >
          What a quick scan checks
        </h2>
        <ul className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {CHECK_GROUPS.map(({ icon: Icon, name, detail }) => (
            <li key={name} className="flex gap-3">
              <Icon
                className="mt-0.5 size-4 shrink-0 text-muted-foreground"
                aria-hidden
              />
              <div>
                <h3 className="text-sm font-medium">{name}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{detail}</p>
              </div>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
