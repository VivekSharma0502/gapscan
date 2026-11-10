import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";

import { Providers } from "@/components/providers";
import { SiteHeader } from "@/components/site-header";
import { PRODUCT_NAME } from "@/lib/product";

import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  // Pages set only their own part, like "Sign in", and the name is added here.
  title: { default: PRODUCT_NAME, template: `%s | ${PRODUCT_NAME}` },
  description: "Security checks for websites and GitHub repos.",
};

// Runs before first paint, so a visitor who chose light never sees a dark flash.
// A fixed string with no outside input, so it can't be used to inject a script.
const THEME_SCRIPT = `(function(){try{if(localStorage.getItem("gapscan.theme")==="light")document.documentElement.classList.remove("dark")}catch(e){}})()`;

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      // The inline script may change the class before React hydrates.
      suppressHydrationWarning
      className={`dark ${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="flex min-h-full flex-col">
        <Providers>
          <SiteHeader />
          {children}
        </Providers>
      </body>
    </html>
  );
}
