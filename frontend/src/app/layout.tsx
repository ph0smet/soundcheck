import type { Metadata } from "next";
import localFont from "next/font/local";

import { AppShell } from "@/components/shell/app-shell";
import { SIDEBAR_BOOTSTRAP, THEME_BOOTSTRAP } from "@/components/shell/theme";

import "./globals.css";

// Self-hosted from the pinned @fontsource-variable packages (SIL OFL 1.1), so
// builds need no network access to Google Fonts and are reproducible.
const instrument = localFont({
  variable: "--font-instrument",
  src: "../../node_modules/@fontsource-variable/instrument-sans/files/instrument-sans-latin-wght-normal.woff2",
  weight: "400 700",
  style: "normal",
  display: "swap",
});

const jetbrains = localFont({
  variable: "--font-jetbrains",
  src: "../../node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2",
  weight: "100 800",
  style: "normal",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "Soundcheck", template: "%s · Soundcheck" },
  description:
    "Proof-or-counterexample for declarative security policy. Verify Kong configurations with an SMT solver.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      data-theme="light"
      suppressHydrationWarning
      className={`${instrument.variable} ${jetbrains.variable} antialiased`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP + SIDEBAR_BOOTSTRAP }} />
      </head>
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
