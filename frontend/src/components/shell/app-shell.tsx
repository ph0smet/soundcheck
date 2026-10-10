"use client";

import { BookMarked, FileSearch, GitCompareArrows, Library, ShieldCheck, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

import { EngineProvider, EngineStatusCard } from "./engine-status";
import { ThemeSwitcher } from "./theme-switcher";

const NAV: { href: string; label: string; hint: string; icon: LucideIcon }[] = [
  { href: "/audit", label: "Audit", hint: "Scan configs", icon: FileSearch },
  { href: "/verify", label: "Verify", hint: "Prove a property", icon: ShieldCheck },
  { href: "/compare", label: "Compare", hint: "Decision equivalence", icon: GitCompareArrows },
  { href: "/corpus", label: "Corpus", hint: "Labeled cases", icon: Library },
  { href: "/profile", label: "Profile", hint: "Assurance boundary", icon: BookMarked },
];

export function Mark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={className}>
      <rect width="24" height="24" rx="6" className="fill-inverse" />
      <path
        d="M4.5 12.5h3l1.6-3.2 2.6 6.4 7.8-9.2"
        fill="none"
        strokeWidth="1.9"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="stroke-on-inverse"
      />
    </svg>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  return (
    <EngineProvider>
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-inverse px-3 py-2 text-on-inverse focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
      >
        Skip to content
      </a>
      <div className="flex min-h-dvh flex-col lg:flex-row">
        <aside className="sticky top-0 z-30 flex shrink-0 flex-col border-b border-line bg-surface/90 backdrop-blur lg:h-dvh lg:w-60 lg:border-b-0 lg:border-r lg:bg-surface">
          <div className="flex items-center gap-2.5 px-4 py-3 lg:px-5 lg:pb-6 lg:pt-5">
            <Link href="/audit" className="flex items-center gap-2.5" aria-label="Soundcheck home">
              <Mark className="size-6" />
              <span className="text-[15px] font-semibold tracking-[-0.01em]">soundcheck</span>
            </Link>
          </div>

          <nav aria-label="Primary" className="scrollbar-thin overflow-x-auto px-2 pb-2 lg:flex-1 lg:px-3 lg:pb-0">
            <p className="hidden px-2 pb-2 text-2xs font-medium uppercase tracking-[0.08em] text-ink-3 lg:block">
              Workspace
            </p>
            <ul className="flex gap-1 lg:flex-col lg:gap-0.5">
              {NAV.map(({ href, label, hint, icon: Icon }) => {
                const active = pathname === href || pathname.startsWith(`${href}/`);
                return (
                  <li key={href}>
                    <Link
                      href={href}
                      aria-current={active ? "page" : undefined}
                      className={`group flex items-center gap-2.5 whitespace-nowrap rounded-md px-2.5 py-1.5 transition-colors lg:py-2 ${
                        active ? "bg-surface-3 text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"
                      }`}
                    >
                      <Icon className="size-4 shrink-0" strokeWidth={active ? 2 : 1.75} />
                      <span className="font-medium">{label}</span>
                      <span className="ml-auto hidden text-2xs text-ink-3 xl:inline">{hint}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>

          <div className="hidden space-y-3 p-3 lg:block">
            <EngineStatusCard />
            <ThemeSwitcher />
          </div>
        </aside>

        <main id="main" className="min-w-0 flex-1">
          {children}
        </main>

        <div className="space-y-3 border-t border-line bg-surface p-3 lg:hidden">
          <EngineStatusCard />
          <ThemeSwitcher />
        </div>
      </div>
    </EngineProvider>
  );
}
