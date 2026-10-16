"use client";

import {
  BookMarked,
  FileSearch,
  GitCompareArrows,
  Library,
  ChevronLeft,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useLayoutEffect, useSyncExternalStore, type ReactNode } from "react";

import { EngineProvider, EngineStatusCard } from "./engine-status";
import { SIDEBAR_KEY } from "./theme";
import { ThemeSwitcher } from "./theme-switcher";

const NAV: { href: string; label: string; hint: string; icon: LucideIcon }[] = [
  { href: "/audit", label: "Audit", hint: "Scan configs", icon: FileSearch },
  { href: "/verify", label: "Verify", hint: "Prove a property", icon: ShieldCheck },
  { href: "/compare", label: "Compare", hint: "Decision equivalence", icon: GitCompareArrows },
  { href: "/corpus", label: "Corpus", hint: "Labeled cases", icon: Library },
  { href: "/profile", label: "Profile", hint: "Assurance boundary", icon: BookMarked },
];

export function Mark({ className = "" }: { className?: string }) {
  // A small static PNG: served as-is, so it needs no image optimizer at runtime.
  return <Image src="/soundcheck-logo.png" alt="" width={256} height={256} priority unoptimized className={className} />;
}

// The collapsed state lives on <html data-sidebar>, set before first paint by
// SIDEBAR_BOOTSTRAP, so CSS lays the sidebar out without waiting for React.
const CHANGE_EVENT = "soundcheck-sidebar-change";

function readCollapsed() {
  return document.documentElement.getAttribute("data-sidebar") === "collapsed";
}

function storedCollapsed() {
  try {
    return localStorage.getItem(SIDEBAR_KEY) === "collapsed";
  } catch {
    return false;
  }
}

function applyCollapsed(collapsed: boolean) {
  if (collapsed) document.documentElement.setAttribute("data-sidebar", "collapsed");
  else document.documentElement.removeAttribute("data-sidebar");
}

function subscribe(onChange: () => void) {
  window.addEventListener(CHANGE_EVENT, onChange);
  window.addEventListener("storage", onChange);
  return () => {
    window.removeEventListener(CHANGE_EVENT, onChange);
    window.removeEventListener("storage", onChange);
  };
}

function setCollapsed(collapsed: boolean) {
  try {
    localStorage.setItem(SIDEBAR_KEY, collapsed ? "collapsed" : "expanded");
  } catch {}
  applyCollapsed(collapsed);
  window.dispatchEvent(new Event(CHANGE_EVENT));
}

// Labels that fade and fold away when the sidebar collapses (desktop only).
// max-width (not width) animates the fold; it needs a finite expanded value to transition from.
const FOLD =
  "max-w-48 transition-[opacity,max-width] duration-300 ease-out motion-reduce:transition-none lg:collapsed:max-w-0 lg:collapsed:opacity-0";

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const collapsed = useSyncExternalStore(subscribe, readCollapsed, () => false);

  // Re-applies after React's dev remount resets <html> attributes; a no-op in production.
  useLayoutEffect(() => applyCollapsed(storedCollapsed()), []);

  return (
    <EngineProvider>
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-inverse px-3 py-2 text-on-inverse focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
      >
        Skip to content
      </a>
      <div className="flex min-h-dvh flex-col lg:flex-row">
        {/* The wrapper is what sticks, so the toggle can sit on the sidebar's edge
            without being clipped by the sidebar's own overflow. */}
        <div className="sticky top-0 z-30 shrink-0 lg:h-dvh">
          <aside
            className="flex h-full flex-col overflow-hidden border-b border-line bg-surface/90 backdrop-blur transition-[width] duration-300 ease-out motion-reduce:transition-none lg:w-64 lg:border-b-0 lg:border-r lg:bg-surface lg:collapsed:w-16"
          >
            <div className="flex items-center gap-2 px-4 py-3 lg:px-3 lg:pb-5 lg:pt-4">
              <Link
                href="/audit"
                className="flex min-w-0 flex-1 items-center gap-2.5 rounded-md lg:px-1.5"
                aria-label="Soundcheck home"
              >
                <Mark className="size-7 shrink-0" />
                <span className={`overflow-hidden whitespace-nowrap text-[15px] font-semibold tracking-[-0.01em] ${FOLD}`}>
                  soundcheck
                </span>
              </Link>
            </div>

            <nav aria-label="Primary" className="scrollbar-thin overflow-x-auto px-2 pb-2 lg:flex-1 lg:overflow-x-hidden lg:px-3 lg:pb-0">
              <p className={`hidden overflow-hidden whitespace-nowrap px-2 pb-2 text-2xs font-medium uppercase tracking-[0.08em] text-ink-3 lg:block ${FOLD}`}>
                Workspace
              </p>
              <ul className="flex gap-1 lg:flex-col lg:gap-0.5">
                {NAV.map(({ href, label, hint, icon: Icon }) => {
                  const active = pathname === href || pathname.startsWith(`${href}/`);
                  return (
                    <li key={href} className="min-w-0">
                      <Link
                        href={href}
                        aria-current={active ? "page" : undefined}
                        title={collapsed ? `${label}: ${hint}` : undefined}
                        className={`group flex min-w-0 items-center gap-2.5 overflow-hidden whitespace-nowrap rounded-md px-2.5 py-1.5 transition-colors lg:py-2 ${
                          active ? "bg-surface-3 text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"
                        }`}
                      >
                        <Icon className="size-4 shrink-0" strokeWidth={active ? 2 : 1.75} />
                        <span className={`shrink-0 overflow-hidden font-medium ${FOLD}`}>{label}</span>
                        {/* The hint yields space and truncates rather than spilling past the highlight. */}
                        <span className={`ml-auto hidden min-w-0 truncate text-2xs text-ink-3 xl:inline ${FOLD}`}>{hint}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </nav>

            <div className="hidden space-y-3 p-3 transition-[opacity,visibility] duration-300 lg:block lg:collapsed:pointer-events-none lg:collapsed:invisible lg:collapsed:opacity-0">
              <EngineStatusCard />
              <ThemeSwitcher />
            </div>
          </aside>

          {/* Desktop toggle, centred on the sidebar's right border. */}
          <button
            type="button"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-expanded={!collapsed}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="absolute -right-3 top-[22px] hidden size-6 items-center justify-center rounded-full border border-line bg-surface text-ink-3 shadow-card transition-colors hover:border-line-strong hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 lg:flex"
          >
            <ChevronLeft className="size-3.5 transition-transform duration-300 lg:collapsed:rotate-180 motion-reduce:transition-none" />
          </button>
        </div>

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
