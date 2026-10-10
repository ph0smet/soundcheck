"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useEffect, useLayoutEffect, useSyncExternalStore } from "react";

import { applyPreference, readPreference, THEME_KEY, type ThemePreference } from "./theme";

const OPTIONS: { value: ThemePreference; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
];

const CHANGE_EVENT = "soundcheck-theme-change";

function subscribe(onChange: () => void) {
  window.addEventListener(CHANGE_EVENT, onChange);
  window.addEventListener("storage", onChange);
  return () => {
    window.removeEventListener(CHANGE_EVENT, onChange);
    window.removeEventListener("storage", onChange);
  };
}

function choose(next: ThemePreference) {
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {}
  applyPreference(next);
  window.dispatchEvent(new Event(CHANGE_EVENT));
}

export function ThemeSwitcher() {
  const preference = useSyncExternalStore(subscribe, readPreference, () => "system" as const);

  // Re-applies after React's dev remount resets <html> attributes; a no-op in production.
  useLayoutEffect(() => applyPreference(readPreference()), []);

  useEffect(() => {
    if (preference !== "system") return;
    const media = matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyPreference("system");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [preference]);

  return (
    <div
      role="radiogroup"
      aria-label="Color theme"
      className="flex items-center rounded-md border border-line bg-surface-2 p-0.5"
    >
      {OPTIONS.map(({ value, label, icon: Icon }) => {
        const active = preference === value;
        return (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={label}
            title={label}
            onClick={() => choose(value)}
            className={`flex h-6 flex-1 items-center justify-center gap-1.5 rounded-[5px] text-2xs font-medium transition-colors ${
              active ? "bg-surface text-ink shadow-card" : "text-ink-3 hover:text-ink-2"
            }`}
          >
            <Icon className="size-3.5" strokeWidth={1.75} />
            <span>{label}</span>
          </button>
        );
      })}
    </div>
  );
}
