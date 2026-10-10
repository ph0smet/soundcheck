"use client";

import { Search } from "lucide-react";
import { useState } from "react";

import type { AssuranceProfile, ProfileFeature } from "@/lib/contract";
import type { Tone } from "@/lib/domain";

import { CopyButton, TONE_BG, TONE_TEXT } from "../ui";

const GROUPS: { key: "modeled" | "conservative" | "unsupported"; title: string; tone: Tone; meaning: string }[] = [
  {
    key: "modeled",
    title: "Modeled",
    tone: "proved",
    meaning: "Encoded exactly. A proof covers this behavior.",
  },
  {
    key: "conservative",
    title: "Conservative",
    tone: "vacuous",
    meaning: "Over-approximated. It may over-report, but it never produces a false proof.",
  },
  {
    key: "unsupported",
    title: "Unsupported",
    tone: "unknown",
    meaning: "Outside the fragment. The whole result becomes unknown instead of a guess.",
  },
];

export function ProfileView({ profile }: { profile: AssuranceProfile }) {
  const [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const match = (feature: ProfileFeature) =>
    !needle || feature.code.includes(needle) || feature.description.toLowerCase().includes(needle);
  const total = profile.modeled.length + profile.conservative.length + profile.unsupported.length;

  return (
    <div className="space-y-6 p-4 md:p-6">
      <section className="grid gap-px overflow-hidden rounded-xl border border-line bg-line shadow-card md:grid-cols-[1.4fr_repeat(3,1fr)]">
        <div className="bg-surface p-5">
          <p className="text-2xs text-ink-3">Profile identity</p>
          <div className="mt-1 flex items-center gap-2">
            <p className="truncate font-mono text-[15px] font-semibold">{profile.id}</p>
            <CopyButton text={profile.id} label="Copy" />
          </div>
          <p className="mt-2 text-[13px] leading-relaxed text-ink-2">{profile.target}</p>
          <p className="mt-3 font-mono text-2xs text-ink-3">
            connector {profile.connector} · version {profile.version} · schema v{profile.schema_version}
          </p>
        </div>
        {GROUPS.map((group) => {
          const count = profile[group.key].length;
          return (
            <a key={group.key} href={`#${group.key}`} className="group bg-surface p-5 transition-colors hover:bg-surface-2">
              <div className="flex items-center gap-2">
                <span className={`size-2 rounded-full ${TONE_BG[group.tone]}`} />
                <p className="text-[13px] font-medium">{group.title}</p>
              </div>
              <p className={`mt-2 font-mono text-[28px] font-semibold leading-none tabular-nums ${TONE_TEXT[group.tone]}`}>{count}</p>
              <div className="mt-3 h-1 overflow-hidden rounded-full bg-surface-3">
                <div className={`h-full ${TONE_BG[group.tone]}`} style={{ width: `${(count / total) * 100}%` }} />
              </div>
              <p className="mt-3 text-xs leading-snug text-ink-2">{group.meaning}</p>
            </a>
          );
        })}
      </section>

      <div className="relative max-w-sm">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-ink-3" />
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filter features"
          aria-label="Filter features"
          className="h-8 w-full rounded-md border border-line bg-surface pl-8 pr-3 text-[13px] outline-none placeholder:text-ink-3 hover:border-line-strong focus:border-ink"
        />
      </div>

      {GROUPS.map((group) => {
        const features = profile[group.key].filter(match);
        return (
          <section key={group.key} id={group.key} className="scroll-mt-6">
            <div className="mb-2 flex items-baseline gap-2">
              <h2 className={`text-[13px] font-semibold ${TONE_TEXT[group.tone]}`}>{group.title}</h2>
              <span className="font-mono text-2xs text-ink-3">{features.length}</span>
            </div>
            <div className="overflow-hidden rounded-xl border border-line bg-surface shadow-card">
              {features.length === 0 ? (
                <p className="px-4 py-3 text-[13px] text-ink-3">No matching features.</p>
              ) : (
                <ul className="divide-y divide-line">
                  {features.map((feature) => (
                    <li key={feature.code} className="grid gap-1 px-4 py-2.5 md:grid-cols-[300px_1fr] md:gap-4">
                      <code className="font-mono text-[12.5px] text-ink">{feature.code}</code>
                      <p className="text-[13px] leading-relaxed text-ink-2">{feature.description}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        );
      })}
    </div>
  );
}
