"use client";

import { ChevronRight, Search } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";

import type { Verdict } from "@/lib/contract";
import { PROPERTIES, VERDICTS } from "@/lib/domain";

import { TONE_BG, ToneBadge } from "../ui";

export interface CaseSummary {
  id: string;
  title: string;
  scenario: string;
  property: string;
  verdict: Verdict;
  assurance: string | null;
}

const ORDER: Verdict[] = ["proved", "violated", "unknown", "vacuous", "inconsistent"];

export function CorpusBrowser({ cases }: { cases: CaseSummary[] }) {
  const [query, setQuery] = useState("");
  const [property, setProperty] = useState<string>("all");
  const [verdict, setVerdict] = useState<Verdict | "all">("all");

  const counts = useMemo(() => {
    const map = new Map<Verdict, number>();
    for (const item of cases) map.set(item.verdict, (map.get(item.verdict) ?? 0) + 1);
    return map;
  }, [cases]);

  const propertyCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const item of cases) map.set(item.property, (map.get(item.property) ?? 0) + 1);
    return map;
  }, [cases]);

  const needle = query.trim().toLowerCase();
  const visible = cases.filter(
    (item) =>
      (property === "all" || item.property === property) &&
      (verdict === "all" || item.verdict === verdict) &&
      (!needle || item.id.includes(needle) || item.scenario.toLowerCase().includes(needle)),
  );

  return (
    <div className="space-y-5 p-4 md:p-6">
      <section className="rounded-xl border border-line bg-surface p-5 shadow-card">
        <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2">
          <p>
            <span className="font-mono text-[28px] font-semibold leading-none tabular-nums">{cases.length}</span>
            <span className="ml-2 text-[13px] text-ink-2">labeled cases, each with a golden verdict</span>
          </p>
          <p className="text-xs text-ink-3">
            Gated by <code className="font-mono text-ink-2">dune test</code> on every pull request.
          </p>
        </div>
        <div className="mt-4 flex h-2.5 overflow-hidden rounded-full bg-surface-3" aria-hidden>
          {ORDER.filter((key) => counts.get(key)).map((key) => (
            <div
              key={key}
              className={`${TONE_BG[VERDICTS[key].tone]} transition-opacity ${verdict !== "all" && verdict !== key ? "opacity-25" : ""}`}
              style={{ width: `${((counts.get(key) ?? 0) / cases.length) * 100}%` }}
            />
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-1.5" role="group" aria-label="Filter by golden verdict">
          <FilterChip active={verdict === "all"} onClick={() => setVerdict("all")}>
            All <span className="text-ink-3">{cases.length}</span>
          </FilterChip>
          {ORDER.filter((key) => counts.get(key)).map((key) => (
            <FilterChip key={key} active={verdict === key} onClick={() => setVerdict(verdict === key ? "all" : key)}>
              <span className={`size-1.5 rounded-full ${TONE_BG[VERDICTS[key].tone]}`} />
              {VERDICTS[key].label} <span className="text-ink-3">{counts.get(key)}</span>
            </FilterChip>
          ))}
        </div>
      </section>

      <div className="flex flex-col gap-3 md:flex-row md:items-start">
        <div className="relative shrink-0 md:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-ink-3" />
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search cases and scenarios"
            aria-label="Search cases"
            className="h-8 w-full rounded-md border border-line bg-surface pl-8 pr-3 text-[13px] outline-none placeholder:text-ink-3 hover:border-line-strong focus:border-ink"
          />
        </div>
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by property">
          <FilterChip active={property === "all"} onClick={() => setProperty("all")}>
            Every property
          </FilterChip>
          {PROPERTIES.filter((item) => propertyCounts.get(item.id)).map((item) => (
            <FilterChip key={item.id} active={property === item.id} onClick={() => setProperty(property === item.id ? "all" : item.id)}>
              {item.title} <span className="text-ink-3">{propertyCounts.get(item.id)}</span>
            </FilterChip>
          ))}
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-line bg-surface shadow-card">
        <div className="hidden grid-cols-[minmax(0,240px)_150px_minmax(0,1fr)_120px_16px] gap-4 border-b border-line bg-surface-2 px-4 py-2 text-2xs font-medium text-ink-3 lg:grid">
          <span>Case</span>
          <span>Property</span>
          <span>Scenario</span>
          <span>Golden verdict</span>
          <span />
        </div>
        {visible.length === 0 ? (
          <p className="px-4 py-10 text-center text-[13px] text-ink-3">No cases match these filters.</p>
        ) : (
          <ul className="divide-y divide-line">
            {visible.map((item) => {
              const info = VERDICTS[item.verdict];
              const propertyTitle = PROPERTIES.find((p) => p.id === item.property)?.title ?? item.property;
              return (
                <li key={item.id}>
                  <Link
                    href={`/corpus/${item.id}`}
                    className="group grid gap-x-4 gap-y-1 px-4 py-3 transition-colors hover:bg-surface-2 lg:grid-cols-[minmax(0,240px)_150px_minmax(0,1fr)_120px_16px] lg:items-center"
                  >
                    <span className="min-w-0">
                      <span className="block truncate text-[13px] font-medium">{item.title}</span>
                      <span className="block truncate font-mono text-2xs text-ink-3">{item.id}</span>
                    </span>
                    <span className="truncate text-xs text-ink-2">{propertyTitle}</span>
                    <span className="line-clamp-2 text-xs leading-relaxed text-ink-2">{item.scenario || "No scenario notes."}</span>
                    <span className="flex items-center gap-1.5">
                      <ToneBadge tone={info.tone}>{info.label}</ToneBadge>
                    </span>
                    <ChevronRight className="hidden size-4 text-ink-3 transition-transform group-hover:translate-x-0.5 lg:block" />
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`inline-flex h-7 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 text-xs font-medium transition-colors ${
        active ? "border-ink bg-inverse text-on-inverse [&_.text-ink-3]:text-on-inverse/60" : "border-line bg-surface text-ink-2 hover:border-line-strong hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}
