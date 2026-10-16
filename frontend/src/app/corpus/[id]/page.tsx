import { ArrowLeft, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { LiveCheck } from "@/components/corpus/live-check";
import { CaseConfig } from "@/components/corpus/case-config";
import { VerifyOutcome } from "@/components/results/verify-result";
import { Chip, Eyebrow, Panel } from "@/components/ui";
import { formalStatement, propertyInfo } from "@/lib/domain";
import { caseIds, getCase } from "@/lib/server/corpus";

export async function generateStaticParams() {
  return (await caseIds()).map((id) => ({ id }));
}

export async function generateMetadata({ params }: PageProps<"/corpus/[id]">): Promise<Metadata> {
  const item = await getCase((await params).id);
  return { title: item ? item.title : "Case not found" };
}

export default async function CasePage({ params }: PageProps<"/corpus/[id]">) {
  const item = await getCase((await params).id);
  if (!item) notFound();

  const info = propertyInfo(item.spec.property);
  const ce = item.expected.counterexample;
  const params_ = Object.entries({
    "path prefix": item.spec.pathPrefix,
    method: item.spec.method,
    host: item.spec.host,
    "trusted cidr": item.spec.trustedCidr,
  }).filter(([, value]) => value);

  return (
    <div>
      <header className="border-b border-line bg-surface px-5 py-5 md:px-8 md:py-6">
        <Link href="/corpus" className="inline-flex items-center gap-1.5 text-xs font-medium text-ink-3 hover:text-ink">
          <ArrowLeft className="size-3.5" />
          Corpus
        </Link>
        <div className="mt-2 flex flex-col gap-4 md:flex-row md:items-end">
          <div className="min-w-0">
            <h1 className="text-[22px] font-semibold leading-tight tracking-[-0.02em]">{item.title}</h1>
            <p className="mt-1 font-mono text-xs text-ink-3">bench/kong/cases/{item.id}</p>
          </div>
          <Link
            href={`/verify?case=${encodeURIComponent(item.id)}`}
            className="inline-flex h-8 items-center gap-2 rounded-md bg-inverse px-3 text-[13px] font-medium text-on-inverse shadow-card transition hover:opacity-90 md:ml-auto"
          >
            <ShieldCheck className="size-3.5" />
            Open in Verify
          </Link>
        </div>
      </header>

      <div className="grid gap-4 p-4 md:p-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <Panel title="Scenario" bodyClassName="space-y-4 p-4">
            {item.scenario ? (
              item.scenario.split("\n\n").map((paragraph) => (
                <p key={paragraph} className="text-[13.5px] leading-relaxed text-ink-2">{paragraph}</p>
              ))
            ) : (
              <p className="text-[13px] text-ink-3">No scenario notes for this case.</p>
            )}
            {item.expectation && (
              <div className="rounded-lg bg-surface-2 px-3.5 py-2.5">
                <Eyebrow>Author&rsquo;s expectation</Eyebrow>
                <p className="mt-1 text-[13px] leading-relaxed text-ink">{item.expectation}</p>
              </div>
            )}
          </Panel>

          <Panel title="Property under test" bodyClassName="space-y-3 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-[13.5px] font-medium">{info?.title ?? item.spec.property}</p>
              {params_.map(([key, value]) => (
                <Chip key={key}>{key} {value}</Chip>
              ))}
            </div>
            <p className="text-[13px] text-ink-2">{info?.question}</p>
            <div className="space-y-1.5 rounded-lg bg-surface-2 px-3.5 py-3">
              {formalStatement(item.spec).map((clause) => (
                <div key={clause.text} className="flex gap-3 font-mono text-[12px] leading-relaxed">
                  {clause.label && <span className="w-20 shrink-0 text-ink-3">{clause.label}</span>}
                  <span className="min-w-0 break-words">{clause.text}</span>
                </div>
              ))}
            </div>
          </Panel>

          <CaseConfig
            config={item.config}
            flags={[
              ...(ce?.route ? [{ term: ce.route, kind: "primary" as const }] : []),
              ...(ce?.shadowed_route ? [{ term: ce.shadowed_route, kind: "secondary" as const }] : []),
            ]}
          />
        </div>

        <div className="min-w-0 space-y-4">
          <Panel title="Golden result" bodyClassName="p-4">
            <VerifyOutcome report={item.expected} source="expected.json" />
          </Panel>
          <LiveCheck spec={item.spec} config={item.config} golden={item.expected} />
        </div>
      </div>
    </div>
  );
}
