import type { Metadata } from "next";

import { CorpusBrowser, type CaseSummary } from "@/components/corpus/corpus-browser";
import { PageHeader } from "@/components/ui";
import { listCases } from "@/lib/server/corpus";

export const metadata: Metadata = { title: "Corpus" };

export default async function CorpusPage() {
  const cases = await listCases();
  const summaries: CaseSummary[] = cases.map((item) => ({
    id: item.id,
    title: item.title,
    scenario: item.scenario,
    property: item.spec.property,
    verdict: item.expected.result,
    assurance: item.expected.assurance?.status ?? null,
  }));

  return (
    <div>
      <PageHeader
        title="Corpus"
        description="Real misconfiguration shapes and correct baselines, pinned from both sides. Each golden is hand-checked against intent and every counterexample is re-validated against the reference semantics."
      />
      <CorpusBrowser cases={summaries} />
    </div>
  );
}
