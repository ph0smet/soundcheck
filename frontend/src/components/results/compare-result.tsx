"use client";

import { CheckCircle2, CircleDashed, XCircle } from "lucide-react";
import { useState, type ReactNode } from "react";

import type { CompareReport, Observation, RepairReport, ServiceTarget, Witness } from "@/lib/contract";
import { isRepairReport } from "@/lib/contract";
import { COMPARE_OUTCOMES, VERDICTS, sentence, type Tone } from "@/lib/domain";

import { CodeBlock, CopyButton, Eyebrow, Tabs, TONE_TEXT, ToneBadge } from "../ui";
import { RequestLine } from "./request";
import { Readout, VerifyReportView, verifyTitle } from "./verify-result";

const COMPARISON_LABEL: Record<string, string> = {
  security_decision: "Security-decision equivalence",
  route_service: "Route & service equivalence",
  service_target: "Service-target equivalence",
  frozen_scope_preservation: "Frozen-scope repair",
  frozen_route_service_preservation: "Frozen-scope repair, route & service preserved",
  frozen_service_target_preservation: "Frozen-scope repair, service target preserved",
};

function target(value: ServiceTarget | null) {
  if (!value) return null;
  return `${value.protocol}://${value.host}:${value.port}${value.path ?? ""}`;
}

function WitnessView({ witness, title }: { witness: Witness; title: string }) {
  const rows: { label: string; pick: (o: Observation) => string | null }[] = [
    { label: "Decision", pick: (o) => o.decision },
    { label: "Route", pick: (o) => o.route },
    { label: "Service", pick: (o) => o.service },
  ];
  if (witness.before.service_target || witness.after.service_target) {
    rows.push({ label: "Target", pick: (o) => target(o.service_target) });
  }
  return (
    <section className="space-y-2.5">
      <Eyebrow>{title}</Eyebrow>
      <RequestLine request={witness.request} showSource={false} />
      <div className="overflow-hidden rounded-lg border border-line">
        <table className="w-full table-fixed text-left text-[13px]">
          <thead className="bg-surface-2 text-2xs text-ink-3">
            <tr>
              <th scope="col" className="w-24 px-3.5 py-2 font-medium">Observation</th>
              <th scope="col" className="px-3.5 py-2 font-medium">Before</th>
              <th scope="col" className="px-3.5 py-2 font-medium">After</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((row) => {
              const before = row.pick(witness.before);
              const after = row.pick(witness.after);
              const changed = before !== after;
              const cell = (value: string | null, side: "before" | "after") => (
                <td className={`truncate px-3.5 py-2 font-mono text-[12.5px] ${changed ? (side === "after" ? "font-semibold text-violated" : "text-ink") : "text-ink-2"}`}>
                  {value === "allow" || value === "deny" ? value.toUpperCase() : value ?? <span className="text-ink-3">none</span>}
                </td>
              );
              return (
                <tr key={row.label} className={changed ? "tint-violated" : undefined}>
                  <th scope="row" className="px-3.5 py-2 text-2xs font-medium text-ink-3">{row.label}</th>
                  {cell(before, "before")}
                  {cell(after, "after")}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Reason({ text }: { text: string }) {
  return (
    <section className="space-y-2.5">
      <Eyebrow>Why no exact comparison</Eyebrow>
      <p className="rounded-lg border border-line bg-surface-2 px-3.5 py-3 text-[13px] leading-relaxed text-ink-2">{text}</p>
    </section>
  );
}

function Step({
  index,
  title,
  state,
  badge,
  children,
}: {
  index: number;
  title: string;
  state: "pass" | "fail" | "skip";
  badge?: ReactNode;
  children?: ReactNode;
}) {
  const Icon = state === "pass" ? CheckCircle2 : state === "fail" ? XCircle : CircleDashed;
  const tone = state === "pass" ? "text-proved" : state === "fail" ? "text-violated" : "text-ink-3";
  return (
    <li className="group relative pl-9">
      <span className="absolute left-3 top-7 bottom-0 w-px bg-line group-last:hidden" aria-hidden />
      <Icon className={`absolute left-0 top-0.5 size-6 ${tone}`} strokeWidth={1.75} />
      <div className="flex flex-wrap items-center gap-2 pb-2">
        <p className="text-[13.5px] font-medium">
          <span className="mr-1.5 font-mono text-2xs text-ink-3">{index}</span>
          {title}
        </p>
        {badge}
      </div>
      {children && <div className="pb-6">{children}</div>}
    </li>
  );
}

function RepairView({ report }: { report: RepairReport }) {
  const contract = report.contract_result;
  const verdict = VERDICTS[contract.result];
  const contractPassed = contract.result === "proved";
  const preserved = report.result === "valid_repair";
  const regression = report.result === "out_of_scope_regression";

  return (
    <div className="space-y-6">
      <ol className="space-y-0">
        <Step
          index={1}
          title="The replacement satisfies the frozen contract"
          state={contractPassed ? "pass" : report.result === "unknown" && !contractPassed ? "skip" : "fail"}
          badge={<ToneBadge tone={verdict.tone}>{verdict.label}</ToneBadge>}
        >
          {!contractPassed && (
            <div className="space-y-4">
              <div>
                <p className="text-[13px] font-medium">{verifyTitle(contract)}</p>
                <p className="text-[13px] text-ink-2">
                  {contract.clause ? `${sentence(contract.clause.description)}.` : verdict.meaning}
                </p>
              </div>
              <VerifyReportView report={{ ...contract, frozen_spec: null }} />
            </div>
          )}
        </Step>
        <Step
          index={2}
          title="Every decision outside the frozen scope is preserved"
          state={preserved ? "pass" : regression ? "fail" : "skip"}
          badge={
            preserved ? (
              <ToneBadge tone="proved">Equivalent</ToneBadge>
            ) : regression ? (
              <ToneBadge tone="violated">Different</ToneBadge>
            ) : (
              <span className="text-2xs text-ink-3">{contractPassed ? "inconclusive" : "not checked"}</span>
            )
          }
        >
          {report.witness && <WitnessView witness={report.witness} title="Outside-scope request that changed" />}
          {report.reason && <Reason text={report.reason} />}
        </Step>
      </ol>
      <section className="space-y-2.5">
        <Eyebrow>Frozen contract</Eyebrow>
        <CodeBlock>{JSON.stringify(report.frozen_spec, null, 2)}</CodeBlock>
      </section>
    </div>
  );
}

export function CompareOutcome({
  report,
  exitCode,
  durationMs,
  command,
}: {
  report: CompareReport | RepairReport;
  exitCode: number;
  durationMs: number;
  command: string;
}) {
  const [tab, setTab] = useState<"details" | "json" | "command">("details");
  const outcome = COMPARE_OUTCOMES[report.result];
  const json = JSON.stringify(report, null, 2);
  const repair = isRepairReport(report);
  const tone: Tone = outcome.tone;

  return (
    <div className="animate-reveal space-y-4">
      <Readout
        outcome={outcome}
        title={
          <>
            {COMPARISON_LABEL[report.comparison] ?? report.comparison}
            <span className={`ml-2 font-mono text-2xs ${TONE_TEXT[tone]}`}>{report.assurance_profile}</span>
          </>
        }
        exitCode={exitCode}
        durationMs={durationMs}
      />
      <div className="border-b border-line">
        <Tabs
          label="Result views"
          value={tab}
          onChange={setTab}
          tabs={[
            { value: "details", label: "Details" },
            { value: "json", label: "JSON" },
            { value: "command", label: "CLI" },
          ]}
        />
      </div>
      {tab === "details" &&
        (repair ? (
          <RepairView report={report} />
        ) : (
          <div className="space-y-6">
            {report.witness && <WitnessView witness={report.witness} title="Distinguishing request" />}
            {report.reason && <Reason text={report.reason} />}
            {report.result === "equivalent" && (
              <p className="rounded-lg border border-line bg-surface-2 px-3.5 py-3 text-[13px] leading-relaxed text-ink-2">
                The solver proved there is no request, within the modeled semantics, on which these configs disagree.
              </p>
            )}
          </div>
        ))}
      {tab === "json" && (
        <div className="space-y-2">
          <div className="flex items-center">
            <p className="text-2xs text-ink-3">Comparison contract, schema v{report.schema_version}.</p>
            <div className="ml-auto"><CopyButton text={json} /></div>
          </div>
          <CodeBlock className="max-h-[460px]">{json}</CodeBlock>
        </div>
      )}
      {tab === "command" && (
        <div className="space-y-2">
          <div className="flex items-center">
            <p className="text-2xs text-ink-3">Reproduce this comparison locally or in CI.</p>
            <div className="ml-auto"><CopyButton text={command} /></div>
          </div>
          <CodeBlock>{`$ ${command}`}</CodeBlock>
        </div>
      )}
    </div>
  );
}
