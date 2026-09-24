"use client";

import { AlertTriangle, CircleSlash, FileLock2, ShieldAlert } from "lucide-react";
import { useState, type ReactNode } from "react";

import type { Assurance, Counterexample, FrozenSpec, VerifyReport } from "@/lib/contract";
import { ASSURANCE, VERDICTS, humanize, propertyInfo, sentence, type OutcomeInfo } from "@/lib/domain";

import { Chip, CodeBlock, CopyButton, Eyebrow, Tabs, TONE_BG, TONE_TEXT, ToneBadge } from "../ui";
import { RequestLine, Trace, TraceStep } from "./request";

export function Readout({
  outcome,
  title,
  subtitle,
  exitCode,
  durationMs,
  source,
}: {
  outcome: OutcomeInfo;
  title: ReactNode;
  subtitle?: ReactNode;
  exitCode?: number | null;
  durationMs?: number;
  source?: string;
}) {
  const code = exitCode ?? outcome.exitCode;
  return (
    <div className="relative overflow-hidden rounded-lg border border-line bg-surface">
      <span className={`absolute inset-y-0 left-0 w-1 ${TONE_BG[outcome.tone]}`} aria-hidden />
      <div className="py-4 pl-5 pr-4">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <p className={`font-mono text-[22px] font-semibold uppercase leading-none tracking-[0.04em] ${TONE_TEXT[outcome.tone]}`}>
            {outcome.label}
          </p>
          <div className="flex items-center gap-1.5">
            {code !== null && code !== undefined && <Chip title="Process exit code, as used in CI gates">exit {code}</Chip>}
            {durationMs !== undefined && <Chip title="Wall-clock time including solver">{formatDuration(durationMs)}</Chip>}
            {source && <Chip>{source}</Chip>}
          </div>
        </div>
        <p className="mt-2.5 text-[13.5px] font-medium text-ink">{title}</p>
        <p className="mt-0.5 text-[13px] leading-relaxed text-ink-2">{subtitle ?? outcome.meaning}</p>
      </div>
    </div>
  );
}

export function formatDuration(ms: number) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  return (
    <section className="space-y-2.5">
      <div className="flex items-center gap-2">
        <Eyebrow>{title}</Eyebrow>
        {aside && <div className="ml-auto">{aside}</div>}
      </div>
      {children}
    </section>
  );
}

function CounterexampleView({ report, ce }: { report: VerifyReport; ce: Counterexample }) {
  const mustAllow = report.clause?.kind === "must_allow";
  const shadowing = ce.shadowed_route !== null;
  const sourceMatters = ["admin-api-not-reachable", "network-restricted-access"].includes(report.property);

  const steps: ReactNode[] = [<TraceStep key="req" label="Request" value={`${ce.action || "ANY"} ${ce.path}`} />];
  if (ce.route) steps.push(<TraceStep key="route" label={shadowing ? "Served by route" : "Route"} value={ce.route} />);
  if (ce.service) steps.push(<TraceStep key="service" label="Service" value={ce.service} />);
  steps.push(
    <TraceStep
      key="decision"
      label="Decision"
      strong
      value={<span className="text-violated">{mustAllow ? "Not definitely allowed" : "Allowed"}</span>}
    />,
  );

  return (
    <Section
      title="Counterexample"
      aside={<span className="text-2xs text-ink-3">Dashed values were left free by the solver</span>}
    >
      <p className="text-[13px] leading-relaxed text-ink-2">
        {mustAllow
          ? "An authenticated request inside the frozen scope that this config does not definitely allow. A deny-all config cannot pass as a repair."
          : shadowing
            ? "A request the higher-ranked route serves and lets through, although the route written to handle it would have stopped it."
            : "A concrete request the config lets through that the property forbids."}
      </p>
      <RequestLine request={ce} showSource={sourceMatters} />
      <Trace steps={steps} />
      {shadowing && (
        <div className="flex gap-3 rounded-lg border border-line bg-surface-2 px-3.5 py-3 text-[13px] leading-relaxed">
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-vacuous" />
          <p className="text-ink-2">
            Route <code className="font-mono text-ink">{ce.route}</code> outranks{" "}
            <code className="font-mono text-ink">{ce.shadowed_route}</code>
            {ce.shadowed_service && (
              <>
                {" "}
                (service <code className="font-mono text-ink">{ce.shadowed_service}</code>)
              </>
            )}{" "}
            for this request, so the stricter guard on the shadowed route never applies.
          </p>
        </div>
      )}
    </Section>
  );
}

export function AssuranceView({ assurance }: { assurance: Assurance }) {
  const info = ASSURANCE[assurance.status];
  return (
    <Section title="Assurance" aside={<span className="font-mono text-2xs text-ink-3">{assurance.profile}</span>}>
      <div className="rounded-lg border border-line">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3.5 py-2.5">
          <ToneBadge tone={info.tone}>{info.label}</ToneBadge>
          <p className="text-[13px] text-ink-2">{info.meaning}</p>
        </div>
        {assurance.findings.length > 0 && (
          <ul className="divide-y divide-line border-t border-line">
            {assurance.findings.map((finding, index) => (
              <li key={index} className="space-y-1 px-3.5 py-2.5">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Chip>{finding.code}</Chip>
                  {finding.service && <span className="text-2xs text-ink-3">service <span className="font-mono text-ink-2">{finding.service}</span></span>}
                  {finding.route && <span className="text-2xs text-ink-3">route <span className="font-mono text-ink-2">{finding.route}</span></span>}
                </div>
                <p className="text-[13px] leading-relaxed text-ink-2">{finding.detail}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}

export function FrozenSpecView({ spec }: { spec: FrozenSpec }) {
  let pretty = spec.canonical;
  try {
    pretty = JSON.stringify(JSON.parse(spec.canonical), null, 2);
  } catch {}
  return (
    <Section title="Frozen specification" aside={<CopyButton text={spec.canonical} label="Copy identity" />}>
      <div className="flex gap-3 rounded-lg border border-line px-3.5 py-3">
        <FileLock2 className="mt-0.5 size-4 shrink-0 text-ink-2" />
        <div className="min-w-0 flex-1 space-y-2">
          <p className="text-[13px] leading-relaxed text-ink-2">
            This verdict is bound to a human-confirmed <code className="font-mono text-ink">{spec.kind}</code> contract
            (schema v{spec.schema_version}). Repairs may change the config, never this specification.
          </p>
          <CodeBlock>{pretty}</CodeBlock>
        </div>
      </div>
    </Section>
  );
}

function ReasonView({ reason, inconsistent }: { reason: string; inconsistent: boolean }) {
  const Icon = inconsistent ? CircleSlash : AlertTriangle;
  return (
    <Section title={inconsistent ? "Why the contract is inconsistent" : "Why no verdict was given"}>
      <div className="flex gap-3 rounded-lg border border-line bg-surface-2 px-3.5 py-3">
        <Icon className={`mt-0.5 size-4 shrink-0 ${inconsistent ? "text-inconsistent" : "text-unknown"}`} />
        <p className="text-[13px] leading-relaxed text-ink-2">{reason}</p>
      </div>
    </Section>
  );
}

export function VerifyReportView({ report }: { report: VerifyReport }) {
  return (
    <div className="space-y-6">
      {report.result === "violated" && report.counterexample && (
        <CounterexampleView report={report} ce={report.counterexample} />
      )}
      {report.reason && <ReasonView reason={report.reason} inconsistent={report.result === "inconsistent"} />}
      {report.result === "vacuous" && (
        <ReasonView
          inconsistent={false}
          reason="The property's forbidden request class is empty for these parameters, e.g. a scope no request can fall into. This exits nonzero because it is not a proof about the config; adjust the property scope."
        />
      )}
      {report.assurance && <AssuranceView assurance={report.assurance} />}
      {report.frozen_spec && <FrozenSpecView spec={report.frozen_spec} />}
    </div>
  );
}

export function verifyTitle(report: VerifyReport) {
  const info = propertyInfo(report.property);
  const name = info?.title ?? humanize(report.property);
  if (report.clause) return `${name}: ${report.clause.name} clause failed`;
  return name;
}

export function VerifyOutcome({
  report,
  exitCode,
  durationMs,
  command,
  source,
}: {
  report: VerifyReport;
  exitCode?: number;
  durationMs?: number;
  command?: string;
  source?: string;
}) {
  const [tab, setTab] = useState<"verdict" | "json" | "command">("verdict");
  const json = JSON.stringify(report, null, 2);
  const outcome = VERDICTS[report.result];
  const subtitle = report.clause ? `${sentence(report.clause.description)}.` : undefined;

  return (
    <div className="animate-reveal space-y-4">
      <Readout
        outcome={outcome}
        title={verifyTitle(report)}
        subtitle={subtitle}
        exitCode={exitCode}
        durationMs={durationMs}
        source={source}
      />
      <div className="border-b border-line">
        <Tabs
          label="Result views"
          value={tab}
          onChange={setTab}
          tabs={[
            { value: "verdict", label: "Details" },
            { value: "json", label: "JSON" },
            ...(command ? [{ value: "command" as const, label: "CLI" }] : []),
          ]}
        />
      </div>
      {tab === "verdict" && <VerifyReportView report={report} />}
      {tab === "json" && (
        <div className="space-y-2">
          <div className="flex items-center">
            <p className="text-2xs text-ink-3">Stable contract, schema v{report.schema_version}. Every key is always present.</p>
            <div className="ml-auto"><CopyButton text={json} /></div>
          </div>
          <CodeBlock className="max-h-[460px]">{json}</CodeBlock>
        </div>
      )}
      {tab === "command" && command && (
        <div className="space-y-2">
          <div className="flex items-center">
            <p className="text-2xs text-ink-3">Reproduce this run locally or gate a pipeline on its exit code.</p>
            <div className="ml-auto"><CopyButton text={command} /></div>
          </div>
          <CodeBlock>{`$ ${command}`}</CodeBlock>
        </div>
      )}
    </div>
  );
}
