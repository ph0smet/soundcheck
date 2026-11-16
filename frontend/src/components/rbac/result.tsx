"use client";

import { ArrowDownToLine, ChevronRight, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState, type ReactNode } from "react";

import type { VerifyReport } from "@/lib/contract";
import type { RbacMode, RbacRunSuccess } from "@/lib/rbac/api";
import type { RbacAuthorization, RbacProfile, RbacReport, RbacSequenceReport } from "@/lib/rbac/contract";
import { failureLocation, isSequenceReport, outcome, sequenceRows, STATUS_LABELS, statusTone, witnessDecision, type CheckStatus } from "@/lib/rbac/presentation";

import { Button, Chip, CodeBlock, CopyButton, Eyebrow, TONE_TEXT, ToneBadge } from "../ui";

function json(value: unknown) { return JSON.stringify(value, null, 2); }
function download(content: BlobPart, filename: string, mediaType: string) {
  const href = URL.createObjectURL(new Blob([content], { type: mediaType }));
  const link = document.createElement("a");
  link.href = href; link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}

function CheckBadge({ status }: { status: CheckStatus }) {
  const tone = statusTone(status);
  return tone ? <ToneBadge tone={tone}>{STATUS_LABELS[status]}</ToneBadge> : <span className="text-2xs text-ink-3">{STATUS_LABELS[status]}</span>;
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return <div className="min-w-0"><dt className="text-2xs text-ink-3">{label}</dt><dd className="mt-1 break-words font-mono text-xs text-ink">{children}</dd></div>;
}

export function RbacWitness({ report }: { report: VerifyReport }) {
  const witness = report.counterexample;
  if (!witness) return null;
  const compound = ["apply-existing", "apply-missing", "update-existing", "update-missing"].includes(witness.action);
  return (
    <section className="space-y-3 rounded-lg border border-line bg-surface-2 p-3 sm:p-4" aria-label="RBAC counterexample">
      <div className="flex flex-wrap items-center gap-2"><Eyebrow>Validated modeled witness</Eyebrow><Chip>{witness.action || "(empty action)"}</Chip></div>
      <p className="text-[13px] font-medium">{witnessDecision(report)}</p>
      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Detail label="Identity">{witness.principal}</Detail>
        <Detail label="Trusted groups">{witness.identity_groups?.length ? witness.identity_groups.join(", ") : "(none)"}</Detail>
        {witness.object_request ? <>
          <Detail label="Resource coordinate">{witness.object_request.resource_kind}</Detail>
          <Detail label="Authorization namespace">{witness.object_request.namespace || "(empty authorization namespace)"}</Detail>
          <Detail label="Effective authorization name">{witness.object_request.name || "(empty authorization name)"}</Detail>
        </> : <Detail label="Non-resource URL">{witness.path}</Detail>}
      </dl>
      {report.clause && <p className="break-words text-xs leading-relaxed text-ink-2">{report.clause.description}</p>}
      {compound && <p className="text-xs leading-relaxed text-ink-2">This is a conditional operation. Allow requires every modeled prerequisite; NoOpinion means at least one lacks a grant. It does not observe an actual storage branch or successful execution.</p>}
      <details><summary className="cursor-pointer text-xs font-medium text-ink-2">Reported granting rules ({witness.granting_rules.length})</summary>
        {witness.granting_rules.length ? <ul className="mt-2 space-y-1.5">{witness.granting_rules.map((rule, i) => <li key={i} className="break-words font-mono text-2xs text-ink-2">{rule}</li>)}</ul> : <p className="mt-2 text-xs text-ink-3">The engine reported no granting rules for this witness.</p>}
      </details>
      <p className="border-t border-line pt-2 text-2xs leading-relaxed text-ink-3">NoOpinion is the absence of an RBAC grant, not a final API-server denial. A modeled Allow does not establish API success.</p>
    </section>
  );
}

export function RbacCoreReport({ title, report }: { title: string; report: VerifyReport | null }) {
  if (!report) return <div className="flex items-center justify-between gap-3 rounded-lg border border-dashed border-line px-3 py-2.5"><span className="text-xs text-ink-2">{title}</span><CheckBadge status="not_executed" /></div>;
  return (
    <section className="space-y-3 rounded-lg border border-line p-3">
      <div className="flex flex-wrap items-center gap-2"><h3 className="mr-auto text-xs font-semibold">{title}</h3><CheckBadge status={report.result} /></div>
      {report.clause && <p className="break-words text-xs text-ink-2"><span className="font-medium text-ink">{report.clause.name}</span> · {report.clause.kind.replaceAll("_", " ")}</p>}
      {report.reason && <p className="whitespace-pre-wrap break-words text-xs leading-relaxed text-ink-2">{report.reason}</p>}
      {report.result === "vacuous" && <p className="text-xs leading-relaxed text-ink-2">The required request class is empty. No proof is claimed for this obligation.</p>}
      <RbacWitness report={report} />
    </section>
  );
}

function Authorization({ authorization }: { authorization: RbacAuthorization | null }) {
  if (!authorization) return <div className="flex items-center gap-3 text-xs"><span className="text-ink-2">Operation authorization</span><CheckBadge status="not_executed" /></div>;
  const checks = [{ label: "Initial operation", value: authorization.initial }, ...(authorization.special ? [{ label: "Bind / escalate", value: authorization.special }] : [])];
  return <div className="space-y-3">
    <div className="flex flex-wrap items-center gap-2"><span className="mr-auto text-xs font-semibold">Operation authorization</span><CheckBadge status={authorization.allowed ? "authorized" : "not_authorized"} /></div>
    <p className="text-xs leading-relaxed text-ink-2">{authorization.reason}</p>
    <details><summary className="cursor-pointer text-xs text-ink-2">Modeled prerequisite checks</summary><div className="mt-2 space-y-2">
      {checks.map(({ label, value }) => <div key={label} className="rounded-lg border border-line bg-surface-2 p-3"><div className="flex flex-wrap items-center gap-2"><span className="text-2xs text-ink-2">{label}</span><Chip>{value.attributes.verb}</Chip><span className="ml-auto text-2xs text-ink-3">{value.granting_rule_indices.length ? "RBAC grant present" : "NoOpinion"}</span></div><p className="mt-1.5 break-words font-mono text-2xs text-ink-2">{value.attributes.resource}.{value.attributes.api_group} · namespace {JSON.stringify(value.attributes.namespace)} · name {JSON.stringify(value.attributes.name)}</p><p className="mt-1.5 text-2xs text-ink-3">Granting rule indices: {value.granting_rule_indices.length ? value.granting_rule_indices.join(", ") : "none"}</p></div>)}
      {authorization.coverage && <div className="rounded-lg border border-line p-3"><p className="text-xs text-ink-2">Full-policy coverage: {authorization.coverage.covered ? "covered" : "missing permissions"} · {authorization.coverage.atom_count} atoms</p>{authorization.coverage.missing.length > 0 && <CodeBlock className="mt-2 max-h-64">{json(authorization.coverage.missing)}</CodeBlock>}</div>}
    </div></details>
  </div>;
}

export function RbacSequenceTimeline({ report }: { report: RbacSequenceReport }) {
  const rows = sequenceRows(report);
  if (!rows.length) return <p className="rounded-lg border border-dashed border-line p-3 text-xs leading-relaxed text-ink-3">State construction did not complete. No operation authorization or state verification is shown as passed.</p>;
  return <section className="space-y-3" aria-label="Migration state timeline">
    <div><Eyebrow>Migration states</Eyebrow><p className="mt-1 text-xs leading-relaxed text-ink-3">Authorization uses the immediately preceding state. Invariants and preservation below describe the resulting state.</p></div>
    <ol className="space-y-2">
      {rows.map((row) => {
        const step = report.steps.find((item) => item.index === row.state);
        const invariant = "state_invariants" in report ? report.state_invariants.find((item) => item.state === row.state) : undefined;
        const preserved = report.intermediate_preservation.find((item) => item.step === row.state);
        return <li key={row.state} className={`rounded-lg border ${row.failed ? (report.result === "unknown" ? "border-unknown/40 bg-unknown/5" : "border-violated/40 bg-violated/5") : "border-line bg-surface"}`}>
          <details open={row.failed}>
            <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 px-3 py-3 [&::-webkit-details-marker]:hidden">
              <span className="flex h-7 min-w-8 items-center justify-center rounded-md border border-line bg-surface-2 px-1.5 font-mono text-xs font-medium">S{row.state}</span>
              <span className="min-w-0 flex-1"><span className="block text-xs font-medium">{row.operation}</span>{row.target && <span className="mt-0.5 block break-words font-mono text-2xs text-ink-3">{row.target}</span>}</span>
              {row.failed && <span className={`text-2xs font-medium ${report.result === "unknown" ? "text-unknown" : "text-violated"}`}>{report.result === "unknown" ? "Stopped here" : "Reported failure"}</span>}<ChevronRight className="size-3.5 text-ink-3" />
            </summary>
            <div className="space-y-3 border-t border-line px-3 py-3">
              {step && <Authorization authorization={step.authorization} />}
              {invariant && <RbacCoreReport title={`Selected invariants at S${row.state}`} report={invariant.report} />}
              {preserved && <RbacCoreReport title={`Preservation at S${row.state}, compared with S0`} report={preserved.report} />}
              {row.state === report.steps.length && <p className="text-2xs text-ink-3">Final requirements and final preservation are shown separately below.</p>}
              {row.state === 0 && !invariant && <p className="text-xs text-ink-3">No baseline invariants were selected. Final-only requirements are not asserted at this state.</p>}
            </div>
          </details>
          <dl className="grid grid-cols-1 gap-x-3 gap-y-2 border-t border-line px-3 py-2.5 sm:grid-cols-3">
            <div><dt className="mb-1 text-2xs text-ink-3">Incoming operation</dt><dd><CheckBadge status={row.authorization} /></dd></div>
            <div><dt className="mb-1 text-2xs text-ink-3">Selected invariants</dt><dd><CheckBadge status={row.invariant} /></dd></div>
            <div><dt className="mb-1 text-2xs text-ink-3">Preservation vs S0</dt><dd><CheckBadge status={row.preservation} /></dd></div>
          </dl>
        </li>;
      })}
    </ol>
    <p className="text-2xs leading-relaxed text-ink-3">The engine checks authorization, final requirements, selected invariants, then intermediate preservation. The reported failure is in this execution order; it need not be the earliest chronological defect. “Not selected” and “Not executed” are not proofs.</p>
  </section>;
}

export function RbacProfileView({ profile, accessProfile }: { profile: RbacProfile; accessProfile: RbacProfile }) {
  const profiles = profile.id === accessProfile.id ? [profile] : [profile, accessProfile];
  return <details className="rounded-lg border border-line px-3 py-2.5"><summary className="cursor-pointer text-xs font-medium text-ink-2">Assurance boundary{profiles.length > 1 ? " and nested access profile" : ""}</summary>
    <div className="mt-3 space-y-4">{profiles.map((item) => <section key={item.id} className="space-y-2">
      <p className="break-words font-mono text-2xs font-medium">{item.id}</p>
      {typeof item.scope === "string" && <p className="text-xs leading-relaxed text-ink-2">{item.scope}</p>}
      <ul className="list-disc space-y-2 pl-4 text-xs leading-relaxed text-ink-2">{item.assumptions.map((assumption, i) => <li key={i}>{assumption}</li>)}</ul>
      <details><summary className="cursor-pointer text-2xs text-ink-3">Complete profile JSON</summary><CodeBlock className="mt-2 max-h-64">{json(item)}</CodeBlock></details>
    </section>)}</div>
  </details>;
}

function ReportChecks({ report, mode }: { report: RbacReport; mode: RbacMode }) {
  if (!("kind" in report)) return <div className="space-y-3"><RbacCoreReport title={report.property === "rbac-repair-preservation" ? "Access and out-of-scope preservation" : "Frozen access requirements"} report={report} />{mode === "repair" && report.property !== "rbac-repair-preservation" && <RbacCoreReport title="Preservation outside the approved scope" report={null} />}</div>;
  const comparison = report.verification?.comparison_report;
  return <div className="space-y-4">
    {isSequenceReport(report) ? <RbacSequenceTimeline report={report} /> : <div className="rounded-lg border border-line p-3"><Authorization authorization={report.authorization} /></div>}
    <RbacCoreReport title="Final access requirements" report={report.verification?.candidate_report ?? null} />
    <RbacCoreReport title="Final preservation outside the approved scope" report={comparison?.property === "rbac-repair-preservation" ? comparison : null} />
  </div>;
}

export function RbacResult({ response }: { response: RbacRunSuccess }) {
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const summary = outcome(response.report.result, response.mode);
  const report = response.report;
  const OutcomeIcon = summary.tone === "proved" ? ShieldCheck : ShieldAlert;
  const reason = "reason" in report ? report.reason : undefined;
  const receipt = { ...response, evidenceArchive: { ...response.evidenceArchive, base64: undefined } };
  const downloadEvidence = () => {
    try {
      const binary = atob(response.evidenceArchive.base64);
      const bytes = Uint8Array.from(binary, (value) => value.charCodeAt(0));
      download(bytes, response.evidenceArchive.filename, response.evidenceArchive.mediaType);
      setDownloadError(null);
    } catch { setDownloadError("The evidence download could not be created. The original report remains available below."); }
  };
  return <div className="space-y-4">
    <section className="rounded-lg border border-line bg-surface-2 p-4" aria-label="RBAC verification outcome">
      <div className="flex flex-wrap items-center gap-2"><OutcomeIcon className={`size-4 ${TONE_TEXT[summary.tone]}`} /><h2 className={`text-lg font-semibold ${TONE_TEXT[summary.tone]}`}>{summary.title}</h2><Chip>exit {response.exitCode}</Chip><Chip>{(response.durationMs / 1000).toFixed(2)} s</Chip></div>
      <p className="mt-2 text-[13px] leading-relaxed text-ink-2">{summary.explanation}</p>
      {reason && <p className="mt-2 whitespace-pre-wrap break-words text-xs leading-relaxed text-ink-2">{reason}</p>}
      {isSequenceReport(report) && <p className="mt-2 text-2xs text-ink-3">Phase: {report.phase.replaceAll("_", " ")}{failureLocation(report) ? ` · ${failureLocation(report)}` : ""}</p>}
    </section>

    <ReportChecks report={report} mode={response.mode} />
    <RbacProfileView profile={response.profile} accessProfile={response.accessProfile} />

    <section className="space-y-3 rounded-lg border border-line p-3">
      <div className="flex flex-wrap items-center gap-2"><Eyebrow>Report and evidence</Eyebrow><span className="ml-auto text-2xs text-ink-3">{response.evidenceArchive.fileCount} evidence files</span></div>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => download(`${json(report)}\n`, "soundcheck-rbac-report-view.json", "application/json")}><ArrowDownToLine className="size-3.5" /> Report view JSON</Button>
        <Button size="sm" onClick={downloadEvidence} title="Includes full private policy snapshots"><ArrowDownToLine className="size-3.5" /> Evidence ZIP</Button>
        <Button size="sm" onClick={() => download(`${json(receipt)}\n`, "soundcheck-rbac-run.json", "application/json")}><ArrowDownToLine className="size-3.5" /> Run receipt</Button>
      </div>
      {downloadError && <p role="alert" className="text-xs text-violated">{downloadError}</p>}
      <p className="text-2xs leading-relaxed text-ink-3">Evidence includes private policy snapshots and solver replay material. It is not an independently checked UNSAT certificate or a guarantee of live deployment behavior.</p>
      <details><summary className="cursor-pointer text-xs font-medium text-ink-2">Inspect accepted report</summary><div className="mt-2 flex justify-end"><CopyButton text={json(report)} label="Copy report" /></div><CodeBlock className="mt-2 max-h-96">{json(report)}</CodeBlock></details>
      <details><summary className="cursor-pointer text-xs font-medium text-ink-2">Input and engine provenance</summary><CodeBlock className="mt-2 max-h-72">{json({ inputs: response.provenance.inputs, engine: response.provenance.engine, evidence_archive: { sha256: response.evidenceArchive.sha256, bytes: response.evidenceArchive.bytes, files: response.evidenceArchive.fileCount }, command: response.command })}</CodeBlock></details>
      <details><summary className="cursor-pointer text-xs font-medium text-ink-2">Evidence manifest</summary><CodeBlock className="mt-2 max-h-96">{json(response.provenance.evidence)}</CodeBlock></details>
    </section>
  </div>;
}
