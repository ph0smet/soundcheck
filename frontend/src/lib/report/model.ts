import {
  BASIS_COPY,
  cellOutcome,
  describeResult,
  reproduceCommand,
  resultKey,
  STATUS_COPY,
  totals,
  type AuditCheck,
  type AuditFile,
  type AuditRun,
  type CellOutcome,
} from "../audit";
import { ASSURANCE } from "../domain";
import { gateway } from "../gateways";

// Format-neutral report content, rendered by both the Markdown and PDF writers
// so the two downloads can never disagree.

export const OUTCOME_LABEL: Record<CellOutcome, string> = {
  proved: "PROVED",
  violated: "VIOLATED",
  vacuous: "VACUOUS",
  inconsistent: "INCONSISTENT",
  unknown: "UNKNOWN",
  error: "ERROR",
  pending: "NOT RUN",
};

export interface ReportFinding {
  check: AuditCheck;
  outcome: CellOutcome;
  exitCode: number | null;
  summary: string;
  command: string;
}

export interface ReportFileSection {
  file: AuditFile;
  /** Provenance lines: the file digest and, for frozen-contract runs, the engine's evidence. */
  evidence: string[];
  worst: CellOutcome;
  /** Set when every check failed identically (a parse error, an unsupported construct), so it is reported once. */
  shared: { outcome: CellOutcome; exitCode: number | null; summary: string } | null;
  assurance: string | null;
  assuranceFindings: string[];
  findings: ReportFinding[];
}

export interface ReportModel {
  title: string;
  generatedAt: string;
  source: string;
  gateway: string;
  profile: string;
  statusLabel: string;
  statusSummary: string;
  status: ReturnType<typeof totals>["status"];
  /** Whether every planned check ran, stated in one line. */
  completion: string;
  provenance: [string, string][];
  stats: [string, string][];
  checks: AuditCheck[];
  matrix: { path: string; outcomes: CellOutcome[] }[];
  sections: ReportFileSection[];
  skipped: { path: string; detail: string }[];
  contract: string | null;
  scope: string[];
}

const SEVERITY: CellOutcome[] = ["pending", "proved", "vacuous", "unknown", "error", "inconsistent", "violated"];

function worst(outcomes: CellOutcome[]): CellOutcome {
  return outcomes.reduce((a, b) => (SEVERITY.indexOf(b) > SEVERITY.indexOf(a) ? b : a), "pending");
}

export function buildReport(run: AuditRun): ReportModel {
  const sum = totals(run);
  const status = STATUS_COPY[sum.status];
  const audited = run.files.filter((file) => file.status === "audit");

  const sections = audited.map((file): ReportFileSection => {
    const findings = run.checks.map((check): ReportFinding => {
      const response = run.results[resultKey(file.index, check.id)];
      return {
        check,
        outcome: cellOutcome(response),
        exitCode: response?.ok ? response.exitCode : (response?.exitCode ?? null),
        summary: response ? describeResult(response) : "Not run.",
        command: reproduceCommand(file, check),
      };
    });
    const assured = run.checks
      .map((check) => run.results[resultKey(file.index, check.id)])
      .find((response) => response?.ok && response.report.assurance);
    const assurance = assured?.ok ? assured.report.assurance : null;
    const [first] = findings;
    const identical =
      findings.length > 1 &&
      first.outcome !== "proved" &&
      first.outcome !== "pending" &&
      findings.every((finding) => finding.outcome === first.outcome && finding.summary === first.summary);
    const evidence = [`Config SHA-256: ${file.sha256 ?? "not read"}`];
    for (const finding of findings) {
      const response = run.results[resultKey(file.index, finding.check.id)];
      const manifest = response?.ok ? response.provenance.evidence : null;
      if (manifest) {
        const solver = manifest.solver.version ?? `solver version unavailable (${manifest.solver.version_error ?? "no reason"})`;
        evidence.push(
          `${finding.check.label}: engine evidence bundle schema ${manifest.schema_version}, ` +
            `verifier SHA-256 ${manifest.soundcheck.executable_sha256}, ${solver}, ` +
            `canonical contract SHA-256 ${manifest.contract.sha256}, report SHA-256 ${manifest.report.sha256}`,
        );
      }
    }
    return {
      file,
      evidence,
      worst: worst(findings.map((finding) => finding.outcome)),
      shared: identical ? { outcome: first.outcome, exitCode: first.exitCode, summary: first.summary } : null,
      assurance: assurance ? `${ASSURANCE[assurance.status].label} (${assurance.profile})` : null,
      assuranceFindings:
        assurance?.findings.map((item) =>
          [item.code, item.route && `route ${item.route}`, item.service && `service ${item.service}`, item.detail]
            .filter(Boolean)
            .join(" · "),
        ) ?? [],
      findings,
    };
  });

  const o = sum.outcomes;
  const ran = sum.checks - sum.pending;
  const completion =
    run.completion === "complete" && sum.pending === 0
      ? `Complete: all ${sum.checks} planned checks ran.`
      : `INCOMPLETE (${run.completion}): ${ran} of ${sum.checks} planned checks ran.${run.failure ? ` ${run.failure}` : ""}`;
  const frozen = Object.values(run.results).find((response) => response.ok && response.report.frozen_spec);
  const frozenSpec = frozen?.ok ? frozen.report.frozen_spec : null;
  const engine = run.provenance.engine;
  const provenance: [string, string][] = [
    ["Source SHA-256", run.provenance.sourceSha256],
    ["Engine", `${engine.label} (${engine.source})`],
    ["Engine executable SHA-256", engine.executableSha256 ?? "not identified (the engine runs behind a wrapper)"],
    ["Solver", engine.solverVersion ?? "not identified by the web server"],
    ["Assurance profile", run.provenance.profile],
    ["Uploaded contract text SHA-256", run.provenance.contractSha256 ?? "no frozen contract supplied"],
  ];
  if (frozenSpec) provenance.push(["Frozen contract identity", frozenSpec.canonical]);
  provenance.push(["Report", "Generated by the Soundcheck web UI. A summary, not a signed evidence bundle."]);
  return {
    title: "Soundcheck audit report",
    generatedAt: new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC"),
    source: run.source,
    gateway: gateway(run.gateway)?.name ?? run.gateway,
    profile: run.profile ?? "unknown",
    status: sum.status,
    statusLabel: status.label,
    statusSummary: status.summary,
    completion,
    provenance,
    stats: [
      ["Files scanned", String(sum.files)],
      ["Configs audited", String(sum.audited)],
      ["Files skipped", String(sum.skipped)],
      ["Checks planned", String(sum.checks)],
      ["Checks not run", String(sum.pending)],
      ["Coverage gaps", String(sum.coverageGaps)],
      ["Outside profile", String(sum.unsupported)],
      ["Proved", String(o.proved)],
      ["Violated", String(o.violated)],
      ["Unknown", String(o.unknown)],
      ["Vacuous", String(o.vacuous)],
      ["Inconsistent", String(o.inconsistent)],
      ["Errors", String(o.error)],
    ],
    checks: run.checks,
    matrix: sections.map((section) => ({
      path: section.file.path,
      outcomes: section.findings.map((finding) => finding.outcome),
    })),
    sections,
    skipped: run.files
      .filter((file) => file.status === "skipped")
      .map((file) => ({ path: file.path, detail: file.skip?.detail ?? "Skipped." })),
    contract: run.contract,
    scope: [
      `Every verdict holds within the modeled semantics of assurance profile ${run.profile ?? "unknown"}. The profile's modeled, conservative and unsupported features are listed by \`soundcheck profile kong\`.`,
      "PROVED means the SMT solver established that no violating request exists in that model, not that none was found by sampling.",
      "UNKNOWN means the config left the supported fragment. It is never a pass.",
      "Counterexamples are concrete requests chosen by the solver. Paths such as /v1E are arbitrary members of the violating class: any request with the same shape is affected.",
      `${BASIS_COPY.exploratory.label}s encode policy assumptions chosen when the audit was run (the protected prefix, the trusted network, which routes should be rate limited). They are not reviewed intent and cannot produce a Pass on their own.`,
      "Only a human-reviewed frozen contract is a specification. Paired functionality contracts (authenticated-access, network-restricted-access) run only from one.",
      "An INCOMPLETE report is never a pass: checks marked NOT RUN produced no result. Skipped files that may be configs are listed as coverage gaps and prevent a Pass.",
      "For audit-grade evidence of a frozen contract, run `soundcheck verify <config> --contract <contract> --evidence-dir <dir>`. The bundle binds the exact input bytes, verifier and solver with SHA-256.",
    ],
  };
}
