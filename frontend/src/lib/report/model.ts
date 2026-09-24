import {
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
    return {
      file,
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
  return {
    title: "Soundcheck audit report",
    generatedAt: new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC"),
    source: run.source,
    gateway: gateway(run.gateway)?.name ?? run.gateway,
    profile: run.profile ?? "unknown",
    status: sum.status,
    statusLabel: status.label,
    statusSummary: status.summary,
    stats: [
      ["Files scanned", String(sum.files)],
      ["Configs audited", String(sum.audited)],
      ["Files skipped", String(sum.skipped)],
      ["Checks run", String(sum.checks)],
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
      "Paired functionality contracts (authenticated-access, network-restricted-access) encode intent that Soundcheck does not infer from a config. They run only when a frozen contract is supplied.",
    ],
  };
}
