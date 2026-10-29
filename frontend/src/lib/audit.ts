import type { PropertySpec, VerifyResponse } from "./api";
import type { Verdict } from "./contract";
import { formalStatement, humanize, propertyInfo } from "./domain";
import type { GatewayId } from "./gateways";
import { shellCommand } from "./shell";

export interface AuditOptions {
  pathPrefix: string;
  trustedCidr: string;
}

export const DEFAULT_AUDIT_OPTIONS: AuditOptions = {
  pathPrefix: "/admin",
  trustedCidr: "127.0.0.1/32",
};

/**
 * Where a check's specification comes from.
 *
 * - `exploratory`: a built-in preset. Its parameters (which prefix is protected,
 *   which network is trusted, that public routes should be rate limited) are
 *   policy assumptions picked by whoever ran the audit, not reviewed intent.
 * - `frozen-contract`: a human-confirmed, versioned contract artifact. Only these
 *   results can support a Pass.
 */
export type CheckBasis = "exploratory" | "frozen-contract";

export interface AuditCheck {
  id: string;
  label: string;
  description: string;
  basis: CheckBasis;
  /** The policy assumptions an exploratory preset bakes in. Empty for contracts. */
  assumptions: string[];
  parameters: string | null;
  statement: string[];
  /** Property spec, or null for the uploaded frozen contract. */
  spec: PropertySpec | null;
}

function presetAssumptions(spec: PropertySpec): string[] {
  switch (spec.property) {
    case "no-anonymous-access":
      return [`Everything under ${spec.pathPrefix} must require authentication.`];
    case "admin-api-not-reachable":
      // The property covers anonymous requests only; authenticated requests
      // from outside the block are out of its scope and stay unchecked.
      return [
        `Anonymous requests from outside ${spec.trustedCidr} must not reach the Kong Admin API (authenticated requests are not checked).`,
      ];
    case "rate-limit-on-public":
      return ["Every route reachable without authentication should be rate limited."];
    case "no-shadowed-routes":
      return ["No route should be fully hidden by another route."];
    default:
      return [];
  }
}

/**
 * Exploratory presets run on every config. They are useful for triage but are
 * not a substitute for a reviewed contract: each one assumes a policy. Paired
 * functionality properties encode intended behaviour, which Soundcheck never
 * infers from the config, so they only run from a frozen contract.
 */
export function auditChecks(options: AuditOptions, contractKind: string | null): AuditCheck[] {
  const specs: PropertySpec[] = [
    { mode: "property", property: "no-anonymous-access", pathPrefix: options.pathPrefix },
    { mode: "property", property: "rate-limit-on-public" },
    { mode: "property", property: "no-shadowed-routes" },
    { mode: "property", property: "admin-api-not-reachable", trustedCidr: options.trustedCidr },
  ];
  const checks: AuditCheck[] = specs.map((spec) => {
    const info = propertyInfo(spec.property)!;
    const parameters =
      spec.property === "no-anonymous-access"
        ? `path prefix ${spec.pathPrefix}`
        : spec.property === "admin-api-not-reachable"
          ? `trusted CIDR ${spec.trustedCidr}`
          : null;
    return {
      id: spec.property,
      label: info.title,
      description: info.question,
      basis: "exploratory",
      assumptions: presetAssumptions(spec),
      parameters,
      statement: formalStatement(spec).map((clause) => (clause.label ? `${clause.label}: ${clause.text}` : clause.text)),
      spec,
    };
  });
  if (contractKind) {
    checks.push({
      id: "contract",
      label: `Frozen contract (${humanize(contractKind)})`,
      description: "The uploaded human-confirmed contract, checked clause by clause.",
      basis: "frozen-contract",
      assumptions: [],
      parameters: contractKind,
      statement: [],
      spec: null,
    });
  }
  return checks;
}

export type SkipReason = "coming-soon" | "not-a-config" | "unsupported-type" | "too-large" | "unreadable";

/**
 * Skips that may hide a gateway config. They block a Pass: the audit cannot claim
 * coverage of files it could not read or classify. Only files of an unrelated
 * type (a README, an image) are excluded without affecting the outcome.
 */
export const COVERAGE_GAP_REASONS: readonly SkipReason[] = ["coming-soon", "not-a-config", "too-large", "unreadable"];

export interface AuditFile {
  index: number;
  path: string;
  bytes: number;
  /** SHA-256 of the file's exact bytes, or null when it was too large to read. */
  sha256: string | null;
  status: "audit" | "skipped";
  gateway: GatewayId | null;
  skip?: { reason: SkipReason; detail: string };
}

export interface AuditProvenance {
  /** SHA-256 of the uploaded file, or of the concatenated sample bundle. */
  sourceSha256: string;
  engine: { source: string; label: string; executableSha256: string | null; solverVersion: string | null };
  profile: string;
  /** SHA-256 of the contract text as uploaded, when one was supplied. */
  contractSha256: string | null;
}

export type AuditEvent =
  | {
      type: "plan";
      source: string;
      gateway: GatewayId;
      profile: string | null;
      options: AuditOptions;
      contract: string | null;
      checks: AuditCheck[];
      files: AuditFile[];
      provenance: AuditProvenance;
    }
  | { type: "result"; file: number; check: string; response: VerifyResponse }
  /** Sent only after every planned check has produced a result. */
  | { type: "done"; durationMs: number; completed: number; expected: number }
  | { type: "error"; message: string };

export type CellOutcome = Verdict | "error" | "pending";

export function cellOutcome(response: VerifyResponse | undefined): CellOutcome {
  if (!response) return "pending";
  return response.ok ? response.report.result : "error";
}

/** How the run ended. Anything but `complete` means some checks may never have run. */
export type AuditCompletion = "running" | "complete" | "cancelled" | "failed";

export type AuditStatus = "fail" | "incomplete" | "review" | "pass" | "no-findings";

export interface AuditTotals {
  files: number;
  audited: number;
  skipped: number;
  coverageGaps: number;
  /** Results whose config uses features outside the assurance profile. */
  unsupported: number;
  /** Checks planned: audited files times checks. */
  checks: number;
  pending: number;
  outcomes: Record<Exclude<CellOutcome, "pending">, number>;
  status: AuditStatus;
}

export interface AuditRun {
  source: string;
  gateway: GatewayId;
  profile: string | null;
  options: AuditOptions;
  contract: string | null;
  checks: AuditCheck[];
  files: AuditFile[];
  results: Record<string, VerifyResponse>;
  startedAt: string;
  durationMs: number | null;
  completion: AuditCompletion;
  /** Why the run did not complete, when it did not. */
  failure: string | null;
  provenance: AuditProvenance;
}

export const resultKey = (file: number, check: string) => `${file}:${check}`;

export function totals(run: AuditRun): AuditTotals {
  const outcomes = { proved: 0, violated: 0, vacuous: 0, inconsistent: 0, unknown: 0, error: 0 };
  let pending = 0;
  let unsupported = 0;
  const audited = run.files.filter((file) => file.status === "audit");
  for (const file of audited) {
    for (const check of run.checks) {
      const response = run.results[resultKey(file.index, check.id)];
      const outcome = cellOutcome(response);
      if (outcome === "pending") pending++;
      else outcomes[outcome]++;
      // A verdict on a config the profile does not cover is not a clean result,
      // whatever it says (the engine's compare treats Unsupported as fail-closed too).
      if (response?.ok && response.report.assurance?.status === "unsupported") unsupported++;
    }
  }
  const coverageGaps = run.files.filter(
    (file) => file.status === "skipped" && file.skip && COVERAGE_GAP_REASONS.includes(file.skip.reason),
  ).length;
  const planned = audited.length * run.checks.length;
  const contractBacked = run.checks.some((check) => check.basis === "frozen-contract");

  // A concrete violation stands even in an unfinished run; nothing else is
  // concluded until every planned check has a result.
  const status: AuditStatus =
    outcomes.violated + outcomes.inconsistent > 0
      ? "fail"
      : run.completion !== "complete" || pending > 0 || planned === 0
        ? "incomplete"
        : outcomes.unknown + outcomes.vacuous + outcomes.error > 0 || coverageGaps > 0 || unsupported > 0
          ? "review"
          : contractBacked
            ? "pass"
            : "no-findings";
  return {
    files: run.files.length,
    audited: audited.length,
    skipped: run.files.length - audited.length,
    coverageGaps,
    unsupported,
    checks: planned,
    pending,
    outcomes,
    status,
  };
}

export const STATUS_COPY: Record<AuditStatus, { label: string; summary: string }> = {
  pass: {
    label: "Pass",
    summary: "Every check, including the frozen contract, was proved for every audited config, and no file was left unread.",
  },
  "no-findings": {
    label: "No findings (exploratory)",
    summary:
      "Every exploratory preset was proved for every audited config. Presets encode assumed policy, not reviewed intent; add a frozen contract for a pass.",
  },
  review: {
    label: "Needs review",
    summary:
      "No violations, but some checks returned no proof (unknown, vacuous or a tool error), some configs use features outside the assurance profile, or some files that may be configs could not be audited.",
  },
  incomplete: {
    label: "Incomplete",
    summary: "The audit did not finish, so some checks never ran. This is not a pass.",
  },
  fail: { label: "Fail", summary: "At least one check found a concrete violating request." },
};

export const BASIS_COPY: Record<CheckBasis, { label: string; summary: string }> = {
  exploratory: {
    label: "Exploratory preset",
    summary: "Assumes a policy. Useful for triage, not a substitute for a reviewed contract.",
  },
  "frozen-contract": {
    label: "Frozen contract",
    summary: "Human-confirmed, versioned specification.",
  },
};

/** One line describing a result, in the config's own vocabulary. */
export function describeResult(response: VerifyResponse): string {
  if (!response.ok) return `${response.stage} error: ${response.message.split("\n")[0]}`;
  const report = response.report;
  const ce = report.counterexample;
  switch (report.result) {
    case "proved":
      return "Holds for every modeled request.";
    case "vacuous":
      return "Forbidden request class is empty; nothing was verified.";
    case "inconsistent":
    case "unknown":
      return report.reason || "No verdict.";
    case "violated": {
      if (!ce) return "Violated.";
      const request = `${ce.principal} ${ce.action || "<any-method>"} ${ce.path}`;
      const candidate = report.assurance?.status === "conservative" ? " (conservative model: a candidate to confirm against Kong)" : "";
      const where = [ce.route && `route "${ce.route}"`, ce.service && `service "${ce.service}"`].filter(Boolean).join(", ");
      if (ce.shadowed_route) {
        return `${request} can be served by ${where} in the modeled route selection instead of guarded route "${ce.shadowed_route}"${candidate}.`;
      }
      if (report.clause?.kind === "must_allow") {
        return `${request} is not definitely allowed (${report.clause.name}).`;
      }
      return `${request} is allowed in the model${where ? ` via ${where}` : ""}${report.clause ? ` (${report.clause.name})` : ""}${candidate}.`;
    }
  }
}

/** The command that reproduces one check; every argument is shell-quoted. */
export function reproduceCommand(file: AuditFile, check: AuditCheck): string {
  if (!check.spec) {
    return shellCommand(["soundcheck", "verify", file.path, "--contract", "contract.yaml", "--evidence-dir", "evidence"]);
  }
  const args = ["soundcheck", "verify", file.path, "--property", check.spec.property];
  if (check.spec.pathPrefix) args.push("--path-prefix", check.spec.pathPrefix);
  if (check.spec.trustedCidr) args.push("--trusted-cidr", check.spec.trustedCidr);
  return shellCommand(args);
}
