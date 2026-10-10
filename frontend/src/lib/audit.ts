import type { PropertySpec, VerifyResponse } from "./api";
import type { Verdict } from "./contract";
import { formalStatement, humanize, propertyInfo } from "./domain";
import type { GatewayId } from "./gateways";

export interface AuditOptions {
  pathPrefix: string;
  trustedCidr: string;
}

export const DEFAULT_AUDIT_OPTIONS: AuditOptions = {
  pathPrefix: "/admin",
  trustedCidr: "127.0.0.1/32",
};

export interface AuditCheck {
  id: string;
  label: string;
  description: string;
  parameters: string | null;
  statement: string[];
  /** Property spec, or null for the uploaded frozen contract. */
  spec: PropertySpec | null;
}

/**
 * Checks that need no human intent run on every config. The paired properties
 * (authenticated-access, network-restricted-access) encode *intended*
 * functionality, which Soundcheck never infers from the config, so they only run
 * when the user supplies a frozen contract.
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
      parameters: contractKind,
      statement: [],
      spec: null,
    });
  }
  return checks;
}

export type SkipReason = "coming-soon" | "not-a-config" | "unsupported-type" | "too-large" | "unreadable";

export interface AuditFile {
  index: number;
  path: string;
  bytes: number;
  status: "audit" | "skipped";
  gateway: GatewayId | null;
  skip?: { reason: SkipReason; detail: string };
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
    }
  | { type: "result"; file: number; check: string; response: VerifyResponse }
  | { type: "done"; durationMs: number }
  | { type: "error"; message: string };

export type CellOutcome = Verdict | "error" | "pending";

export function cellOutcome(response: VerifyResponse | undefined): CellOutcome {
  if (!response) return "pending";
  return response.ok ? response.report.result : "error";
}

export type AuditStatus = "pass" | "review" | "fail";

export interface AuditTotals {
  files: number;
  audited: number;
  skipped: number;
  checks: number;
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
}

export const resultKey = (file: number, check: string) => `${file}:${check}`;

export function totals(run: AuditRun): AuditTotals {
  const outcomes = { proved: 0, violated: 0, vacuous: 0, inconsistent: 0, unknown: 0, error: 0 };
  const audited = run.files.filter((file) => file.status === "audit");
  for (const file of audited) {
    for (const check of run.checks) {
      const outcome = cellOutcome(run.results[resultKey(file.index, check.id)]);
      if (outcome !== "pending") outcomes[outcome]++;
    }
  }
  const status: AuditStatus =
    outcomes.violated + outcomes.inconsistent > 0
      ? "fail"
      : outcomes.unknown + outcomes.vacuous + outcomes.error > 0 || audited.length === 0
        ? "review"
        : "pass";
  return {
    files: run.files.length,
    audited: audited.length,
    skipped: run.files.length - audited.length,
    checks: audited.length * run.checks.length,
    outcomes,
    status,
  };
}

export const STATUS_COPY: Record<AuditStatus, { label: string; summary: string }> = {
  pass: { label: "Pass", summary: "Every check was proved for every audited config." },
  review: {
    label: "Needs review",
    summary: "No violations, but some checks returned no proof (unknown, vacuous or a tool error).",
  },
  fail: { label: "Fail", summary: "At least one check found a concrete violating request." },
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
      const request = `${ce.principal} ${ce.action || "ANY"} ${ce.path}`;
      const where = [ce.route && `route "${ce.route}"`, ce.service && `service "${ce.service}"`].filter(Boolean).join(", ");
      if (ce.shadowed_route) {
        return `${request} is served by ${where}, which shadows guarded route "${ce.shadowed_route}".`;
      }
      if (report.clause?.kind === "must_allow") {
        return `${request} is not definitely allowed (${report.clause.name}).`;
      }
      return `${request} is allowed${where ? ` via ${where}` : ""}${report.clause ? ` (${report.clause.name})` : ""}.`;
    }
  }
}

export function reproduceCommand(file: AuditFile, check: AuditCheck): string {
  const quoted = /^[\w./-]+$/.test(file.path) ? file.path : `'${file.path.replace(/'/g, `'\\''`)}'`;
  if (!check.spec) return `soundcheck verify ${quoted} --contract contract.yaml`;
  const args = ["--property", check.spec.property];
  if (check.spec.pathPrefix) args.push("--path-prefix", check.spec.pathPrefix);
  if (check.spec.trustedCidr) args.push("--trusted-cidr", check.spec.trustedCidr);
  return `soundcheck verify ${quoted} ${args.join(" ")}`;
}
