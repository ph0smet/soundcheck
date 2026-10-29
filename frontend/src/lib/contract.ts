// The engine's stable JSON contracts, as strict validators. Every TypeScript type
// below is inferred from its validator, so the shape is declared once and the
// web adapter rejects anything that does not match it exactly.
//
// Source of truth: core/report.ml (verify, schema 9), core/evidence.ml (bundle
// manifest, schema 1), connectors/kong/compare.ml (compare and repair, schema 1)
// and connectors/kong/assurance.ml (profile, schema 1). The conformance test in
// src/lib/server/__tests__/conformance.test.ts runs the real CLI against these.

import {
  array,
  integer,
  literal,
  nullable,
  object,
  oneOf,
  refine,
  string,
  type Infer,
  type Validator,
} from "./schema";

export const VERIFY_SCHEMA_VERSION = 9;
export const COMPARE_SCHEMA_VERSION = 1;
export const PROFILE_SCHEMA_VERSION = 1;
export const EVIDENCE_SCHEMA_VERSION = 1;

export const VERDICT_IDS = ["proved", "violated", "vacuous", "inconsistent", "unknown"] as const;
export type Verdict = (typeof VERDICT_IDS)[number];

const header = object({ name: string, value: string });
export type Header = Infer<typeof header>;

const counterexample = object({
  principal: string,
  action: string,
  path: string,
  host: string,
  scheme: string,
  sni: string,
  headers: array(header),
  source_ip: string,
  route: nullable(string),
  service: nullable(string),
  shadowed_route: nullable(string),
  shadowed_service: nullable(string),
});
export type Counterexample = Infer<typeof counterexample>;

const assuranceStatus = oneOf(["within_profile", "conservative", "unsupported"]);
export type AssuranceStatus = Infer<typeof assuranceStatus>;

const assuranceFinding = object({
  code: string,
  service: nullable(string),
  route: nullable(string),
  detail: string,
});
export type AssuranceFinding = Infer<typeof assuranceFinding>;

const assurance = object({ profile: string, status: assuranceStatus, findings: array(assuranceFinding) });
export type Assurance = Infer<typeof assurance>;

const frozenSpec = object({ schema_version: integer, kind: string, canonical: string });
export type FrozenSpec = Infer<typeof frozenSpec>;

const clause = object({ name: string, description: string, kind: oneOf(["must_deny", "must_allow"]) });
export type Clause = Infer<typeof clause>;

const WITH_REASON: readonly Verdict[] = ["inconsistent", "unknown"];

export const verifyReport = refine(
  object(
    {
      result: oneOf(VERDICT_IDS),
      schema_version: literal(VERIFY_SCHEMA_VERSION),
      property: string,
      assurance: nullable(assurance),
      frozen_spec: nullable(frozenSpec),
      clause: nullable(clause),
      counterexample: nullable(counterexample),
    },
    { reason: string },
  ),
  (report) => {
    if ((report.result === "violated") !== (report.counterexample !== null)) {
      return "a counterexample must be present exactly when the result is violated";
    }
    if (WITH_REASON.includes(report.result) !== (report.reason !== undefined)) {
      return "a reason must be present exactly when the result is inconsistent or unknown";
    }
    return null;
  },
);
export type VerifyReport = Infer<typeof verifyReport>;

const witnessRequest = object({
  principal: oneOf(["anonymous", "authenticated"]),
  action: string,
  path: string,
  host: string,
  scheme: string,
  sni: string,
  headers: array(header),
  source_ip: string,
});
export type WitnessRequest = Infer<typeof witnessRequest>;

const serviceTarget = object({ protocol: string, host: string, port: integer, path: nullable(string) });
export type ServiceTarget = Infer<typeof serviceTarget>;

const observation = object({
  decision: oneOf(["allow", "deny"]),
  route: nullable(string),
  service: nullable(string),
  service_target: nullable(serviceTarget),
  upstream_uri: nullable(string),
});
export type Observation = Infer<typeof observation>;

const witness = object({ request: witnessRequest, before: observation, after: observation });
export type Witness = Infer<typeof witness>;

export const COMPARISON_KINDS = ["security_decision", "route_service", "service_target", "upstream_uri"] as const;
export type ComparisonKind = (typeof COMPARISON_KINDS)[number];

export const compareReport = refine(
  object(
    {
      result: oneOf(["equivalent", "different", "unknown"]),
      schema_version: literal(COMPARE_SCHEMA_VERSION),
      comparison: oneOf(COMPARISON_KINDS),
      assurance_profile: string,
      witness: nullable(witness),
    },
    { reason: string },
  ),
  (report) => {
    if ((report.result === "different") !== (report.witness !== null)) {
      return "a witness must be present exactly when the result is different";
    }
    if ((report.result === "unknown") !== (report.reason !== undefined)) {
      return "a reason must be present exactly when the result is unknown";
    }
    return null;
  },
);
export type CompareReport = Infer<typeof compareReport>;

const canonicalContract = object(
  {
    schema_version: integer,
    kind: string,
    scope: object({ path_prefix: string, method: nullable(string), host: nullable(string) }, { trusted_cidr: string }),
  },
  { assumptions: object({ source_ip_integrity: string }) },
);
export type CanonicalContract = Infer<typeof canonicalContract>;

export const REPAIR_COMPARISONS = [
  "frozen_scope_preservation",
  "frozen_route_service_preservation",
  "frozen_service_target_preservation",
  "frozen_upstream_uri_preservation",
] as const;

export const repairReport = refine(
  object(
    {
      result: oneOf(["valid_repair", "contract_failed", "out_of_scope_regression", "unknown"]),
      schema_version: literal(COMPARE_SCHEMA_VERSION),
      comparison: oneOf(REPAIR_COMPARISONS),
      assurance_profile: string,
      frozen_spec: canonicalContract,
      contract_result: verifyReport,
      witness: nullable(witness),
    },
    { reason: string },
  ),
  (report) => {
    if ((report.result === "out_of_scope_regression") !== (report.witness !== null)) {
      return "a witness must be present exactly when the result is out_of_scope_regression";
    }
    if ((report.result === "unknown") !== (report.reason !== undefined)) {
      return "a reason must be present exactly when the result is unknown";
    }
    if (report.contract_result.frozen_spec === null) {
      return "a repair's contract_result must carry the frozen spec identity";
    }
    const inner = report.contract_result.result;
    // Scope preservation is only judged once the frozen contract is proved.
    if ((report.result === "valid_repair" || report.result === "out_of_scope_regression") && inner !== "proved") {
      return `${report.result} requires a proved contract_result, got ${inner}`;
    }
    if (report.result === "contract_failed" && !["violated", "vacuous", "inconsistent"].includes(inner)) {
      return `contract_failed requires a failed contract_result, got ${inner}`;
    }
    if (report.result === "unknown" && inner !== "unknown" && inner !== "proved") {
      return `unknown requires an unknown or proved contract_result, got ${inner}`;
    }
    return null;
  },
);
export type RepairReport = Infer<typeof repairReport>;

const profileFeature = object({ code: string, description: string });
export type ProfileFeature = Infer<typeof profileFeature>;

export const assuranceProfile = object({
  schema_version: literal(PROFILE_SCHEMA_VERSION),
  id: string,
  connector: string,
  version: integer,
  target: string,
  modeled: array(profileFeature),
  conservative: array(profileFeature),
  unsupported: array(profileFeature),
});
export type AssuranceProfile = Infer<typeof assuranceProfile>;

const sha256: Validator<string> = refine(string, (value) =>
  /^[0-9a-f]{64}$/.test(value) ? null : "expected a lowercase SHA-256 hex digest",
);
const artifact = object({ path: string, sha256 });
const opaque: Validator<unknown> = (value) => value;

/**
 * The evidence bundle manifest written by `verify --contract --evidence-dir`.
 * Obligation entries are carried through opaquely: the verdict comes from the
 * validated report, and the manifest supplies provenance.
 */
export const evidenceManifest = object({
  schema_version: literal(EVIDENCE_SCHEMA_VERSION),
  config: object({ sha256, size_bytes: integer }),
  contract: artifact,
  assurance_profile: object({ id: string, artifact }),
  soundcheck: object({
    executable_sha256: sha256,
    ocaml_version: string,
    report_schema_version: literal(VERIFY_SCHEMA_VERSION),
  }),
  solver: object({ name: literal("z3"), version: nullable(string), version_error: nullable(string) }),
  obligation_plan: opaque,
  obligations: array(opaque),
  report: artifact,
  result: oneOf(VERDICT_IDS),
});
export type EvidenceManifest = Infer<typeof evidenceManifest>;

export function isRepairReport(report: CompareReport | RepairReport): report is RepairReport {
  return "contract_result" in report;
}
