// TypeScript mirror of the engine's stable JSON contracts. Source of truth:
// core/report.ml (verify, schema 9), connectors/kong/compare.ml (compare and
// repair, schema 1) and connectors/kong/assurance.ml (profile, schema 1).

export type Verdict = "proved" | "violated" | "vacuous" | "inconsistent" | "unknown";

export interface Header {
  name: string;
  value: string;
}

export interface Counterexample {
  principal: string;
  action: string;
  path: string;
  host: string;
  scheme: string;
  sni: string;
  headers: Header[];
  source_ip: string;
  route: string | null;
  service: string | null;
  shadowed_route: string | null;
  shadowed_service: string | null;
}

export type AssuranceStatus = "within_profile" | "conservative" | "unsupported";

export interface AssuranceFinding {
  code: string;
  service: string | null;
  route: string | null;
  detail: string;
}

export interface Assurance {
  profile: string;
  status: AssuranceStatus;
  findings: AssuranceFinding[];
}

export interface FrozenSpec {
  schema_version: number;
  kind: string;
  canonical: string;
}

export interface Clause {
  name: string;
  description: string;
  kind: "must_deny" | "must_allow";
}

export interface VerifyReport {
  result: Verdict;
  schema_version: number;
  property: string;
  assurance: Assurance | null;
  frozen_spec: FrozenSpec | null;
  clause: Clause | null;
  counterexample: Counterexample | null;
  reason?: string;
}

export interface WitnessRequest {
  principal: string;
  action: string;
  path: string;
  host: string;
  scheme: string;
  sni: string;
  headers: Header[];
  source_ip: string;
}

export interface ServiceTarget {
  protocol: string;
  host: string;
  port: number;
  path: string | null;
}

export interface Observation {
  decision: "allow" | "deny";
  route: string | null;
  service: string | null;
  service_target: ServiceTarget | null;
}

export interface Witness {
  request: WitnessRequest;
  before: Observation;
  after: Observation;
}

export type ComparisonKind = "security_decision" | "route_service" | "service_target";

export interface CompareReport {
  result: "equivalent" | "different" | "unknown";
  schema_version: number;
  comparison: ComparisonKind;
  assurance_profile: string;
  witness: Witness | null;
  reason?: string;
}

export interface CanonicalContract {
  schema_version: number;
  kind: string;
  scope: {
    path_prefix: string;
    method: string | null;
    host: string | null;
    trusted_cidr?: string;
  };
  assumptions?: { source_ip_integrity: string };
}

export interface RepairReport {
  result: "valid_repair" | "contract_failed" | "out_of_scope_regression" | "unknown";
  schema_version: number;
  comparison:
    | "frozen_scope_preservation"
    | "frozen_route_service_preservation"
    | "frozen_service_target_preservation";
  assurance_profile: string;
  frozen_spec: CanonicalContract;
  contract_result: VerifyReport;
  witness: Witness | null;
  reason?: string;
}

export interface ProfileFeature {
  code: string;
  description: string;
}

export interface AssuranceProfile {
  schema_version: number;
  id: string;
  connector: string;
  version: number;
  target: string;
  modeled: ProfileFeature[];
  conservative: ProfileFeature[];
  unsupported: ProfileFeature[];
}

export function isRepairReport(report: CompareReport | RepairReport): report is RepairReport {
  return "contract_result" in report;
}
