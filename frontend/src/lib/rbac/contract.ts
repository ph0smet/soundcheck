/** Strict RBAC wire contracts. These validate presentation protocol, never policy semantics. */
import { verifyReport, type VerifyReport } from "../contract";
import { array, integer, literal, nullable, object, oneOf, refine, string, SchemaError, type Infer, type Validator } from "../schema";
import type { JsonValue } from "./api";

export const bool: Validator<boolean> = (value, path) => {
  if (typeof value !== "boolean") throw new SchemaError(path, "expected boolean");
  return value;
};
export const nonnegative = refine(integer, (n) => n >= 0 ? null : "expected nonnegative integer");
export const sha256 = refine(string, (s) => /^[0-9a-f]{64}$/.test(s) ? null : "expected SHA-256");
const outerVersion = refine(integer, (n) => n === 1 || n === 2 ? null : "unsupported outer schema");
const frozen = object({ schema_version: integer, kind: string, canonical: string });
export const inputDigest = object({ sha256, bytes: nonnegative });
const inputs = object({ before: inputDigest, after: inputDigest });
export const target = object({ kind: oneOf(["Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"]), namespace: nullable(string), name: string });
const check = object({ attributes: object({ verb: string, api_group: literal("rbac.authorization.k8s.io"), namespace: string, resource: string, subresource: literal(""), name: string }), granting_rule_indices: array(nonnegative) });
const resourceRule = object({ verbs: array(string), apiGroups: array(string), resources: array(string), resourceNames: array(string) });
const urlRule = object({ verbs: array(string), nonResourceURLs: array(string) });
const policyRule: Validator<Infer<typeof resourceRule> | Infer<typeof urlRule>> = (v, p) => {
  return typeof v === "object" && v !== null && "nonResourceURLs" in v ? urlRule(v, p) : resourceRule(v, p);
};
export const authorization = refine(object({
  method: literal("deterministic-native-rbac-policy-coverage"), allowed: bool, reason: string,
  initial: check, special: nullable(check), coverage: nullable(object({ covered: bool, atom_count: nonnegative,
    missing: array(object({ proposed_rule_index: nonnegative, atom_index: nonnegative, rule: policyRule })) })),
}), (a) => {
  if (a.allowed && a.initial.granting_rule_indices.length === 0) return "allowed authorization lacks initial grant";
  if (a.coverage && a.coverage.covered !== (a.coverage.missing.length === 0)) return "coverage disagrees with missing rules";
  if (a.allowed && a.special && !a.special.granting_rule_indices.length && !a.coverage?.covered) return "allowed authorization lacks special authority or coverage";
  if (!a.allowed && a.initial.granting_rule_indices.length && (a.special?.granting_rule_indices.length || a.coverage?.covered)) return "denied authorization contradicts checked grants";
  return null;
});
export type RbacAuthorization = Infer<typeof authorization>;
/** Check native stage presence/request coordinates, not whether any policy grants them. */
export function authorizationProblem(a:RbacAuthorization,operation:string,t:Infer<typeof target>,roleRef?:{kind:string;name:string}):string|null {
  const resource={Role:"roles",ClusterRole:"clusterroles",RoleBinding:"rolebindings",ClusterRoleBinding:"clusterrolebindings"}[t.kind];
  const initial={verb:operation==="create"?"create":operation==="delete-existing"?"delete":"update",api_group:"rbac.authorization.k8s.io",namespace:t.namespace??"",resource,subresource:"",name:operation==="create"?"":t.name};
  if(!jsonEqual(a.initial.attributes,initial)) return "initial authorization request differs from frozen operation/target";
  if(!a.initial.granting_rule_indices.length) return a.allowed||a.special!==null||a.coverage!==null?"initial failure carries later authorization stages":null;
  if(operation==="delete-existing") return !a.allowed||a.special!==null||a.coverage!==null?"ordinary deletion has unexpected authorization stages":null;
  if(!a.special) return "create/update authorization lacks bind/escalate stage";
  const role=t.kind==="Role"||t.kind==="ClusterRole";
  if(role) {
    if(!jsonEqual(a.special.attributes,{...initial,verb:"escalate"})) return "escalate request differs from frozen target";
  } else {
    const special=a.special.attributes;
    if(special.verb!=="bind"||special.namespace!==initial.namespace||!["roles","clusterroles"].includes(special.resource)||!special.name) return "invalid binding authorization request";
    if(roleRef && (special.name!==roleRef.name||special.resource!==(roleRef.kind==="Role"?"roles":"clusterroles"))) return "bind request differs from candidate roleRef";
  }
  if(a.special.granting_rule_indices.length) return !a.allowed||a.coverage!==null?"explicit authority carries incoherent coverage":null;
  if(!a.coverage||a.allowed!==a.coverage.covered) return "authorization outcome disagrees with native policy coverage";
  return null;
}

export const rbacVerifyReport = refine(verifyReport, (r) => {
  if (!r.assurance?.profile.startsWith("kubernetes-rbac-")) return "expected an RBAC assurance profile";
  if (r.assurance.status === "conservative" || (r.assurance.status === "unsupported" && r.result !== "unknown")) return "RBAC assurance status cannot support this verdict";
  if (!r.frozen_spec) return "RBAC reports require frozen contract identity";
  const canonical = JSON.parse(r.frozen_spec.canonical) as { kind?: string; schema_version?: number; requirements?: { schema_version?: number } };
  if (canonical.kind !== r.frozen_spec.kind || canonical.schema_version !== r.frozen_spec.schema_version) return "frozen identity does not describe its canonical artifact";
  const accessVersion = r.property === "rbac-sequence-invariants" ? canonical.requirements?.schema_version : canonical.schema_version;
  if (canonical.kind !== (r.property === "rbac-sequence-invariants" ? "kubernetes-rbac-policy-sequence" : "kubernetes-rbac-access") || !Number.isInteger(accessVersion) || accessVersion! < 1 || accessVersion! > 10 || r.assurance.profile !== ACCESS_PROFILES[accessVersion! - 1]) return "report property or profile disagrees with its frozen identity";
  if (!["kubernetes-rbac-access", "rbac-repair-preservation", "rbac-sequence-invariants", "rbac-sequence-preservation"].includes(r.property)) return "unsupported RBAC report property";
  if (r.counterexample && r.counterexample.identity_groups === null) return "RBAC witness lacks trusted identity groups";
  return null;
});
export type RbacVerifyReport = Infer<typeof rbacVerifyReport>;
const verification = object({ comparison_report: rbacVerifyReport, candidate_report: nullable(rbacVerifyReport) });
const assurance = object({ profile: string, status: oneOf(["within_profile", "unsupported_or_inconclusive"]) });
const common = { schema_version: outerVersion, reason: string, assurance, frozen_spec: nullable(frozen), inputs, verification: nullable(verification) };
const changeShape = object({ ...common, kind: literal("kubernetes-rbac-policy-change"),
  result: oneOf(["valid_change", "authorization_failed", "contract_failed", "out_of_scope_regression", "unknown"]), authorization: nullable(authorization) });
const operation = oneOf(["create", "update-existing", "delete-existing"]);
const invariant = object({ state: nonnegative, input: inputDigest,
  status: oneOf(["proved", "violated", "vacuous", "inconsistent", "unknown", "not_executed"]), report: nullable(rbacVerifyReport) });
const preservation = object({ step: nonnegative, inputs,
  status: oneOf(["proved", "violated", "unknown", "not_executed"]), report: nullable(rbacVerifyReport) });
const sequenceBase = { ...common, kind: literal("kubernetes-rbac-policy-sequence"),
  result: oneOf(["valid_sequence", "authorization_failed", "contract_failed", "invariant_failed", "out_of_scope_regression", "unknown"]),
  phase: oneOf(["preparation", "authorization", "final_verification", "state_invariants", "intermediate_preservation", "complete"]),
  failing_step: nullable(nonnegative), states: array(object({ index: nonnegative, digest: inputDigest })),
  steps: array(object({ index: nonnegative, operation, target, inputs, authorization: nullable(authorization) })),
  intermediate_preservation: array(preservation),
};
const sequenceV1 = object({ ...sequenceBase, schema_version: literal(1) });
const sequenceV2 = object({ ...sequenceBase, schema_version: literal(2), state_invariants: array(invariant) });
export type RbacChangeReport = Infer<typeof changeShape>;
export type RbacSequenceReport = Infer<typeof sequenceV1> | Infer<typeof sequenceV2>;
export type RbacReport = RbacVerifyReport | RbacChangeReport | RbacSequenceReport;

export function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((v, i) => jsonEqual(v, b[i]));
  if (a && b && typeof a === "object" && typeof b === "object" && !Array.isArray(a) && !Array.isArray(b)) {
    const x = a as Record<string, unknown>, y = b as Record<string, unknown>;
    return Object.keys(x).length === Object.keys(y).length && Object.keys(x).every(k => Object.hasOwn(y, k) && jsonEqual(x[k], y[k]));
  }
  return false;
}
function outerProblem(r: RbacChangeReport | RbacSequenceReport): string | null {
  if (!r.frozen_spec || r.frozen_spec.kind !== r.kind || r.frozen_spec.schema_version !== r.schema_version) return "outer frozen identity disagrees with report kind/version";
  const expected = `kubernetes-rbac-v1.34-policy-${r.kind.endsWith("sequence") ? "sequence" : "change"}-v${r.schema_version}`;
  if (r.assurance.profile !== expected) return "wrong outer assurance profile";
  if ((r.result === "unknown") !== (r.assurance.status === "unsupported_or_inconclusive")) return "outer assurance status disagrees with result";
  const canonical = JSON.parse(r.frozen_spec.canonical) as { requirements?: { schema_version?: number } };
  const requirements = canonical.requirements;
  if (!requirements || !Number.isInteger(requirements.schema_version) || requirements.schema_version! < 1 || requirements.schema_version! > 10) return "invalid nested access schema";
  const nestedProblem = (report: RbacVerifyReport) => report.assurance?.profile !== ACCESS_PROFILES[requirements.schema_version! - 1] || report.frozen_spec?.kind !== "kubernetes-rbac-access" || report.frozen_spec.schema_version !== requirements.schema_version || !jsonEqual(JSON.parse(report.frozen_spec.canonical), requirements);
  const v = r.verification;
  if (v) {
    if (nestedProblem(v.comparison_report) || (v.candidate_report && nestedProblem(v.candidate_report))) return "nested report contract/profile mismatch";
    if (v.comparison_report.property !== (v.candidate_report?.result === "proved" ? "rbac-repair-preservation" : "kubernetes-rbac-access")) return "wrong final comparison property";
    if (v.candidate_report && v.candidate_report.property !== "kubernetes-rbac-access") return "wrong candidate property";
    if (v.comparison_report.result === "proved" && v.candidate_report?.result !== "proved") return "proved comparison requires proved candidate";
  }
  if (r.result === "contract_failed" && (!v || !["violated", "vacuous", "inconsistent"].includes(v.comparison_report.result) || v.candidate_report?.result === "proved")) return "contract failure lacks a failed candidate stage";
  return null;
}
export const rbacChangeReport = refine(changeShape, (r) => {
  const problem = outerProblem(r); if (problem) return problem;
  const canonical=object({schema_version:outerVersion,kind:literal("kubernetes-rbac-policy-change"),actor:string,operation,target,requirements:(v:unknown)=>v})(JSON.parse(r.frozen_spec!.canonical),"canonical change");
  if(canonical.schema_version!==r.schema_version || (r.schema_version===1&&canonical.operation==="delete-existing")) return "change canonical version/operation mismatch";
  if(r.authorization) {const problem=authorizationProblem(r.authorization,canonical.operation,canonical.target);if(problem)return problem;}
  if (r.verification && !r.authorization?.allowed) return "verification cannot precede successful authorization";
  if (r.result === "authorization_failed" && (!r.authorization || r.authorization.allowed || r.verification)) return "invalid authorization failure";
  if (r.result === "valid_change" && (!r.authorization?.allowed || r.verification?.comparison_report.result !== "proved")) return "valid change lacks completed proof stages";
  if (r.result === "out_of_scope_regression" && (r.verification?.comparison_report.result !== "violated" || r.verification!.candidate_report?.result !== "proved")) return "preservation failure lacks proved candidate and violated preservation";
  return null;
});

function statusProblem(status: string, report: VerifyReport | null) {
  return status === "not_executed" ? report !== null : report === null || status !== report.result;
}
export const rbacSequenceReport: Validator<RbacSequenceReport> = (value, path) => {
  const r = typeof value === "object" && value !== null && "schema_version" in value && value.schema_version === 1
    ? sequenceV1(value, path) : sequenceV2(value, path);
  const fail = (reason: string): never => { throw new SchemaError(path, reason); };
  const problem = outerProblem(r); if (problem) fail(problem);
  const invariants = "state_invariants" in r ? r.state_invariants : [];
  const declared = object({ schema_version: outerVersion, kind: literal("kubernetes-rbac-policy-sequence"), actor: string, steps: array(object({ operation, target })), requirements: (v: unknown) => v }, r.schema_version === 2 ? { invariants: array(string) } : {})(JSON.parse(r.frozen_spec!.canonical), "canonical sequence");
  const selected = "invariants" in declared ? declared.invariants : undefined;
  if (r.schema_version === 2 && !Array.isArray(selected)) fail("schema 2 lacks frozen invariant selection");
  if (r.phase !== "preparation" && (r.steps.length !== declared.steps.length || r.intermediate_preservation.length !== declared.steps.length - 1 || invariants.length !== (Array.isArray(selected) && selected.length ? declared.steps.length + 1 : 0))) fail("incomplete frozen sequence plan");
  if (r.steps.some((s,i) => s.operation !== declared.steps[i]?.operation || !jsonEqual(s.target,declared.steps[i]?.target))) fail("reported steps differ from frozen order/targets");
  const req = declared.requirements as { schema_version: number };
  for (const stage of r.intermediate_preservation) if (stage.report && (stage.report.assurance?.profile !== ACCESS_PROFILES[req.schema_version - 1] || stage.report.frozen_spec?.kind !== "kubernetes-rbac-access" || stage.report.frozen_spec.schema_version !== req.schema_version || !jsonEqual(JSON.parse(stage.report.frozen_spec.canonical),req))) fail("intermediate report frozen identity/profile mismatch");
  for (const stage of invariants) if (stage.report && (stage.report.assurance?.profile !== ACCESS_PROFILES[req.schema_version - 1] || !jsonEqual(stage.report.frozen_spec,r.frozen_spec))) fail("invariant report frozen identity/profile mismatch");
  if (r.schema_version === 1 && (r.result === "invariant_failed" || r.phase === "state_invariants" || r.steps.some(s => s.operation === "delete-existing"))) fail("schema 1 cannot claim schema 2 semantics");
  if (r.states.length && r.states.length !== r.steps.length + 1) fail("state/step count mismatch");
  if (r.states.some((s, i) => s.index !== i) || r.steps.some((s, i) => s.index !== i + 1)) fail("nonconsecutive state or step indexes");
  if (r.steps.length > 16) fail("sequence exceeds supported step bound");
  for (const s of r.steps) {
    if(s.authorization) {const problem=authorizationProblem(s.authorization,s.operation,s.target);if(problem)fail(problem);}
    if (JSON.stringify(s.inputs.before) !== JSON.stringify(r.states[s.index - 1]?.digest) || JSON.stringify(s.inputs.after) !== JSON.stringify(r.states[s.index]?.digest)) fail("step input digests disagree with states");
  }
  if (r.states.length && (JSON.stringify(r.states[0].digest) !== JSON.stringify(r.inputs.before) || JSON.stringify(r.states.at(-1)?.digest) !== JSON.stringify(r.inputs.after))) fail("endpoint state inputs disagree");
  if (r.intermediate_preservation.some((p, i) => p.step !== i + 1 || statusProblem(p.status, p.report) || (p.report && p.report.property !== "rbac-sequence-preservation") || JSON.stringify(p.inputs.before) !== JSON.stringify(r.inputs.before) || JSON.stringify(p.inputs.after) !== JSON.stringify(r.states[p.step]?.digest))) fail("incoherent intermediate preservation stage");
  if (invariants.some((p, i) => p.state !== i || statusProblem(p.status, p.report) || (p.report && p.report.property !== "rbac-sequence-invariants") || JSON.stringify(p.input) !== JSON.stringify(r.states[p.state]?.digest))) fail("incoherent state invariant stage");
  const allAuthorized = r.steps.length > 0 && r.steps.every(s => s.authorization?.allowed);
  const finalProved = r.verification?.comparison_report.result === "proved";
  const allInvariants = invariants.every(i => i.status === "proved");
  if (r.verification && !allAuthorized) fail("final verification precedes authorization");
  if (invariants.some(i => i.report) && !finalProved) fail("invariants precede final verification");
  if (r.intermediate_preservation.some(p => p.report) && (!finalProved || !allInvariants)) fail("preservation precedes required stages");
  if (r.phase === "complete" || r.result === "valid_sequence") {
    if (r.phase !== "complete" || r.result !== "valid_sequence" || r.failing_step !== null || !allAuthorized || !finalProved || !allInvariants || r.intermediate_preservation.length !== r.steps.length - 1 || r.intermediate_preservation.some(p => p.status !== "proved")) fail("valid sequence lacks complete proof stages");
  } else if (r.phase === "preparation") {
    if (r.result !== "unknown" || r.steps.length || r.states.length || r.verification || invariants.length || r.intermediate_preservation.length) fail("preparation failure contains executed stages");
  } else if (r.phase === "authorization") {
    const failed = r.steps.find(s => s.index === r.failing_step);
    if (!failed || r.verification || !["authorization_failed", "unknown"].includes(r.result) || (r.result === "authorization_failed" && failed.authorization?.allowed !== false) || (r.result === "unknown" && failed.authorization !== null) || r.steps.some(s => s.index < failed.index ? !s.authorization?.allowed : s.index > failed.index && s.authorization !== null)) fail("incoherent authorization phase");
  } else if (r.phase === "state_invariants") {
    const failed = invariants.find(i => i.state === r.failing_step);
    if (!failed || !failed.report || !["invariant_failed", "unknown"].includes(r.result) || (r.result === "unknown") !== (failed.report.result === "unknown") || failed.report.result === "proved" || invariants.some(i => i.state < failed.state ? i.status !== "proved" : i.state > failed.state && i.report !== null)) fail("incoherent invariant failure");
  } else if (r.phase === "intermediate_preservation") {
    const failed = r.intermediate_preservation.find(i => i.step === r.failing_step);
    if (!failed || !failed.report || !["out_of_scope_regression", "unknown"].includes(r.result) || failed.report.result !== (r.result === "unknown" ? "unknown" : "violated") || r.intermediate_preservation.some(i => i.step < failed.step ? i.status !== "proved" : i.step > failed.step && i.report !== null)) fail("incoherent preservation failure");
  } else if (r.phase === "final_verification") {
    if (!r.verification || r.failing_step !== r.steps.length || !["contract_failed", "out_of_scope_regression", "unknown"].includes(r.result)) fail("incoherent final verification failure");
    if (r.result === "unknown" && r.verification!.comparison_report.result !== "unknown") fail("unknown final phase lacks unknown comparison");
    if (r.result === "out_of_scope_regression" && (r.verification!.comparison_report.result !== "violated" || r.verification!.candidate_report?.result !== "proved")) fail("final preservation failure lacks proved candidate and violated comparison");
  }
  return r;
};

export const ACCESS_PROFILES = ["kubernetes-rbac-v1.34-get-v3", "kubernetes-rbac-v1.34-read-v3", "kubernetes-rbac-v1.34-read-write-v3", "kubernetes-rbac-v1.34-scoped-read-write-v3", "kubernetes-rbac-v1.34-resource-read-write-v1", "kubernetes-rbac-v1.34-collection-write-v1", "kubernetes-rbac-v1.34-subresources-v1", "kubernetes-rbac-v1.34-apply-v1", "kubernetes-rbac-v1.34-static-coverage-v1", "kubernetes-rbac-v1.34-controller-apis-v1"] as const;
export type RbacProfile = { schema_version: number; id: string; assumptions: string[]; [key: string]: JsonValue };
const profileBase = { schema_version: integer, id: string, connector: literal("kubernetes-rbac"), reference_version: literal("v1.34.0"), input_format: literal("strict-json-kubernetes-list"), decision: literal("Allow|NoOpinion"), assumptions: array(string) };
const resourceBase = { api_group: string, resource: string, scope: oneOf(["namespaced", "cluster"]), resource_kind: string };
const domains = array(object(resourceBase));
const subresourceBase = { ...resourceBase, subresource: string };
const operationBase = { name_domain: string, namespace_domain: string };
const domains7 = array(object({ ...subresourceBase, operations: array(object({ ...operationBase, verb: string })) }));
const domains8 = array(object({ ...subresourceBase, operations: array(object({ ...operationBase, operation: string, checks: array(string), object_state: nullable(string) })) }));
export const rbacProfile: Validator<RbacProfile> = (v, p) => {
  if (typeof v !== "object" || v === null || !("id" in v) || typeof v.id !== "string") throw new SchemaError(p, "expected profile");
  let parsed: unknown;
  if (/^kubernetes-rbac-v1\.34-policy-(change|sequence)-v[12]$/.test(v.id)) {
    const shape = { schema_version: outerVersion, id: string, kubernetes_version: literal("1.34.0"), authorization_method: literal("deterministic-native-rbac-policy-coverage"), scope: string, assumptions: array(string) };
    parsed = v.id.includes("sequence") ? object({ ...shape, max_steps: literal(16) })(v, p) : object(shape)(v, p);
    const r = parsed as RbacProfile;
    if (!r.id.endsWith(`-v${r.schema_version}`)) throw new SchemaError(p, "profile version mismatch");
  } else {
    const version = ACCESS_PROFILES.indexOf(v.id as typeof ACCESS_PROFILES[number]) + 1;
    if (!version) throw new SchemaError(p, "unsupported RBAC profile id");
    const base = { ...profileBase, id: literal(v.id) };
    if (version === 1) parsed = object({ ...base, schema_version: literal(1), verb: literal("get"), api_group: literal(""), subresource: literal(""), resources: array(string) })(v,p);
    else {
      const b = { ...base, contract_schema_version: literal(version) };
      if (version <= 4) parsed = object({ ...b, schema_version: literal(2), verbs: array(string), api_group: literal(""), subresource: literal(""), resources: array(string) })(v,p);
      else if (version <= 6) parsed = object({ ...b, schema_version: literal(3), verbs: array(string), subresource: literal(""), resource_domains: domains })(v,p);
      else if (version === 7) parsed = object({ ...b, schema_version: literal(4), resource_domains: domains7 })(v,p);
      else if (version === 8) parsed = object({ ...b, schema_version: literal(5), resource_domains: domains8 })(v,p);
      else parsed = object({ ...b, schema_version: literal(6), resource_domains: domains8,
        custom_resource_catalogue: object({ source: literal("frozen_contract.custom_resources"), max_base_resources: literal(64), authorization: literal("initial-only") }),
        non_resource_domain: object({ methods: array(string), path_domain: literal("canonical-absolute-ascii-unreserved-non-resource-paths"), classification: literal("Kubernetes v1.34 RequestInfo with api/apis prefixes") }) })(v,p);
    }
  }
  return parsed as RbacProfile;
};
