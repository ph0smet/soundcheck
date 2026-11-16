import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { RbacCoreReport, RbacSequenceTimeline, RbacWitness } from "@/components/rbac/result";
import { RbacWorkspace } from "@/components/rbac/workspace";
import type { VerifyReport } from "../contract";
import type { RbacSequenceReport } from "../rbac/contract";
import { contextKey, decodeRbacUpload, failureLocation, outcome, RequestEpoch, runKey, sequenceRows, witnessDecision } from "../rbac/presentation";

function access(result: VerifyReport["result"] = "proved"): VerifyReport {
  return { schema_version: 10, result, property: "kubernetes-rbac-access",
    assurance: { profile: "kubernetes-rbac-v1.34-get-v3", status: "within_profile", findings: [] },
    frozen_spec: { schema_version: 1, kind: "kubernetes-rbac-access", canonical: "{}" },
    clause: null, counterexample: null,
  };
}
function witness(kind: "must_allow" | "must_not_grant" | "must_preserve" = "must_allow"): VerifyReport {
  return { ...access("violated"), clause: { name: "keep-access", description: "Frozen requirement description.", kind },
    counterexample: { principal: "system:serviceaccount:apps:worker", action: "get", path: "", host: "", scheme: "", sni: "", headers: [], source_ip: "0.0.0.0", route: null, service: null, shadowed_route: null, shadowed_service: null,
      object_request: { namespace: "apps", resource_kind: "configmaps", name: "settings" }, identity_groups: ["system:serviceaccounts", "trusted-group"], granting_rules: [] },
  };
}
const hash = "0".repeat(64);
const digest = { sha256: hash, bytes: 1 };
const inputs = { before: digest, after: digest };
function sequence(): Extract<RbacSequenceReport, { schema_version: 2 }> {
  const auth = { method: "deterministic-native-rbac-policy-coverage" as const, allowed: true, reason: "Initial grant present.", initial: { attributes: { verb: "delete", api_group: "rbac.authorization.k8s.io" as const, namespace: "apps", resource: "rolebindings", subresource: "" as const, name: "old" }, granting_rule_indices: [0] }, special: null, coverage: null };
  const invariant = { ...access(), property: "rbac-sequence-invariants" };
  return { schema_version: 2, kind: "kubernetes-rbac-policy-sequence", result: "valid_sequence", reason: "Every required stage passed.", phase: "complete", failing_step: null,
    assurance: { profile: "kubernetes-rbac-v1.34-policy-sequence-v2", status: "within_profile" }, frozen_spec: { schema_version: 2, kind: "kubernetes-rbac-policy-sequence", canonical: "{}" }, inputs,
    states: [0,1,2].map(index => ({ index, digest })),
    steps: [1,2].map(index => ({ index, operation: "delete-existing", target: { kind: "RoleBinding", namespace: "apps", name: `old-${index}` }, inputs, authorization: auth })),
    verification: { candidate_report: access(), comparison_report: { ...access(), property: "rbac-repair-preservation" } },
    intermediate_preservation: [{ step: 1, inputs, status: "proved", report: { ...access(), property: "rbac-sequence-preservation" } }],
    state_invariants: [0,1,2].map(state => ({ state, input: digest, status: "proved", report: invariant })),
  };
}

const html = (report: VerifyReport) => renderToStaticMarkup(createElement(RbacWitness, { report }));

describe("RBAC upload fidelity", () => {
  it("preserves valid UTF-8 characters, whitespace and a supplied BOM", () => {
    const source = '\uFEFF{\n  "identity": "équipe-猫 😀", "literal": "\uFFFD"\n}\n';
    expect(decodeRbacUpload(new TextEncoder().encode(source).buffer)).toBe(source);
  });
  it.each([
    { label: "an invalid continuation", bytes: [0xc3, 0x28] },
    { label: "a truncated character", bytes: [0xe2, 0x82] },
    { label: "an overlong encoding", bytes: [0xc0, 0xaf] },
    { label: "an encoded surrogate", bytes: [0xed, 0xa0, 0x80] },
  ])("rejects $label instead of inserting replacement characters", ({ bytes }) => {
    expect(() => decodeRbacUpload(Uint8Array.from(bytes).buffer)).toThrow(TypeError);
  });
});

describe("RBAC witness presentation", () => {
  it("shows missing required access as NoOpinion, retaining identity and groups", () => {
    const output = html(witness());
    expect(output).toContain("NoOpinion — required access is missing");
    expect(output).toContain("system:serviceaccount:apps:worker");
    expect(output).toContain("trusted-group");
    expect(output).toContain("settings");
    expect(output).toContain("not a final API-server denial");
    expect(output).not.toContain("HTTP request");
  });
  it("shows forbidden grants as Allow without turning preservation witnesses into a guessed direction", () => {
    expect(html(witness("must_not_grant"))).toContain("Allow — forbidden access is granted");
    expect(witnessDecision(witness("must_preserve"))).toBe("A decision changed outside the approved scope");
  });
  it("retains empty authorization attributes instead of displaying any-name/namespace wildcards", () => {
    const report = witness();
    report.counterexample!.object_request = { namespace: "", resource_kind: "namespaces", name: "" };
    const output = html(report);
    expect(output).toContain("(empty authorization namespace)");
    expect(output).toContain("(empty authorization name)");
    expect(output).not.toMatch(/all namespaces|any name/);
  });
  it("renders non-resource URLs without invented object coordinates", () => {
    const report = witness("must_not_grant");
    report.counterexample!.object_request = null;
    report.counterexample!.path = "/healthz";
    const output = html(report);
    expect(output).toContain("Non-resource URL");
    expect(output).toContain("/healthz");
    expect(output).not.toContain("Authorization namespace");
  });
  it("keeps compound operations conditional and does not infer success from a granting-rule list", () => {
    const report = witness();
    report.counterexample!.action = "apply-missing";
    report.counterexample!.granting_rules = ["patch grant in role worker"];
    const output = html(report);
    expect(output).toContain("apply-missing");
    expect(output).toContain("NoOpinion — required access is missing");
    expect(output).toContain("at least one lacks a grant");
    expect(output).toContain("does not observe an actual storage branch");
    expect(output).toContain("patch grant in role worker");
  });
  it("escapes supplied identity, clause and rule strings", () => {
    const report = witness();
    report.counterexample!.principal = "<script>alert(1)</script>";
    const output = html(report);
    expect(output).not.toContain("<script>");
    expect(output).toContain("&lt;script&gt;");
  });
});

describe("migration state presentation", () => {
  it("includes the baseline and never labels baseline authorization/preservation as proved", () => {
    const rows = sequenceRows(sequence());
    expect(rows.map(row => row.state)).toEqual([0,1,2]);
    expect(rows[0]).toMatchObject({ authorization: "not_applicable", preservation: "not_applicable", invariant: "proved" });
    expect(rows[2].preservation).toBe("proved");
  });
  it("marks an S0 invariant failure and subsequent planned checks as unexecuted", () => {
    const report = sequence();
    report.result = "invariant_failed"; report.phase = "state_invariants"; report.failing_step = 0;
    report.state_invariants[0] = { state: 0, input: digest, status: "violated", report: { ...witness(), property: "rbac-sequence-invariants" } };
    report.state_invariants.slice(1).forEach(check => { check.status = "not_executed"; check.report = null; });
    report.intermediate_preservation[0].status = "not_executed"; report.intermediate_preservation[0].report = null;
    const rows = sequenceRows(report);
    expect(rows[0]).toMatchObject({ failed: true, invariant: "violated" });
    expect(rows[1]).toMatchObject({ invariant: "not_executed", preservation: "not_executed" });
    expect(rows[2].preservation).toBe("proved"); // final comparison ran before S0 invariant evaluation
    const output = renderToStaticMarkup(createElement(RbacSequenceTimeline, { report }));
    expect(output).toContain("S0"); expect(output).toContain("Reported failure");
    expect(output).toContain("Not executed");
    expect(output).toContain("need not be the earliest chronological defect");
  });
  it("attributes failed authorization to the preceding state, not execution of the resulting state", () => {
    const report = sequence(); report.phase = "authorization"; report.failing_step = 2;
    expect(failureLocation(report)).toBe("Operation 2, using S1");
    report.phase = "state_invariants"; report.failing_step = 0;
    expect(failureLocation(report)).toBe("State S0 (baseline)");
  });
  it("separates no selected invariants from skipped selected invariants", () => {
    const report = sequence(); report.state_invariants = [];
    expect(sequenceRows(report).every(row => row.invariant === "not_selected")).toBe(true);
    const legacy = JSON.parse(JSON.stringify(report)) as RbacSequenceReport;
    Object.assign(legacy, { schema_version: 1 });
    Reflect.deleteProperty(legacy, "state_invariants");
    expect(sequenceRows(legacy).every(row => row.invariant === "not_selected")).toBe(true);
  });
  it("does not show final preservation as executed when candidate requirements failed first", () => {
    const report = sequence();
    report.verification = { candidate_report: witness(), comparison_report: witness() };
    expect(sequenceRows(report)[2].preservation).toBe("not_executed");
  });
  it("labels null obligation reports as not executed and unknown/vacuous as nonproofs", () => {
    const output = renderToStaticMarkup(createElement(RbacCoreReport, { title: "Preservation", report: null }));
    expect(output).toContain("Not executed"); expect(output).not.toContain("Proved");
    expect(outcome("unknown", "sequence").tone).toBe("unknown");
    expect(outcome("vacuous", "verify").explanation).toContain("not a proof");
  });
});

describe("review and asynchronous result ownership", () => {
  it("rejects a completion after cancel, replacement, unmount or a newer request", () => {
    const requests = new RequestEpoch();
    const first = requests.begin(); requests.invalidate();
    expect(requests.accepts(first)).toBe(false);
    const second = requests.begin(); const third = requests.begin();
    expect(requests.accepts(second)).toBe(false); expect(requests.accepts(third)).toBe(true);
    requests.invalidate(); expect(requests.accepts(third)).toBe(false);
  });
  it("candidate edits invalidate result identity without changing the locked review identity", () => {
    const context = contextKey("sequence", "contract", "baseline");
    expect(contextKey("sequence", "contract", "baseline")).toBe(context);
    expect(runKey("sequence", "contract", "baseline", "old")).not.toBe(runKey("sequence", "contract", "baseline", "new"));
    expect(contextKey("sequence", "changed", "baseline")).not.toBe(context);
    expect(contextKey("sequence", "contract", "changed")).not.toBe(context);
    expect(contextKey("change", "contract", "baseline")).not.toBe(context);
  });
  it("does not let irrelevant hidden baseline content alter an access-only run identity", () => {
    expect(contextKey("verify", "contract", "hidden old baseline")).toBe(contextKey("verify", "contract", ""));
  });
  it("initial rendering asks for review and offers no implied successful result", () => {
    const output = renderToStaticMarkup(createElement(RbacWorkspace, { examples: [] }));
    expect(output).toContain("Review inputs");
    expect(output).toContain("Run verification");
    expect(output).toContain("Structural review checks the contract");
    expect(output).not.toContain("Valid migration");
    expect(output).not.toContain("localStorage");
  });
});
