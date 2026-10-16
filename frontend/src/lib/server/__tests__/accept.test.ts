import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import type { EvidenceManifest, VerifyReport } from "@/lib/contract";

import { acceptCompare, acceptVerify, checkEvidence } from "../accept";
import type { RunResult } from "../engine";

function run(overrides: Partial<RunResult>): RunResult {
  return {
    exitCode: 0,
    signal: null,
    stdout: "",
    stderr: "",
    durationMs: 10,
    timedOut: false,
    outputExceeded: false,
    aborted: false,
    ...overrides,
  };
}

const assurance = { profile: "kong-3.x-v1", status: "within_profile", findings: [] };

const proved = {
  result: "proved",
  schema_version: 9,
  property: "no-anonymous-access",
  assurance,
  frozen_spec: null,
  clause: null,
  counterexample: null,
};

const counterexample = {
  principal: "anonymous",
  action: "GET",
  path: "/admin",
  host: "",
  scheme: "http",
  sni: "",
  headers: [],
  source_ip: "10.0.0.1",
  route: "admin",
  service: "admin-svc",
  shadowed_route: null,
  shadowed_service: null,
};

const violated = { ...proved, result: "violated", counterexample };

const property = { mode: "property", property: "no-anonymous-access" } as const;

function verify(stdout: unknown, overrides: Partial<RunResult> = {}) {
  const text = typeof stdout === "string" ? stdout : JSON.stringify(stdout);
  return acceptVerify(run({ stdout: text, ...overrides }), "soundcheck verify", property);
}

function expectFailure(result: ReturnType<typeof verify>, stage: string) {
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.stage).toBe(stage);
}

describe("acceptVerify: accepted runs", () => {
  it("accepts a proved report with exit 0", () => {
    const result = verify(proved);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.report.result).toBe("proved");
  });

  it("accepts a violated report with exit 3", () => {
    expect(verify(violated, { exitCode: 3 }).ok).toBe(true);
  });

  it("accepts an unknown report with a reason and exit 4", () => {
    expect(verify({ ...proved, result: "unknown", reason: "unsupported regex" }, { exitCode: 4 }).ok).toBe(true);
  });

  it("tolerates a trailing newline", () => {
    expect(verify(`${JSON.stringify(proved)}\n`).ok).toBe(true);
  });
});

describe("acceptVerify: false greens are rejected", () => {
  it("rejects an empty object even with exit 0", () => {
    expectFailure(verify({}), "protocol");
  });

  it("rejects a proved report printed before a timeout", () => {
    expectFailure(verify(proved, { timedOut: true, exitCode: null, signal: "SIGTERM" }), "engine");
  });

  it("rejects a proved report when the process was killed by a signal", () => {
    expectFailure(verify(proved, { exitCode: null, signal: "SIGKILL" }), "engine");
  });

  it("rejects a proved report when output overflowed", () => {
    expectFailure(verify(proved, { outputExceeded: true }), "protocol");
  });

  it("reports a cancelled run as cancelled, never as a verdict", () => {
    expectFailure(verify(proved, { aborted: true }), "cancelled");
  });

  it("rejects a proved report with a non-zero exit code", () => {
    expectFailure(verify(proved, { exitCode: 3 }), "protocol");
    expectFailure(verify(proved, { exitCode: 4 }), "protocol");
  });

  it("rejects a violated report with exit 0", () => {
    expectFailure(verify(violated, { exitCode: 0 }), "protocol");
  });

  it("treats exit 1 as a tool error even if stdout looks like a proof", () => {
    expectFailure(verify(proved, { exitCode: 1 }), "parse");
  });

  it("rejects exit codes the CLI does not define", () => {
    expectFailure(verify(proved, { exitCode: 7 }), "protocol");
    expectFailure(verify(proved, { exitCode: 137 }), "protocol");
  });

  it("rejects an unknown schema version", () => {
    expectFailure(verify({ ...proved, schema_version: 8 }), "protocol");
    expectFailure(verify({ ...proved, schema_version: 10 }), "protocol");
  });

  it("rejects unexpected fields", () => {
    expectFailure(verify({ ...proved, verified: true }), "protocol");
  });

  it("rejects missing fields", () => {
    const missing: Record<string, unknown> = { ...proved };
    delete missing.assurance;
    expectFailure(verify(missing), "protocol");
  });

  it("rejects an unknown result value", () => {
    expectFailure(verify({ ...proved, result: "pass" }), "protocol");
  });

  it("rejects a violated report without a counterexample", () => {
    expectFailure(verify({ ...proved, result: "violated" }, { exitCode: 3 }), "protocol");
  });

  it("rejects a proved report that carries a counterexample", () => {
    expectFailure(verify({ ...proved, counterexample }), "protocol");
  });

  it("rejects an unknown report without a reason", () => {
    expectFailure(verify({ ...proved, result: "unknown" }, { exitCode: 4 }), "protocol");
  });

  it("rejects two concatenated documents", () => {
    expectFailure(verify(`${JSON.stringify(proved)}\n${JSON.stringify(proved)}`), "protocol");
  });

  it("rejects text around the document", () => {
    expectFailure(verify(`warning: slow\n${JSON.stringify(proved)}`), "protocol");
  });

  it("rejects a JSON array or scalar", () => {
    expectFailure(verify("[]"), "protocol");
    expectFailure(verify("true"), "protocol");
    expectFailure(verify(""), "protocol");
  });

  it("rejects a report for a different property", () => {
    expectFailure(verify({ ...proved, property: "rate-limit-on-public" }), "protocol");
  });

  it("rejects a property report that claims a frozen spec", () => {
    const frozen = { schema_version: 1, kind: "authenticated-access", canonical: "{}" };
    expectFailure(verify({ ...proved, frozen_spec: frozen }), "protocol");
  });

  it("requires the frozen spec identity on contract runs", () => {
    const result = acceptVerify(run({ stdout: JSON.stringify(proved) }), "soundcheck verify", { mode: "contract" });
    expectFailure(result, "protocol");
  });

  it("rejects wrongly typed nested values", () => {
    expectFailure(verify({ ...violated, counterexample: { ...counterexample, headers: "none" } }, { exitCode: 3 }), "protocol");
    expectFailure(verify({ ...proved, assurance: { ...assurance, status: "fine" } }), "protocol");
  });
});

const observation = { decision: "allow", route: "r", service: "s", service_target: null, upstream_uri: null };
const witness = {
  request: {
    principal: "anonymous",
    action: "GET",
    path: "/",
    host: "",
    scheme: "http",
    sni: "",
    headers: [],
    source_ip: "10.0.0.1",
  },
  before: observation,
  after: { ...observation, decision: "deny" },
};

const equivalent = {
  result: "equivalent",
  schema_version: 1,
  comparison: "security_decision",
  assurance_profile: "kong-3.x-v1",
  witness: null,
};

function compare(report: unknown, exitCode = 0, mode: "decision" | "upstream-uri" = "decision", contract = false) {
  return acceptCompare(run({ stdout: JSON.stringify(report), exitCode }), "soundcheck compare", mode, contract);
}

describe("acceptCompare", () => {
  it("accepts an equivalent report", () => {
    expect(compare(equivalent).ok).toBe(true);
  });

  it("accepts a different report with a witness and exit 3", () => {
    expect(compare({ ...equivalent, result: "different", witness }, 3).ok).toBe(true);
  });

  it("accepts the upstream-uri mode", () => {
    expect(compare({ ...equivalent, comparison: "upstream_uri" }, 0, "upstream-uri").ok).toBe(true);
  });

  it("rejects a report for a different comparison mode", () => {
    expect(compare(equivalent, 0, "upstream-uri").ok).toBe(false);
  });

  it("rejects equivalent with exit 3 and different with exit 0", () => {
    expect(compare(equivalent, 3).ok).toBe(false);
    expect(compare({ ...equivalent, result: "different", witness }, 0).ok).toBe(false);
  });

  it("rejects different without a witness", () => {
    expect(compare({ ...equivalent, result: "different" }, 3).ok).toBe(false);
  });

  const repair = {
    result: "valid_repair",
    schema_version: 1,
    comparison: "frozen_scope_preservation",
    assurance_profile: "kong-3.x-v1",
    frozen_spec: {
      schema_version: 1,
      kind: "authenticated-access",
      scope: { path_prefix: "/admin", method: "GET", host: null },
    },
    contract_result: {
      ...proved,
      property: "authenticated-access",
      frozen_spec: { schema_version: 1, kind: "authenticated-access", canonical: "{}" },
    },
    witness: null,
  };

  it("accepts a valid repair with a proved contract", () => {
    expect(compare(repair, 0, "decision", true).ok).toBe(true);
  });

  it("rejects a valid repair whose contract was not proved", () => {
    const failed = { ...repair, contract_result: { ...repair.contract_result, result: "violated", counterexample } };
    expect(compare(failed, 0, "decision", true).ok).toBe(false);
  });

  it("requires contract_failed to use the contract's exit code", () => {
    const failed = {
      ...repair,
      result: "contract_failed",
      contract_result: { ...repair.contract_result, result: "violated", counterexample },
    };
    expect(compare(failed, 3, "decision", true).ok).toBe(true);
    expect(compare(failed, 0, "decision", true).ok).toBe(false);
  });

  it("rejects a plain comparison where a repair report was requested", () => {
    expect(compare(equivalent, 0, "decision", true).ok).toBe(false);
  });
});

describe("checkEvidence", () => {
  const config = "services: []\n";
  const canonical = '{"schema_version":1,"kind":"authenticated-access","scope":{"path_prefix":"/admin","method":"GET","host":null}}';
  const report = {
    ...proved,
    property: "authenticated-access",
    assurance: { profile: "kong-3.x-v1", status: "within_profile" as const, findings: [] },
    frozen_spec: { schema_version: 1, kind: "authenticated-access", canonical },
  } as unknown as VerifyReport;
  const stdout = `${JSON.stringify(report)}\n`;
  const hash = (text: string) => createHash("sha256").update(text).digest("hex");
  const manifest = {
    schema_version: 1,
    config: { sha256: hash(config), size_bytes: config.length },
    contract: { path: "contract.json", sha256: hash(`${canonical}\n`) },
    assurance_profile: { id: "kong-3.x-v1", artifact: { path: "assurance-profile.json", sha256: "0".repeat(64) } },
    soundcheck: { executable_sha256: "f".repeat(64), ocaml_version: "5.2.0", report_schema_version: 9 },
    solver: { name: "z3", version: "Z3 version 4.16.0 - 64 bit", version_error: null },
    obligation_plan: {},
    obligations: [],
    report: { path: "report.json", sha256: hash(stdout) },
    result: "proved",
  } as unknown as EvidenceManifest;

  it("accepts a bundle that matches the accepted run exactly", () => {
    expect(checkEvidence(manifest, { config, stdout, report })).toBeNull();
  });

  it("rejects a bundle for different config bytes", () => {
    expect(checkEvidence(manifest, { config: `${config} `, stdout, report })).toMatch(/different config/);
  });

  it("rejects a bundle for a different printed report", () => {
    expect(checkEvidence(manifest, { config, stdout: `${stdout} `, report })).toMatch(/different report/);
  });

  it("rejects a bundle for a different contract", () => {
    const other = { ...report, frozen_spec: { ...report.frozen_spec!, canonical: `${canonical} ` } } as VerifyReport;
    expect(checkEvidence(manifest, { config, stdout, report: other })).toMatch(/different contract/);
  });

  it("rejects a bundle that records a different verdict or profile", () => {
    expect(checkEvidence({ ...manifest, result: "violated" }, { config, stdout, report })).toMatch(/records violated/);
    const profile = { ...manifest, assurance_profile: { ...manifest.assurance_profile, id: "other" } };
    expect(checkEvidence(profile, { config, stdout, report })).toMatch(/names profile other/);
  });
});

describe("repair reports", () => {
  it("rejects a repair whose contract_result lacks the frozen spec identity", () => {
    const repair = {
      result: "valid_repair",
      schema_version: 1,
      comparison: "frozen_scope_preservation",
      assurance_profile: "kong-3.x-v1",
      frozen_spec: { schema_version: 1, kind: "authenticated-access", scope: { path_prefix: "/admin", method: null, host: null } },
      contract_result: { ...proved, property: "authenticated-access" },
      witness: null,
    };
    expect(compare(repair, 0, "decision", true).ok).toBe(false);
  });
});
