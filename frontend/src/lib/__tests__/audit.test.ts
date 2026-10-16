import { describe, expect, it } from "vitest";

import type { VerifyResponse } from "../api";
import {
  auditChecks,
  DEFAULT_AUDIT_OPTIONS,
  resultKey,
  totals,
  type AuditFile,
  type AuditRun,
} from "../audit";
import type { Verdict } from "../contract";
import { renderMarkdown } from "../report/markdown";
import { buildReport } from "../report/model";

const engine = { source: "build", label: "main.exe", executableSha256: "a".repeat(64), solverVersion: "Z3 version 4.16.0 - 64 bit" };

function file(index: number, overrides: Partial<AuditFile> = {}): AuditFile {
  return { index, path: `kong-${index}.yaml`, bytes: 100, sha256: "b".repeat(64), status: "audit", gateway: "kong", ...overrides };
}

function response(result: Verdict): VerifyResponse {
  return {
    ok: true,
    exitCode: { proved: 0, violated: 3, unknown: 4, vacuous: 5, inconsistent: 6 }[result],
    durationMs: 1,
    command: "soundcheck verify",
    provenance: { inputs: {}, engine: { ...engine, source: "build" }, evidence: null },
    report: {
      result,
      schema_version: 9,
      property: "p",
      assurance: null,
      frozen_spec: null,
      clause: null,
      counterexample:
        result === "violated"
          ? {
              principal: "anonymous",
              action: "GET",
              path: "/admin",
              host: "",
              scheme: "http",
              sni: "",
              headers: [],
              source_ip: "10.0.0.1",
              route: "r",
              service: "s",
              shadowed_route: null,
              shadowed_service: null,
            }
          : null,
      ...(result === "unknown" || result === "inconsistent" ? { reason: "why" } : {}),
    },
  };
}

function makeRun(options: {
  files?: AuditFile[];
  contract?: boolean;
  fill?: Verdict | null;
  completion?: AuditRun["completion"];
}): AuditRun {
  const files = options.files ?? [file(0), file(1)];
  const checks = auditChecks(DEFAULT_AUDIT_OPTIONS, options.contract ? "authenticated-access" : null);
  const results: AuditRun["results"] = {};
  if (options.fill !== null) {
    for (const item of files.filter((entry) => entry.status === "audit")) {
      for (const check of checks) results[resultKey(item.index, check.id)] = response(options.fill ?? "proved");
    }
  }
  return {
    source: "configs.zip",
    gateway: "kong",
    profile: "kong-3.x-v1",
    options: DEFAULT_AUDIT_OPTIONS,
    contract: options.contract ? "kind: authenticated-access\n" : null,
    checks,
    files,
    results,
    startedAt: "2026-10-16T00:00:00Z",
    durationMs: 1000,
    completion: options.completion ?? "complete",
    failure: null,
    provenance: { sourceSha256: "c".repeat(64), engine, profile: "kong-3.x-v1", contractSha256: null },
  };
}

describe("audit status", () => {
  it("passes only with a frozen contract and every check proved", () => {
    expect(totals(makeRun({ contract: true })).status).toBe("pass");
  });

  it("never passes on exploratory presets alone", () => {
    expect(totals(makeRun({ contract: false })).status).toBe("no-findings");
  });

  it("is incomplete when zero checks completed", () => {
    expect(totals(makeRun({ contract: true, fill: null })).status).toBe("incomplete");
  });

  it("is incomplete when no config was audited", () => {
    const run = makeRun({
      contract: true,
      files: [file(0, { status: "skipped", gateway: null, skip: { reason: "unsupported-type", detail: ".md" } })],
    });
    expect(totals(run).status).toBe("incomplete");
  });

  it("is incomplete when any planned check is still pending", () => {
    const run = makeRun({ contract: true });
    delete run.results[resultKey(1, "contract")];
    const sum = totals(run);
    expect(sum.status).toBe("incomplete");
    expect(sum.pending).toBe(1);
  });

  it("is incomplete after cancellation, even if every result had arrived", () => {
    expect(totals(makeRun({ contract: true, completion: "cancelled" })).status).toBe("incomplete");
  });

  it("is incomplete when the stream failed", () => {
    expect(totals(makeRun({ contract: true, completion: "failed" })).status).toBe("incomplete");
  });

  it("still reports a concrete violation from an unfinished run", () => {
    const run = makeRun({ contract: true, completion: "cancelled", fill: null });
    run.results[resultKey(0, "no-anonymous-access")] = response("violated");
    expect(totals(run).status).toBe("fail");
  });

  it.each(["too-large", "unreadable", "not-a-config", "coming-soon"] as const)(
    "needs review when a possible config was skipped (%s)",
    (reason) => {
      const run = makeRun({
        contract: true,
        files: [file(0), file(1, { status: "skipped", gateway: null, skip: { reason, detail: "" } })],
      });
      const sum = totals(run);
      expect(sum.status).toBe("review");
      expect(sum.coverageGaps).toBe(1);
    },
  );

  it("ignores files of an unrelated type", () => {
    const run = makeRun({
      contract: true,
      files: [file(0), file(1, { status: "skipped", gateway: null, skip: { reason: "unsupported-type", detail: ".md" } })],
    });
    expect(totals(run).status).toBe("pass");
  });

  it("needs review when a proof is about a config outside the assurance profile", () => {
    const run = makeRun({ contract: true });
    const cell = run.results[resultKey(0, "contract")];
    if (!cell.ok) throw new Error("fixture");
    run.results[resultKey(0, "contract")] = {
      ...cell,
      report: { ...cell.report, assurance: { profile: "kong-3.x-v1", status: "unsupported", findings: [] } },
    };
    const sum = totals(run);
    expect(sum.status).toBe("review");
    expect(sum.unsupported).toBe(1);
  });

  it("needs review for unknown, vacuous or error outcomes", () => {
    expect(totals(makeRun({ contract: true, fill: "unknown" })).status).toBe("review");
    expect(totals(makeRun({ contract: true, fill: "vacuous" })).status).toBe("review");
    const run = makeRun({ contract: true });
    run.results[resultKey(0, "contract")] = { ok: false, stage: "protocol", exitCode: 0, message: "bad schema" };
    expect(totals(run).status).toBe("review");
  });
});

describe("audit report", () => {
  it("labels an incomplete run as incomplete and lists checks that never ran", () => {
    const run = makeRun({ contract: true, completion: "cancelled" });
    delete run.results[resultKey(1, "contract")];
    run.failure = "The audit was cancelled before every check ran.";
    const markdown = renderMarkdown(buildReport(run));
    expect(markdown).toContain("**Overall: Incomplete.**");
    expect(markdown).toContain("INCOMPLETE (cancelled)");
    expect(markdown).toContain("NOT RUN");
    expect(markdown).not.toContain("Overall: Pass");
  });

  it("records provenance: source, config and engine digests and the solver", () => {
    const markdown = renderMarkdown(buildReport(makeRun({ contract: true })));
    expect(markdown).toContain("c".repeat(64));
    expect(markdown).toContain(`Config SHA-256: ${"b".repeat(64)}`);
    expect(markdown).toContain("a".repeat(64));
    expect(markdown).toContain("Z3 version 4.16.0");
  });

  it("marks presets as exploratory and states their assumptions", () => {
    const markdown = renderMarkdown(buildReport(makeRun({ contract: false })));
    expect(markdown).toContain("[Exploratory preset]");
    expect(markdown).toContain("Assumes: Everything under /admin must require authentication.");
    expect(markdown).toContain("No findings (exploratory)");
  });
});
