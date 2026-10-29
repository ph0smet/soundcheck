import { readFileSync } from "node:fs";
import path from "node:path";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AuditWorkspace } from "@/components/audit/audit-workspace";
import { RequestLine } from "@/components/results/request";
import { VerifyReportView } from "@/components/results/verify-result";

import { auditChecks, DEFAULT_AUDIT_OPTIONS } from "../audit";
import { verifyReport } from "../contract";
import { parseJson } from "../schema";

// This checked-in witness has an empty method, but the fixture guards GET and
// exposes only other methods. The value cannot stand for "any method".
const report = parseJson(
  readFileSync(path.resolve(__dirname, "../../../../bench/kong/cases/category-more-criteria-wins/expected.json"), "utf8"),
  verifyReport,
);
const witness = report.counterexample;
if (!witness) throw new Error("The corpus regression needs a counterexample.");

describe("witness presentation", () => {
  it("preserves an empty method in both the request card and route trace", () => {
    expect(witness.action).toBe("");
    const html = renderToStaticMarkup(createElement(VerifyReportView, { report }));
    expect(html.match(/\(empty method\)/g)).toHaveLength(2);
    expect(html).toContain("this does not establish the result for other methods");
    expect(html).not.toMatch(/any[ -]method/i);
    expect(witness.action).toBe("");
  });

  it("shows a nonempty method exactly as supplied, without adding scope", () => {
    const html = renderToStaticMarkup(createElement(RequestLine, { request: { ...witness, action: "POST" } }));
    expect(html).toContain(">POST</span>");
    expect(html).not.toContain("(empty method)");
    expect(html).not.toMatch(/any[ -]method/i);
  });
});

describe("audit setup", () => {
  it("shows the same preset assumptions as the audit, including the anonymous-only Admin API boundary", () => {
    const html = renderToStaticMarkup(createElement(AuditWorkspace, { contracts: [] }));
    for (const check of auditChecks(DEFAULT_AUDIT_OPTIONS, null)) {
      expect(html).toContain(check.assumptions.join(" "));
    }
    expect(html).toContain("Anonymous requests from outside 127.0.0.1/32");
    expect(html).toContain("authenticated requests are not checked");
    expect(html).not.toContain("only the trusted block");
  });
});
