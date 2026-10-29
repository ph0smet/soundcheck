import { describe, expect, it } from "vitest";

import { reproduceCommand, type AuditCheck, type AuditFile } from "../audit";
import { shellCommand, shellQuote } from "../shell";

const file: AuditFile = { index: 0, path: "config.yaml", bytes: 1, sha256: null, status: "audit", gateway: "kong" };
const check = (pathPrefix: string): AuditCheck => ({
  id: "no-anonymous-access",
  label: "No anonymous access",
  description: "",
  basis: "exploratory",
  assumptions: [],
  parameters: null,
  statement: [],
  spec: { mode: "property", property: "no-anonymous-access", pathPrefix },
});

describe("shell quoting", () => {
  it("quotes a prefix that would otherwise run another command (review repro)", () => {
    expect(reproduceCommand(file, check("/admin;id"))).toBe(
      "soundcheck verify config.yaml --property no-anonymous-access --path-prefix '/admin;id'",
    );
  });

  it.each(["/admin*", "/a?b", "/a[b]", "/a b", "/$HOME", "/`id`", "/a|b", "/a&b", "/a>b", "~/x", "=cmd", "/a{b,c}", "/a'b"])(
    "quotes %s so the shell passes it through unchanged",
    (value) => {
      const quoted = shellQuote(value);
      expect(quoted).not.toBe(value);
      expect(quoted.startsWith("'")).toBe(true);
    },
  );

  it("escapes embedded single quotes", () => {
    expect(shellQuote("it's")).toBe(String.raw`'it'\''s'`);
  });

  it("leaves plain words alone and quotes every argument, including file paths", () => {
    expect(shellCommand(["soundcheck", "verify", "my configs/kong.yaml", "--trusted-cidr", "10.0.0.0/8"])).toBe(
      "soundcheck verify 'my configs/kong.yaml' --trusted-cidr 10.0.0.0/8",
    );
  });
});
