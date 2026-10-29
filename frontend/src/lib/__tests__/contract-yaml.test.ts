import { describe, expect, it } from "vitest";
import { contractProblems, contractYaml, EMPTY_CONTRACT, type ContractDraft } from "../contract-yaml";

const draft: ContractDraft = {
  ...EMPTY_CONTRACT,
  kind: "protected-prefix-with-public-exceptions",
  pathPrefix: "/api",
  publicPathPrefixes: "/api/health\n/api/status",
};

describe("public exception contract authoring", () => {
  it("keeps each public prefix explicit under the reviewed scope", () => {
    expect(contractProblems(draft)).toEqual([]);
    expect(contractYaml(draft)).toBe(
      "schema_version: 1\nkind: protected-prefix-with-public-exceptions\nscope:\n  path_prefix: /api\n  method: GET\n  public_path_prefixes:\n    - /api/health\n    - /api/status\n",
    );
  });

  it.each(["", "/api", "/outside", "/api/health\n/api/health"])("flags an invalid exception list: %s", (publicPathPrefixes) => {
    expect(contractProblems({ ...draft, publicPathPrefixes }).length).toBeGreaterThan(0);
  });

  it("quotes prefixes that could inject YAML and retains the exact string", () => {
    const output = contractYaml({ ...draft, publicPathPrefixes: "/api/foo: bar # comment" });
    expect(output).toContain('    - "/api/foo: bar # comment"\n');
  });

  it("does not attach exceptions to existing contract kinds", () => {
    expect(contractYaml(EMPTY_CONTRACT)).not.toContain("public_path_prefixes");
  });
});
