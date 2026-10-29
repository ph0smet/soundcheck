export type ContractKind = "authenticated-access" | "network-restricted-access" | "protected-prefix-with-public-exceptions";

export interface ContractDraft {
  kind: ContractKind;
  pathPrefix: string;
  method: string;
  host: string;
  trustedCidr: string;
  publicPathPrefixes: string;
  acknowledged: boolean;
}

export const EMPTY_CONTRACT: ContractDraft = {
  kind: "authenticated-access",
  pathPrefix: "/admin",
  method: "GET",
  host: "",
  trustedCidr: "10.0.0.0/8",
  publicPathPrefixes: "/admin/health",
  acknowledged: false,
};

function scalar(value: string) {
  return /^[\w./*-]+$/.test(value) ? value : JSON.stringify(value);
}

function publicPrefixes(draft: ContractDraft): string[] {
  return draft.publicPathPrefixes.split(/\r?\n/).map((prefix) => prefix.trim()).filter(Boolean);
}

/** Renders the strict, versioned artifact the engine loads with --contract. */
export function contractYaml(draft: ContractDraft): string {
  const lines = ["schema_version: 1", `kind: ${draft.kind}`, "scope:", `  path_prefix: ${scalar(draft.pathPrefix.trim())}`];
  if (draft.method.trim()) lines.push(`  method: ${scalar(draft.method.trim().toUpperCase())}`);
  if (draft.host.trim()) lines.push(`  host: ${scalar(draft.host.trim())}`);
  if (draft.kind === "protected-prefix-with-public-exceptions") {
    const prefixes = publicPrefixes(draft);
    if (prefixes.length) {
      lines.push("  public_path_prefixes:", ...prefixes.map((prefix) => `    - ${scalar(prefix)}`));
    } else {
      lines.push("  public_path_prefixes: []");
    }
  }
  if (draft.kind === "network-restricted-access") {
    lines.push(`  trusted_cidr: ${scalar(draft.trustedCidr.trim())}`);
    lines.push("assumptions:", "  source_ip_integrity: externally-enforced");
  }
  return `${lines.join("\n")}\n`;
}

export function contractProblems(draft: ContractDraft): string[] {
  const problems: string[] = [];
  if (!draft.pathPrefix.startsWith("/")) problems.push("The path prefix must start with /.");
  if (draft.kind === "protected-prefix-with-public-exceptions") {
    const prefixes = publicPrefixes(draft);
    const outer = draft.pathPrefix.trim();
    if (!prefixes.length) problems.push("Enter at least one public path prefix.");
    if (prefixes.some((prefix) => prefix === outer || !prefix.startsWith(outer))) {
      problems.push("Every public prefix must be strictly inside the protected prefix.");
    }
    if (new Set(prefixes).size !== prefixes.length) problems.push("Public prefixes must be distinct.");
  }
  if (draft.kind === "network-restricted-access") {
    if (!/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(draft.trustedCidr.trim())) {
      problems.push("Enter a trusted IPv4 block such as 10.0.0.0/8.");
    }
    if (!draft.acknowledged) {
      problems.push("Confirm that the deployment protects the client IP Kong derives.");
    }
  }
  return problems;
}
