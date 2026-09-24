import type { PropertyId, PropertySpec } from "./api";
import type { AssuranceStatus, Verdict } from "./contract";

export type Tone = "proved" | "violated" | "vacuous" | "unknown" | "inconsistent";

export interface PropertyInfo {
  id: PropertyId;
  title: string;
  question: string;
  params: ("pathPrefix" | "method" | "host" | "trustedCidr")[];
  paired: boolean;
  defaults: Partial<Record<"pathPrefix" | "trustedCidr", string>>;
  requiredCidr?: boolean;
  note?: string;
}

export const PROPERTIES: PropertyInfo[] = [
  {
    id: "no-anonymous-access",
    title: "No anonymous access",
    question: "Can any unauthenticated request reach a protected path prefix?",
    params: ["pathPrefix"],
    paired: false,
    defaults: { pathPrefix: "/admin" },
  },
  {
    id: "rate-limit-on-public",
    title: "Rate limit on public",
    question:
      "Is every anonymously-reachable route covered by a general request-rate limiting plugin?",
    params: [],
    paired: false,
    defaults: {},
  },
  {
    id: "no-shadowed-routes",
    title: "No shadowed routes",
    question:
      "Does a permissive route intercept traffic a stricter route was written to handle?",
    params: [],
    paired: false,
    defaults: {},
    note: "Reads intent from the config itself and reports structure, not intent. A deliberately public health check can be a legitimate finding.",
  },
  {
    id: "admin-api-not-reachable",
    title: "Admin API not reachable",
    question:
      "Can an anonymous request from outside a trusted address block reach a route proxying the Admin API?",
    params: ["trustedCidr"],
    paired: false,
    defaults: { trustedCidr: "127.0.0.1/32" },
    note: "The Admin API is recognised by its default upstream ports, 8001 and 8444.",
  },
  {
    id: "authenticated-access",
    title: "Authenticated access",
    question:
      "Are anonymous requests denied while authenticated requests stay definitely allowed in one explicit scope?",
    params: ["pathPrefix", "method", "host"],
    paired: true,
    defaults: { pathPrefix: "/admin" },
  },
  {
    id: "network-restricted-access",
    title: "Network restricted access",
    question:
      "Are requests outside a trusted IPv4 block denied while authenticated requests inside it stay definitely allowed?",
    params: ["pathPrefix", "method", "host", "trustedCidr"],
    paired: true,
    defaults: { pathPrefix: "/admin" },
    requiredCidr: true,
  },
];

export function propertyInfo(id: string): PropertyInfo | undefined {
  return PROPERTIES.find((p) => p.id === id);
}

function scopeTerms(spec: { pathPrefix?: string; method?: string; host?: string }) {
  const terms = [`prefix(path, "${spec.pathPrefix || "/admin"}")`];
  if (spec.method) terms.push(`method = ${spec.method.toUpperCase()}`);
  if (spec.host) terms.push(`host = "${spec.host.toLowerCase()}"`);
  return terms.join(" ∧ ");
}

export interface FormalClause {
  label?: string;
  text: string;
}

export function formalStatement(spec: PropertySpec): FormalClause[] {
  const prefix = spec.pathPrefix || "/admin";
  switch (spec.property) {
    case "no-anonymous-access":
      return [{ text: `∀ req. prefix(path, "${prefix}") ∧ principal = anonymous ⇒ Deny` }];
    case "rate-limit-on-public":
      return [{ text: "∀ req. principal = anonymous ∧ Allow(req) ⇒ rate_limited(rule(req))" }];
    case "no-shadowed-routes":
      return [{ text: "¬∃ req. selected_i(req) ∧ match_k(req) ∧ guard_i(req) ∧ ¬guard_k(req)" }];
    case "admin-api-not-reachable":
      return [
        {
          text: `∀ req. principal = anonymous ∧ source ∉ ${spec.trustedCidr || "127.0.0.1/32"} ∧ upstream ∈ AdminAPI ⇒ Deny`,
        },
      ];
    case "authenticated-access": {
      const scope = scopeTerms(spec);
      return [
        { label: "must_deny", text: `∀ req. ${scope} ∧ principal = anonymous ⇒ Deny` },
        { label: "must_allow", text: `∀ req. ${scope} ∧ principal = authenticated ⇒ Allow` },
      ];
    }
    case "network-restricted-access": {
      const scope = scopeTerms(spec);
      const cidr = spec.trustedCidr || "‹cidr›";
      return [
        { label: "must_deny", text: `∀ req. ${scope} ∧ source ∉ ${cidr} ⇒ Deny` },
        {
          label: "must_allow",
          text: `∀ req. ${scope} ∧ principal = authenticated ∧ source ∈ ${cidr} ⇒ Allow`,
        },
      ];
    }
  }
}

export interface OutcomeInfo {
  label: string;
  tone: Tone;
  exitCode: number | null;
  meaning: string;
}

export const VERDICTS: Record<Verdict, OutcomeInfo> = {
  proved: {
    label: "Proved",
    tone: "proved",
    exitCode: 0,
    meaning: "No violating request exists anywhere in the modeled request space.",
  },
  violated: {
    label: "Violated",
    tone: "violated",
    exitCode: 3,
    meaning: "The solver produced a concrete request the config allows but the property forbids.",
  },
  vacuous: {
    label: "Vacuous",
    tone: "vacuous",
    exitCode: 5,
    meaning:
      "The property's forbidden request class is empty, so nothing about this config was verified.",
  },
  inconsistent: {
    label: "Inconsistent",
    tone: "inconsistent",
    exitCode: 6,
    meaning: "The frozen contract contradicts itself, so no config could ever satisfy it.",
  },
  unknown: {
    label: "Unknown",
    tone: "unknown",
    exitCode: 4,
    meaning:
      "The config leaves the supported fragment. Soundcheck refuses to guess rather than report a false proof.",
  },
};

export const COMPARE_OUTCOMES: Record<string, OutcomeInfo> = {
  equivalent: {
    label: "Equivalent",
    tone: "proved",
    exitCode: 0,
    meaning: "Both configs agree on every modeled request.",
  },
  different: {
    label: "Different",
    tone: "violated",
    exitCode: 3,
    meaning: "The solver found a request on which the two configs disagree.",
  },
  unknown: {
    label: "Unknown",
    tone: "unknown",
    exitCode: 4,
    meaning: "The model cannot support an exact comparison for these configs.",
  },
  valid_repair: {
    label: "Valid repair",
    tone: "proved",
    exitCode: 0,
    meaning:
      "The replacement satisfies the frozen contract and preserves every decision outside its scope.",
  },
  contract_failed: {
    label: "Contract failed",
    tone: "violated",
    exitCode: null,
    meaning: "The replacement does not satisfy the frozen contract.",
  },
  out_of_scope_regression: {
    label: "Out-of-scope regression",
    tone: "violated",
    exitCode: 3,
    meaning:
      "The replacement satisfies the contract but changes a decision outside the frozen scope.",
  },
};

export const ASSURANCE: Record<AssuranceStatus, { label: string; tone: Tone; meaning: string }> = {
  within_profile: {
    label: "Within profile",
    tone: "proved",
    meaning: "Every construct in this config is modeled exactly.",
  },
  conservative: {
    label: "Conservative",
    tone: "vacuous",
    meaning: "Some constructs are over-approximated. This can over-report, but never creates a false proof.",
  },
  unsupported: {
    label: "Unsupported",
    tone: "unknown",
    meaning: "The config contains a construct outside the profile, so the outcome is unknown.",
  },
};

export const COMPARE_MODE_INFO = {
  decision: {
    label: "Security decision",
    short: "Decision",
    description: "Every modeled request gets the same Allow or Deny.",
  },
  "route-service": {
    label: "Route & service",
    short: "Route & service",
    description: "Same decision and the same selected route and service. Needs unique route names.",
  },
  "service-target": {
    label: "Service target",
    short: "Service target",
    description: "Additionally preserves the service's protocol, host, port and base path.",
  },
} as const;

const ACRONYMS: Record<string, string> = {
  api: "API",
  ip: "IP",
  sni: "SNI",
  jwt: "JWT",
  graphql: "GraphQL",
};

export function sentence(text: string) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function humanize(id: string) {
  return sentence(
    id
      .split("-")
      .map((word) => ACRONYMS[word] ?? word)
      .join(" "),
  );
}
