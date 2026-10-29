import type { CompareReport, EvidenceManifest, RepairReport, VerifyReport } from "./contract";

export const PROPERTY_IDS = [
  "no-anonymous-access",
  "rate-limit-on-public",
  "no-shadowed-routes",
  "admin-api-not-reachable",
  "authenticated-access",
  "network-restricted-access",
] as const;

export type PropertyId = (typeof PROPERTY_IDS)[number];

export const COMPARE_MODES = ["decision", "route-service", "service-target", "upstream-uri"] as const;
export type CompareMode = (typeof COMPARE_MODES)[number];

export interface PropertySpec {
  mode: "property";
  property: PropertyId;
  pathPrefix?: string;
  method?: string;
  host?: string;
  trustedCidr?: string;
}

export interface ContractSpec {
  mode: "contract";
  contract: string;
}

export type Spec = PropertySpec | ContractSpec;

export interface VerifyRequest {
  config: string;
  spec: Spec;
}

export interface CompareRequest {
  before: string;
  after: string;
  mode: CompareMode;
  contract?: string;
}

/**
 * Why no verdict was produced. `protocol` means the engine ran but its output was
 * rejected (schema mismatch, exit code disagreeing with the result, truncated or
 * timed-out output). None of these stages is ever a verification outcome.
 */
export type EngineErrorStage = "parse" | "usage" | "engine" | "input" | "protocol" | "busy" | "cancelled";

export interface EngineFailure {
  ok: false;
  stage: EngineErrorStage;
  message: string;
  exitCode: number | null;
  command?: string;
}

/** Which verifier produced a result, as far as the web server can establish it. */
export interface EngineIdentity {
  source: EngineStatus["source"];
  label: string;
  /** SHA-256 of the engine executable, or null when it runs behind a wrapper. */
  executableSha256: string | null;
  /** `z3 -version` output as seen by the web server, or null when unknown. */
  solverVersion: string | null;
}

export interface RunProvenance {
  /** SHA-256 of each input document exactly as passed to the engine. */
  inputs: Record<string, string>;
  engine: EngineIdentity;
  /** The engine's own evidence manifest; present for frozen-contract verification. */
  evidence: EvidenceManifest | null;
}

export interface EngineSuccess<T> {
  ok: true;
  exitCode: number;
  report: T;
  durationMs: number;
  command: string;
  provenance: RunProvenance;
}

export type VerifyResponse = EngineSuccess<VerifyReport> | EngineFailure;
export type CompareResponse = EngineSuccess<CompareReport | RepairReport> | EngineFailure;

export interface EngineStatus {
  available: boolean;
  source: "binary" | "build" | "dune" | "script" | "none";
  label: string;
  profile: string | null;
  solver: { available: boolean; version: string | null };
  message: string | null;
}

export interface Sample {
  id: string;
  label: string;
  group: string;
  content: string;
}
