import type { CompareReport, RepairReport, VerifyReport } from "./contract";

export const PROPERTY_IDS = [
  "no-anonymous-access",
  "rate-limit-on-public",
  "no-shadowed-routes",
  "admin-api-not-reachable",
  "authenticated-access",
  "network-restricted-access",
] as const;

export type PropertyId = (typeof PROPERTY_IDS)[number];

export const COMPARE_MODES = ["decision", "route-service", "service-target"] as const;
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

export type EngineErrorStage = "parse" | "usage" | "engine" | "input";

export interface EngineFailure {
  ok: false;
  stage: EngineErrorStage;
  message: string;
  exitCode: number | null;
  command?: string;
}

export interface EngineSuccess<T> {
  ok: true;
  exitCode: number;
  report: T;
  durationMs: number;
  command: string;
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
