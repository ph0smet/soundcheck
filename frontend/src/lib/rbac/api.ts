import type { EngineFailure, EngineIdentity } from "../api";
import type { RbacProfile, RbacReport } from "./contract";

export const MAX_RBAC_DOCUMENT_BYTES = 512 * 1024;
export const RBAC_MODES = ["verify", "repair", "change", "sequence"] as const;
export type RbacMode = (typeof RBAC_MODES)[number];
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export interface RbacReviewRequest { mode: RbacMode; contract: string; baseline?: string }
export interface RbacReview {
  mode: RbacMode;
  contractSha256: string;
  baselineSha256: string | null;
  reviewText: string;
  profile: RbacProfile;
  accessProfile: RbacProfile;
}
export type RbacReviewResponse = { ok: true; review: RbacReview } | EngineFailure;
export interface RbacRunRequest extends RbacReviewRequest {
  candidate: string;
  reviewed: Pick<RbacReview, "contractSha256" | "baselineSha256">;
}
export interface RbacEvidenceArchive {
  filename: string;
  mediaType: "application/zip";
  base64: string;
  sha256: string;
  bytes: number;
  fileCount: number;
}
export interface RbacRunSuccess {
  ok: true;
  mode: RbacMode;
  report: RbacReport;
  profile: RbacProfile;
  accessProfile: RbacProfile;
  exitCode: number;
  durationMs: number;
  command: string;
  provenance: { inputs: Record<string, string>; engine: EngineIdentity; evidence: JsonValue };
  evidenceArchive: RbacEvidenceArchive;
}
export type RbacRunResponse = RbacRunSuccess | EngineFailure;
export interface RbacExample extends RbacReviewRequest { id: string; label: string; description: string; candidate: string }
