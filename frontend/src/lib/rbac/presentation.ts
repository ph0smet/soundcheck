import type { VerifyReport } from "../contract";
import type { Tone } from "../domain";
import type { RbacMode } from "./api";
import type { RbacReport, RbacSequenceReport } from "./contract";

export const MODE_LABELS: Record<RbacMode, string> = {
  verify: "Access", repair: "Repair", change: "Single change", sequence: "Migration",
};
export const MODE_DESCRIPTIONS: Record<RbacMode, string> = {
  verify: "Check one complete policy snapshot against frozen access requirements.",
  repair: "Check the candidate requirements and preserve baseline access outside the approved scope.",
  change: "Check one actor-authorized policy operation, final access and preservation.",
  sequence: "Check ordered operations, selected requirements throughout the transition and preservation.",
};

/** Preserve valid input characters; never repair malformed uploaded bytes. */
export function decodeRbacUpload(bytes: ArrayBuffer): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

/** Each request owns an epoch. Cancellation/replacement makes every old completion inert. */
export class RequestEpoch {
  private generation = 0;
  begin(): number { return ++this.generation; }
  invalidate(): void { this.generation++; }
  accepts(generation: number): boolean { return generation === this.generation; }
}

export function contextKey(mode: RbacMode, contract: string, baseline: string): string {
  return JSON.stringify({ mode, contract, baseline: mode === "verify" ? null : baseline });
}

export function runKey(mode: RbacMode, contract: string, baseline: string, candidate: string): string {
  return JSON.stringify({ context: contextKey(mode, contract, baseline), candidate });
}

export function isSequenceReport(report: RbacReport): report is RbacSequenceReport {
  return "kind" in report && report.kind === "kubernetes-rbac-policy-sequence";
}

export function outcome(result: RbacReport["result"], mode: RbacMode): { title: string; tone: Tone; explanation: string } {
  switch (result) {
    case "proved": return { title: mode === "repair" ? "Repair proved" : "Access proved", tone: "proved", explanation: mode === "repair" ? "Frozen access and preservation outside the approved scope passed in the supported model." : "The frozen access requirements hold within the supported model and assumptions." };
    case "valid_change": return { title: "Valid change", tone: "proved", explanation: "Actor authorization, final access and preservation outside scope passed." };
    case "valid_sequence": return { title: "Valid migration", tone: "proved", explanation: "The ordered operations and every required state check passed in the supported model." };
    case "authorization_failed": return { title: "Authorization failed", tone: "violated", explanation: "The frozen actor lacks an RBAC prerequisite for a proposed operation." };
    case "contract_failed": return { title: "Final requirements failed", tone: "violated", explanation: "The final candidate does not satisfy the frozen access requirements." };
    case "invariant_failed": return { title: "Transition requirement failed", tone: "violated", explanation: "A selected invariant failed in the baseline or a resulting state." };
    case "out_of_scope_regression": return { title: "Preservation failed", tone: "violated", explanation: "A modeled decision changes outside the approved scope." };
    case "violated": return { title: "Violated", tone: "violated", explanation: "A validated modeled request breaks an obligation. Inspect its clause and witness below." };
    case "vacuous": return { title: "Vacuous", tone: "vacuous", explanation: "A required request class is empty. This is not a proof of the requirements." };
    case "inconsistent": return { title: "Inconsistent", tone: "inconsistent", explanation: "The frozen requirements demand conflicting decisions for an overlapping request class." };
    case "unknown": return { title: "Unknown", tone: "unknown", explanation: "The engine could not establish a result within its supported semantics or execution limits." };
  }
}

export function witnessDecision(report: VerifyReport): string {
  if (report.clause?.kind === "must_preserve") return "A decision changed outside the approved scope";
  if (report.clause?.kind === "must_allow") return "NoOpinion — required access is missing";
  if (report.clause?.kind === "must_not_grant" || report.clause?.kind === "must_deny") return "Allow — forbidden access is granted";
  return "Modeled obligation violated";
}

export type CheckStatus = VerifyReport["result"] | "authorized" | "not_authorized" | "not_executed" | "not_selected" | "not_applicable";
export const STATUS_LABELS: Record<CheckStatus, string> = {
  proved: "Proved", violated: "Violated", vacuous: "Vacuous", inconsistent: "Inconsistent", unknown: "Unknown",
  authorized: "Authorized", not_authorized: "Not authorized", not_executed: "Not executed", not_selected: "Not selected", not_applicable: "—",
};
export function statusTone(status: CheckStatus): Tone | null {
  switch (status) {
    case "proved": case "authorized": return "proved";
    case "violated": case "not_authorized": return "violated";
    case "unknown": case "vacuous": case "inconsistent": return status;
    default: return null;
  }
}

export interface StateRow {
  state: number;
  operation: string;
  target: string | null;
  authorization: CheckStatus;
  invariant: CheckStatus;
  preservation: CheckStatus;
  failed: boolean;
}

export function sequenceRows(report: RbacSequenceReport): StateRow[] {
  return report.states.map(({ index }) => {
    const step = report.steps.find((item) => item.index === index);
    const invariant = "state_invariants" in report ? report.state_invariants.find((item) => item.state === index) : undefined;
    const preserved = report.intermediate_preservation.find((item) => item.step === index);
    const final = index === report.steps.length;
    const comparison = report.verification?.comparison_report;
    return {
      state: index,
      operation: step?.operation ?? "Original snapshot",
      target: step ? `${step.target.kind} ${step.target.namespace ? `${step.target.namespace}/` : ""}${step.target.name}` : null,
      authorization: index === 0 ? "not_applicable" : step?.authorization ? (step.authorization.allowed ? "authorized" : "not_authorized") : "not_executed",
      invariant: invariant?.status ?? "not_selected",
      preservation: index === 0 ? "not_applicable" : final ? (comparison?.property === "rbac-repair-preservation" ? comparison.result : "not_executed") : preserved?.status ?? "not_executed",
      failed: report.failing_step === index,
    };
  });
}

export function failureLocation(report: RbacSequenceReport): string | null {
  const step = report.failing_step;
  if (step === null) return null;
  if (report.phase === "authorization") return `Operation ${step}, using S${step - 1}`;
  if (report.phase === "preparation") return `Step ${step} preparation`;
  return `State S${step}${step === 0 ? " (baseline)" : ""}`;
}
