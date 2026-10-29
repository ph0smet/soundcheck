// Decides whether one engine run produced a result the web adapter may show.
//
// This is the trust boundary between the CLI and everything the UI renders. A
// run is accepted only if every independent signal agrees: the process exited
// normally within its limits, the exit code is one the command defines, stdout
// is exactly one document matching the versioned schema, the exit code encodes
// the same verdict as the document, and the document answers the question that
// was asked. Anything else is a failure, never a verdict.

import { createHash } from "node:crypto";

import type { EngineFailure } from "@/lib/api";
import {
  compareReport,
  repairReport,
  type EvidenceManifest,
  type CompareReport,
  type RepairReport,
  type Verdict,
  type VerifyReport,
  verifyReport,
} from "@/lib/contract";
import { parseJson, SchemaError, type Validator } from "@/lib/schema";

import type { RunResult } from "./engine";

/** cli/main.ml: 0 proved, 3 violated, 4 unknown, 5 vacuous, 6 inconsistent. */
export const VERIFY_EXIT: Record<Verdict, number> = {
  proved: 0,
  violated: 3,
  unknown: 4,
  vacuous: 5,
  inconsistent: 6,
};

export function compareExit(report: CompareReport): number {
  return { equivalent: 0, different: 3, unknown: 4 }[report.result];
}

export function repairExit(report: RepairReport): number {
  switch (report.result) {
    case "valid_repair":
      return 0;
    case "out_of_scope_regression":
      return 3;
    case "unknown":
      return 4;
    case "contract_failed":
      return VERIFY_EXIT[report.contract_result.result];
  }
}

export type Accepted<T> = { ok: true; report: T; exitCode: number } | EngineFailure;

interface Expectation<T> {
  validate: Validator<T>;
  /** Exit codes that carry a report on stdout. */
  verdictExits: readonly number[];
  /** The exit code the engine must have used for this report. */
  exitFor: (report: T) => number;
  /** Checks that the report answers the request; returns a problem or null. */
  answers?: (report: T) => string | null;
}

function fail(stage: EngineFailure["stage"], command: string, exitCode: number | null, message: string): EngineFailure {
  return { ok: false, stage, exitCode, command, message };
}

export function accept<T>(result: RunResult, command: string, expect: Expectation<T>): Accepted<T> {
  if (result.aborted) {
    return fail("cancelled", command, null, "The run was cancelled. Nothing was verified.");
  }
  if (result.timedOut) {
    return fail("engine", command, null, "The engine did not finish within the time limit. Nothing was verified.");
  }
  if (result.outputExceeded) {
    return fail("protocol", command, null, "The engine produced more output than allowed, so it was stopped. Nothing was verified.");
  }
  if (result.exitCode === null) {
    return fail("engine", command, null, `The engine was terminated${result.signal ? ` by ${result.signal}` : ""}. Nothing was verified.`);
  }
  const detail = result.stderr.trim() || result.stdout.trim();
  if (result.exitCode === 1) {
    return fail("parse", command, 1, detail || "The engine reported an input or verification error.");
  }
  if (result.exitCode === 2) {
    return fail("usage", command, 2, detail || "The engine rejected the command line.");
  }
  if (!expect.verdictExits.includes(result.exitCode)) {
    return fail("protocol", command, result.exitCode, `The engine exited with unexpected code ${result.exitCode}.${detail ? `\n${detail}` : ""}`);
  }

  let report: T;
  try {
    report = parseJson(result.stdout, expect.validate);
  } catch (error) {
    const why = error instanceof SchemaError ? error.message : String(error);
    return fail("protocol", command, result.exitCode, `The engine's output did not match the expected schema (${why}).`);
  }

  const expected = expect.exitFor(report);
  if (expected !== result.exitCode) {
    return fail(
      "protocol",
      command,
      result.exitCode,
      `The engine's exit code ${result.exitCode} disagrees with its reported result (expected ${expected}).`,
    );
  }
  const problem = expect.answers?.(report);
  if (problem) {
    return fail("protocol", command, result.exitCode, `The engine's report does not answer this request: ${problem}.`);
  }
  return { ok: true, report, exitCode: result.exitCode };
}

const VERIFY_EXITS = Object.values(VERIFY_EXIT);

export type VerifyQuestion = { mode: "property"; property: string } | { mode: "contract" };

export function acceptVerify(result: RunResult, command: string, question: VerifyQuestion): Accepted<VerifyReport> {
  return accept(result, command, {
    validate: verifyReport,
    verdictExits: VERIFY_EXITS,
    exitFor: (report) => VERIFY_EXIT[report.result],
    answers: (report) => {
      if (question.mode === "contract") {
        return report.frozen_spec === null ? "a frozen-contract run must carry the frozen spec identity" : null;
      }
      if (report.frozen_spec !== null) return "a property run must not carry a frozen spec";
      return report.property === question.property
        ? null
        : `asked for ${question.property}, got ${report.property}`;
    },
  });
}

const COMPARISON_FOR_MODE = {
  decision: { plain: "security_decision", repair: "frozen_scope_preservation" },
  "route-service": { plain: "route_service", repair: "frozen_route_service_preservation" },
  "service-target": { plain: "service_target", repair: "frozen_service_target_preservation" },
  "upstream-uri": { plain: "upstream_uri", repair: "frozen_upstream_uri_preservation" },
} as const;

export function acceptCompare(
  result: RunResult,
  command: string,
  mode: keyof typeof COMPARISON_FOR_MODE,
  withContract: boolean,
): Accepted<CompareReport | RepairReport> {
  const comparison = COMPARISON_FOR_MODE[mode];
  if (withContract) {
    return accept<RepairReport>(result, command, {
      validate: repairReport,
      verdictExits: [0, 3, 4, 5, 6],
      exitFor: repairExit,
      answers: (report) =>
        report.comparison === comparison.repair ? null : `asked for ${comparison.repair}, got ${report.comparison}`,
    });
  }
  return accept<CompareReport>(result, command, {
    validate: compareReport,
    verdictExits: [0, 3, 4],
    exitFor: compareExit,
    answers: (report) =>
      report.comparison === comparison.plain ? null : `asked for ${comparison.plain}, got ${report.comparison}`,
  });
}

const digest = (text: string) => createHash("sha256").update(text).digest("hex");

/**
 * Binds a frozen-contract run's evidence bundle to the output that was accepted:
 * the bundle must hash the exact config bytes sent, the exact report printed on
 * stdout and the contract's canonical identity, and record the same verdict and
 * assurance profile. Returns a problem, or null when everything agrees.
 */
export function checkEvidence(
  manifest: EvidenceManifest,
  run: { config: string; stdout: string; report: VerifyReport },
): string | null {
  if (manifest.config.sha256 !== digest(run.config)) return "the evidence manifest describes a different config";
  if (manifest.result !== run.report.result) {
    return `the evidence manifest records ${manifest.result}, not ${run.report.result}`;
  }
  if (manifest.report.sha256 !== digest(run.stdout)) return "the evidence manifest describes a different report";
  if (!run.report.frozen_spec) return "the report carries no frozen spec to match the evidence against";
  if (manifest.contract.sha256 !== digest(`${run.report.frozen_spec.canonical}\n`)) {
    return "the evidence manifest describes a different contract";
  }
  if (run.report.assurance && manifest.assurance_profile.id !== run.report.assurance.profile) {
    return `the evidence manifest names profile ${manifest.assurance_profile.id}, not ${run.report.assurance.profile}`;
  }
  return null;
}
