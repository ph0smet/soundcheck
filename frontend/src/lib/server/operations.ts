import "server-only";

import { readFile } from "node:fs/promises";
import path from "node:path";

import {
  COMPARE_MODES,
  PROPERTY_IDS,
  type CompareMode,
  type EngineIdentity,
  type CompareRequest,
  type CompareResponse,
  type EngineFailure,
  type PropertySpec,
  type RunProvenance,
  type Spec,
  type VerifyRequest,
  type VerifyResponse,
} from "@/lib/api";
import {
  assuranceProfile,
  evidenceManifest,
  type AssuranceProfile,
  type EvidenceManifest,
  type VerifyReport,
} from "@/lib/contract";
import { parseJson } from "@/lib/schema";
import { shellCommand } from "@/lib/shell";

import { accept, acceptCompare, acceptVerify, checkEvidence } from "./accept";
import {
  EngineAbortedError,
  EngineBusyError,
  engineIdentity,
  EngineUnavailableError,
  execEngine,
  sha256,
  withWorkspace,
} from "./engine";

export const MAX_DOCUMENT_BYTES = 512 * 1024;

class InputError extends Error {}

const PATTERNS = {
  pathPrefix: /^\/[\x21-\x7e]{0,511}$/,
  method: /^[A-Za-z]{1,32}$/,
  host: /^[A-Za-z0-9*][A-Za-z0-9.*-]{0,252}$/,
  trustedCidr: /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/,
} as const;

const FIELD_LABELS = {
  pathPrefix: "Path prefix",
  method: "Method",
  host: "Host",
  trustedCidr: "Trusted CIDR",
} as const;

function document(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new InputError(`${label} is empty.`);
  }
  if (Buffer.byteLength(value, "utf8") > MAX_DOCUMENT_BYTES) {
    throw new InputError(`${label} is larger than 512 KB.`);
  }
  return value;
}

/** Returns an error message when a scope value would be rejected by the engine bridge. */
export function fieldProblem(value: string, key: keyof typeof PATTERNS): string | null {
  return PATTERNS[key].test(value.trim()) ? null : `${FIELD_LABELS[key]} "${value}" is not valid.`;
}

function optionalField(value: unknown, key: keyof typeof PATTERNS): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !PATTERNS[key].test(value.trim())) {
    throw new InputError(`${FIELD_LABELS[key]} "${String(value)}" is not valid.`);
  }
  return value.trim();
}

function parseSpec(raw: unknown): Spec {
  const spec = raw as Record<string, unknown> | null;
  if (!spec || typeof spec !== "object") throw new InputError("Missing specification.");
  if (spec.mode === "contract") {
    return { mode: "contract", contract: document(spec.contract, "Contract") };
  }
  if (spec.mode !== "property") throw new InputError("Unknown specification mode.");
  if (!PROPERTY_IDS.includes(spec.property as PropertySpec["property"])) {
    throw new InputError(`Unknown property "${String(spec.property)}".`);
  }
  const property = spec.property as PropertySpec["property"];
  const parsed: PropertySpec = {
    mode: "property",
    property,
    pathPrefix: optionalField(spec.pathPrefix, "pathPrefix"),
    method: optionalField(spec.method, "method")?.toUpperCase(),
    host: optionalField(spec.host, "host"),
    trustedCidr: optionalField(spec.trustedCidr, "trustedCidr"),
  };
  if (property === "network-restricted-access" && !parsed.trustedCidr) {
    throw new InputError("Network restricted access requires a trusted CIDR.");
  }
  return parsed;
}

function propertyArgs(spec: PropertySpec): string[] {
  const args = ["--property", spec.property];
  const scoped = spec.property === "no-anonymous-access" ||
    spec.property === "authenticated-access" ||
    spec.property === "network-restricted-access";
  const paired = spec.property === "authenticated-access" || spec.property === "network-restricted-access";
  if (scoped && spec.pathPrefix) args.push("--path-prefix", spec.pathPrefix);
  if (paired && spec.method) args.push("--method", spec.method);
  if (paired && spec.host) args.push("--host", spec.host);
  if (
    (spec.property === "admin-api-not-reachable" || spec.property === "network-restricted-access") &&
    spec.trustedCidr
  ) {
    args.push("--trusted-cidr", spec.trustedCidr);
  }
  return args;
}

function display(args: string[]) {
  return shellCommand(["soundcheck", ...args]);
}

function guard<T extends { ok: boolean }>(fn: () => Promise<T>): Promise<T | EngineFailure> {
  return fn().catch((error: unknown): EngineFailure => {
    if (error instanceof InputError) {
      return { ok: false, stage: "input", exitCode: null, message: error.message };
    }
    if (error instanceof EngineBusyError) {
      return { ok: false, stage: "busy", exitCode: null, message: error.message };
    }
    if (error instanceof EngineAbortedError) {
      return { ok: false, stage: "cancelled", exitCode: null, message: error.message };
    }
    if (error instanceof EngineUnavailableError) {
      return { ok: false, stage: "engine", exitCode: null, message: error.message };
    }
    if (error instanceof EngineChangedError) {
      return { ok: false, stage: "protocol", exitCode: null, message: error.message };
    }
    throw error;
  });
}

class EngineChangedError extends Error {}

/**
 * The engine's identity for a run, taken before it started. If the executable or
 * solver changed while it ran, no single identity describes the run, so it is
 * refused rather than attributed to either.
 */
async function provenance(
  before: EngineIdentity | null,
  inputs: Record<string, string>,
  evidence: EvidenceManifest | null,
): Promise<RunProvenance> {
  const engine = await engineIdentity();
  if (!engine || !before) throw new EngineUnavailableError("The engine disappeared while running.");
  if (engine.executableSha256 !== before.executableSha256 || engine.solverVersion !== before.solverVersion) {
    throw new EngineChangedError("The engine or solver was replaced while this run was in progress. Nothing was verified; run it again.");
  }
  return {
    inputs: Object.fromEntries(Object.entries(inputs).map(([name, content]) => [name, sha256(content)])),
    engine,
    evidence,
  };
}

export type ProfileResult = { ok: true; profile: AssuranceProfile } | EngineFailure;

export function loadProfile(signal?: AbortSignal): Promise<ProfileResult> {
  return guard(async () => {
    const args = ["profile", "kong", "--format", "json"];
    const accepted = accept(await execEngine(args, signal), display(args), {
      validate: assuranceProfile,
      verdictExits: [0],
      exitFor: () => 0,
    });
    if (!accepted.ok) return accepted;
    return { ok: true as const, profile: accepted.report };
  });
}

/** Reads a frozen-contract run's evidence bundle and binds it to the accepted output. */
async function readEvidence(
  dir: string,
  run: { config: string; stdout: string; report: VerifyReport },
): Promise<EvidenceManifest | string> {
  let manifest: EvidenceManifest;
  try {
    manifest = parseJson(await readFile(path.join(dir, "manifest.json"), "utf8"), evidenceManifest);
  } catch (error) {
    return `the evidence manifest is missing or invalid (${(error as Error).message})`;
  }
  return checkEvidence(manifest, run) ?? manifest;
}

export function runVerify(body: Partial<VerifyRequest>, signal?: AbortSignal): Promise<VerifyResponse> {
  return guard(async () => {
    const config = document(body.config, "Config");
    const spec = parseSpec(body.spec);
    const files: Record<string, string> = { "config.yaml": config };
    if (spec.mode === "contract") files["contract.yaml"] = spec.contract;

    return withWorkspace(files, async (paths, dir) => {
      const evidenceDir = path.join(dir, "evidence");
      const argv = (file: (name: string) => string) => [
        "verify",
        file("config.yaml"),
        ...(spec.mode === "contract"
          ? ["--contract", file("contract.yaml"), "--evidence-dir", file("evidence")]
          : propertyArgs(spec)),
        "--format",
        "json",
      ];
      const command = display(argv((name) => name));
      const before = await engineIdentity();
      const result = await execEngine(argv((name) => paths[name] ?? evidenceDir), signal);
      const accepted = acceptVerify(
        result,
        command,
        spec.mode === "contract" ? { mode: "contract" } : { mode: "property", property: spec.property },
      );
      if (!accepted.ok) return accepted;

      let evidence: EvidenceManifest | null = null;
      if (spec.mode === "contract") {
        const read = await readEvidence(evidenceDir, { config, stdout: result.stdout, report: accepted.report });
        if (typeof read === "string") {
          return { ok: false as const, stage: "protocol" as const, exitCode: accepted.exitCode, command, message: `Rejected: ${read}.` };
        }
        evidence = read;
      }
      return {
        ok: true as const,
        exitCode: accepted.exitCode,
        report: accepted.report,
        durationMs: result.durationMs,
        command,
        provenance: await provenance(before, files, evidence),
      };
    });
  });
}

export function runCompare(body: Partial<CompareRequest>, signal?: AbortSignal): Promise<CompareResponse> {
  return guard(async () => {
    const before = document(body.before, "Before config");
    const after = document(body.after, "After config");
    const mode = (body.mode ?? "decision") as CompareMode;
    if (!COMPARE_MODES.includes(mode)) throw new InputError(`Unknown comparison mode "${String(mode)}".`);
    const contract = body.contract ? document(body.contract, "Contract") : undefined;

    const files: Record<string, string> = { "before.yaml": before, "after.yaml": after };
    if (contract) files["contract.yaml"] = contract;

    return withWorkspace(files, async (paths) => {
      const argv = (file: (name: string) => string) => [
        "compare",
        file("before.yaml"),
        file("after.yaml"),
        "--mode",
        mode,
        ...(contract ? ["--contract", file("contract.yaml")] : []),
        "--format",
        "json",
      ];
      const command = display(argv((name) => name));
      const before = await engineIdentity();
      const result = await execEngine(argv((name) => paths[name]), signal);
      const accepted = acceptCompare(result, command, mode, contract !== undefined);
      if (!accepted.ok) return accepted;
      return {
        ok: true as const,
        exitCode: accepted.exitCode,
        report: accepted.report,
        durationMs: result.durationMs,
        command,
        provenance: await provenance(before, files, null),
      };
    });
  });
}
