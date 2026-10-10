import "server-only";

import {
  COMPARE_MODES,
  PROPERTY_IDS,
  type CompareRequest,
  type CompareResponse,
  type EngineFailure,
  type PropertySpec,
  type Spec,
  type VerifyRequest,
  type VerifyResponse,
} from "@/lib/api";
import type { AssuranceProfile, CompareReport, RepairReport, VerifyReport } from "@/lib/contract";

import { EngineUnavailableError, execEngine, withWorkspace, type RunResult } from "./engine";

const MAX_DOCUMENT_BYTES = 512 * 1024;

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
  return ["soundcheck", ...args]
    .map((arg) => (/^[\w./:@=-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`))
    .join(" ");
}

function failure(result: RunResult, command: string): EngineFailure {
  if (result.timedOut) {
    return {
      ok: false,
      stage: "engine",
      exitCode: null,
      command,
      message: "The engine did not finish within the time limit.",
    };
  }
  const stage = result.exitCode === 1 ? "parse" : result.exitCode === 2 ? "usage" : "engine";
  return {
    ok: false,
    stage,
    exitCode: result.exitCode,
    command,
    message: result.stderr.trim() || result.stdout.trim() || `The engine exited with code ${result.exitCode}.`,
  };
}

function parseReport<T>(result: RunResult): T | null {
  const text = result.stdout.trim();
  if (!text.startsWith("{")) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

function guard<T extends { ok: boolean }>(fn: () => Promise<T>): Promise<T | EngineFailure> {
  return fn().catch((error: unknown): EngineFailure => {
    if (error instanceof InputError) {
      return { ok: false, stage: "input", exitCode: null, message: error.message };
    }
    if (error instanceof EngineUnavailableError) {
      return { ok: false, stage: "engine", exitCode: null, message: error.message };
    }
    throw error;
  });
}

export type ProfileResult = { ok: true; profile: AssuranceProfile } | EngineFailure;

export function loadProfile(): Promise<ProfileResult> {
  return guard(async () => {
    const command = display(["profile", "kong", "--format", "json"]);
    const result = await execEngine(["profile", "kong", "--format", "json"]);
    const profile = result.exitCode === 0 ? parseReport<AssuranceProfile>(result) : null;
    if (!profile) return failure(result, command);
    return { ok: true as const, profile };
  });
}

export function runVerify(body: Partial<VerifyRequest>): Promise<VerifyResponse> {
  return guard(async () => {
    const config = document(body.config, "Config");
    const spec = parseSpec(body.spec);
    const files: Record<string, string> = { "config.yaml": config };
    if (spec.mode === "contract") files["contract.yaml"] = spec.contract;

    return withWorkspace(files, async (paths) => {
      const argv = (file: (name: string) => string) => [
        "verify",
        file("config.yaml"),
        ...(spec.mode === "contract" ? ["--contract", file("contract.yaml")] : propertyArgs(spec)),
        "--format",
        "json",
      ];
      const command = display(argv((name) => name));
      const result = await execEngine(argv((name) => paths[name]));
      const report = parseReport<VerifyReport>(result);
      if (!report) return failure(result, command);
      return {
        ok: true as const,
        exitCode: result.exitCode ?? -1,
        report,
        durationMs: result.durationMs,
        command,
      };
    });
  });
}

export function runCompare(body: Partial<CompareRequest>): Promise<CompareResponse> {
  return guard(async () => {
    const before = document(body.before, "Before config");
    const after = document(body.after, "After config");
    const mode = body.mode ?? "decision";
    if (!COMPARE_MODES.includes(mode)) throw new InputError(`Unknown comparison mode "${mode}".`);
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
      const result = await execEngine(argv((name) => paths[name]));
      const report = parseReport<CompareReport | RepairReport>(result);
      if (!report) return failure(result, command);
      return {
        ok: true as const,
        exitCode: result.exitCode ?? -1,
        report,
        durationMs: result.durationMs,
        command,
      };
    });
  });
}
