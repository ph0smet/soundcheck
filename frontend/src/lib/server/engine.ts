import "server-only";

import { spawn } from "node:child_process";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { EngineStatus } from "@/lib/api";

export const REPO_ROOT = path.resolve(
  process.env.SOUNDCHECK_REPO ?? path.join(process.cwd(), ".."),
);

const RUN_TIMEOUT_MS = Number(process.env.SOUNDCHECK_TIMEOUT_MS ?? 60_000);
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const MAX_CONCURRENT_RUNS = 4;

interface Engine {
  command: string;
  prefix: string[];
  source: EngineStatus["source"];
  label: string;
}

export interface RunResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export class EngineUnavailableError extends Error {}

async function exists(file: string) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

function capture(command: string, args: string[], timeoutMs: number): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const child = spawn(command, args, {
      cwd: REPO_ROOT,
      shell: false,
      windowsHide: true,
      env: process.env,
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
      if (stdout.length < MAX_OUTPUT_BYTES) stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
      if (stderr.length < MAX_OUTPUT_BYTES) stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        exitCode: code,
        stdout,
        stderr,
        durationMs: Math.round(performance.now() - started),
        timedOut,
      });
    });
  });
}

async function probe(command: string, args: string[]) {
  try {
    const result = await capture(command, args, 5_000);
    return result.exitCode === 0 ? result : null;
  } catch {
    return null;
  }
}

async function detectEngine(): Promise<Engine | null> {
  const configured = process.env.SOUNDCHECK_BIN;
  if (configured) {
    // A .js/.mjs wrapper lets deployments front the engine (e.g. via a container).
    if (/\.m?js$/i.test(configured)) {
      const script = path.resolve(configured);
      return { command: process.execPath, prefix: [script], source: "script", label: path.basename(script) };
    }
    return { command: configured, prefix: [], source: "binary", label: configured };
  }
  const built = path.join(REPO_ROOT, "_build", "default", "cli", "main.exe");
  if (await exists(built)) {
    return { command: built, prefix: [], source: "build", label: "_build/default/cli/main.exe" };
  }
  if (await probe("dune", ["--version"])) {
    return {
      command: "dune",
      prefix: ["exec", "--root", REPO_ROOT, "--no-print-directory", "--", "soundcheck"],
      source: "dune",
      label: "dune exec soundcheck",
    };
  }
  return null;
}

let cachedEngine: { at: number; engine: Promise<Engine | null> } | null = null;

function resolveEngine() {
  if (!cachedEngine || Date.now() - cachedEngine.at > 15_000) {
    cachedEngine = { at: Date.now(), engine: detectEngine() };
  }
  return cachedEngine.engine;
}

let active = 0;
const waiting: (() => void)[] = [];

async function acquire() {
  if (active < MAX_CONCURRENT_RUNS) {
    active++;
    return;
  }
  await new Promise<void>((resolve) => waiting.push(resolve));
}

function release() {
  const next = waiting.shift();
  if (next) next();
  else active--;
}

export async function execEngine(args: string[]): Promise<RunResult> {
  const engine = await resolveEngine();
  if (!engine) {
    throw new EngineUnavailableError(
      "No Soundcheck engine found. Build it with `dune build` in the repository root, or set SOUNDCHECK_BIN.",
    );
  }
  await acquire();
  try {
    return await capture(engine.command, [...engine.prefix, ...args], RUN_TIMEOUT_MS);
  } catch (error) {
    throw new EngineUnavailableError(
      `Could not start the engine (${engine.label}): ${(error as Error).message}`,
    );
  } finally {
    release();
  }
}

/**
 * Writes inputs to a private temp directory for the lifetime of `fn`. The root is
 * SOUNDCHECK_WORKDIR when set, so a containerized engine can see it via a mount.
 */
export async function withWorkspace<T>(
  files: Record<string, string>,
  fn: (paths: Record<string, string>) => Promise<T>,
): Promise<T> {
  const root = process.env.SOUNDCHECK_WORKDIR ?? os.tmpdir();
  await mkdir(root, { recursive: true });
  const dir = await mkdtemp(path.join(root, "soundcheck-web-"));
  try {
    const paths: Record<string, string> = {};
    for (const [name, content] of Object.entries(files)) {
      const file = path.join(dir, name);
      await writeFile(file, content, "utf8");
      paths[name] = file;
    }
    return await fn(paths);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** A wrapper script may run the engine elsewhere, so ask it to solve something real. */
async function solverWorksThroughEngine() {
  try {
    return await withWorkspace({ "probe.yaml": "services: []\n" }, async (paths) => {
      const result = await execEngine(["verify", paths["probe.yaml"], "--format", "json"]);
      return result.exitCode === 0;
    });
  } catch {
    return false;
  }
}

async function solverStatusFor(engine: Engine | null): Promise<EngineStatus["solver"]> {
  if (engine?.source === "script") {
    return { available: await solverWorksThroughEngine(), version: null };
  }
  const solver = await probe("z3", ["--version"]);
  return {
    available: solver !== null,
    version: solver ? solver.stdout.trim().replace(/^Z3 version\s*/i, "") : null,
  };
}

export async function engineStatus(): Promise<EngineStatus> {
  const engine = await resolveEngine();
  const solverStatus = await solverStatusFor(engine);
  if (!engine) {
    return {
      available: false,
      source: "none",
      label: "Not found",
      profile: null,
      solver: solverStatus,
      message: "Build the engine with `dune build` in the repository root, or set SOUNDCHECK_BIN.",
    };
  }
  try {
    const result = await execEngine(["profile", "kong", "--format", "json"]);
    const profile = result.exitCode === 0 ? (JSON.parse(result.stdout) as { id: string }) : null;
    return {
      available: profile !== null,
      source: engine.source,
      label: engine.label,
      profile: profile?.id ?? null,
      solver: solverStatus,
      message: profile
        ? solverStatus.available
          ? null
          : engine.source === "script"
            ? "The engine wrapper could not complete a verification. Is the engine container running?"
            : "The z3 binary is not on PATH, so verification and comparison will fail."
        : result.stderr.trim() || "The engine did not return a profile.",
    };
  } catch (error) {
    return {
      available: false,
      source: engine.source,
      label: engine.label,
      profile: null,
      solver: solverStatus,
      message: (error as Error).message,
    };
  }
}
