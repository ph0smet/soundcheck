import "server-only";

import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { EngineIdentity, EngineStatus } from "@/lib/api";
import { assuranceProfile } from "@/lib/contract";
import { parseJson } from "@/lib/schema";

export const REPO_ROOT = path.resolve(
  process.env.SOUNDCHECK_REPO ?? path.join(process.cwd(), ".."),
);

function positiveInt(raw: string | undefined, fallback: number) {
  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

export const LIMITS = {
  runTimeoutMs: positiveInt(process.env.SOUNDCHECK_TIMEOUT_MS, 60_000),
  /** After SIGTERM, how long a run gets before it is killed outright. */
  killGraceMs: 2_000,
  maxOutputBytes: 8 * 1024 * 1024,
  maxConcurrentRuns: positiveInt(process.env.SOUNDCHECK_MAX_CONCURRENCY, 4),
  /** Runs allowed to wait for a slot. Beyond this, requests are refused rather than queued. */
  maxQueuedRuns: positiveInt(process.env.SOUNDCHECK_MAX_QUEUE, 32),
};

interface Engine {
  command: string;
  prefix: string[];
  source: EngineStatus["source"];
  label: string;
  /** The executable whose digest identifies the engine, when it is a local file. */
  executable: string | null;
}

export interface RunResult {
  exitCode: number | null;
  /** Set when the process was ended by a signal rather than exiting. */
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  /** stdout or stderr exceeded the cap; the run was killed and its output is incomplete. */
  outputExceeded: boolean;
  /** The caller cancelled the run (for example, the HTTP client disconnected). */
  aborted: boolean;
}

export class EngineUnavailableError extends Error {}
export class EngineBusyError extends Error {}
export class EngineAbortedError extends Error {}

async function exists(file: string) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * Ends the child and everything it started. Wrappers (dune exec, the Docker
 * bridge) spawn grandchildren, so killing only the direct child is not enough.
 */
function killTree(child: ChildProcess, signal: NodeJS.Signals) {
  if (child.pid === undefined) return;
  if (process.platform === "win32") {
    // taskkill needs the parent to walk the tree, so there is nothing to do once it is gone.
    if (child.exitCode !== null || child.signalCode !== null) return;
    // Windows has no process groups or SIGTERM; terminate the whole tree.
    spawn("taskkill", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" }).on(
      "error",
      () => child.kill(),
    );
    return;
  }
  // Signal the group even if the direct child already exited: a wrapper can exit
  // while a grandchild it started still runs and holds the output pipes.
  try {
    process.kill(-child.pid, signal);
  } catch {
    if (child.exitCode === null && child.signalCode === null) child.kill(signal);
  }
}

export interface CaptureOptions {
  timeoutMs: number;
  signal?: AbortSignal;
  maxOutputBytes?: number;
  killGraceMs?: number;
  cwd?: string;
}

export function capture(command: string, args: string[], options: CaptureOptions): Promise<RunResult> {
  const maxOutput = options.maxOutputBytes ?? LIMITS.maxOutputBytes;
  const grace = options.killGraceMs ?? LIMITS.killGraceMs;
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(new EngineAbortedError("The run was cancelled before it started."));
      return;
    }
    const started = performance.now();
    const child = spawn(command, args, {
      cwd: options.cwd ?? REPO_ROOT,
      shell: false,
      windowsHide: true,
      // Own process group on POSIX so the whole tree can be signalled.
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let timedOut = false;
    let outputExceeded = false;
    let aborted = false;
    let killTimer: NodeJS.Timeout | undefined;
    let abandonTimer: NodeJS.Timeout | undefined;

    // SIGTERM, then SIGKILL after the grace period. If the pipes are still open a
    // grace period after that (something outside the tree holds them), stop
    // waiting for them so the run, and its queue slot, always ends.
    const stop = () => {
      killTree(child, "SIGTERM");
      killTimer ??= setTimeout(() => {
        killTree(child, "SIGKILL");
        abandonTimer = setTimeout(() => {
          child.stdout?.destroy();
          child.stderr?.destroy();
        }, grace);
      }, grace);
    };
    const timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, options.timeoutMs);
    const onAbort = () => {
      aborted = true;
      stop();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });

    const collect = (into: Buffer[]) => (chunk: Buffer) => {
      if (outputExceeded) return;
      bytes += chunk.length;
      if (bytes > maxOutput) {
        outputExceeded = true;
        stop();
        return;
      }
      into.push(chunk);
    };
    child.stdout!.on("data", collect(stdout));
    child.stderr!.on("data", collect(stderr));

    const cleanup = () => {
      clearTimeout(timer);
      clearTimeout(killTimer);
      clearTimeout(abandonTimer);
      options.signal?.removeEventListener("abort", onAbort);
    };
    child.on("error", (error) => {
      cleanup();
      reject(error);
    });
    child.on("close", (code, signal) => {
      cleanup();
      resolve({
        exitCode: code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        durationMs: Math.round(performance.now() - started),
        timedOut,
        outputExceeded,
        aborted,
      });
    });
  });
}

async function probe(command: string, args: string[]) {
  try {
    const result = await capture(command, args, { timeoutMs: 5_000 });
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
      return {
        command: process.execPath,
        prefix: [script],
        source: "script",
        label: path.basename(script),
        executable: null,
      };
    }
    return { command: configured, prefix: [], source: "binary", label: configured, executable: configured };
  }
  const built = path.join(REPO_ROOT, "_build", "default", "cli", "main.exe");
  if (await exists(built)) {
    return { command: built, prefix: [], source: "build", label: "_build/default/cli/main.exe", executable: built };
  }
  if (await probe("dune", ["--version"])) {
    return {
      command: "dune",
      prefix: ["exec", "--root", REPO_ROOT, "--no-print-directory", "--", "soundcheck"],
      source: "dune",
      label: "dune exec soundcheck",
      executable: null,
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

/** A counting semaphore with a bounded wait queue whose waiters can be cancelled. */
export class RunQueue {
  private active = 0;
  private readonly waiting: { grant: () => void; fail: (error: Error) => void }[] = [];

  constructor(
    private readonly maxActive: number,
    private readonly maxWaiting: number,
  ) {}

  get pending() {
    return this.waiting.length;
  }

  async acquire(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) throw new EngineAbortedError("The run was cancelled before it started.");
    if (this.active < this.maxActive) {
      this.active++;
      return;
    }
    if (this.waiting.length >= this.maxWaiting) {
      throw new EngineBusyError("The verifier is at capacity. Try again shortly.");
    }
    await new Promise<void>((resolve, reject) => {
      const entry = {
        grant: () => {
          signal?.removeEventListener("abort", onAbort);
          resolve();
        },
        fail: reject,
      };
      const onAbort = () => {
        const index = this.waiting.indexOf(entry);
        if (index >= 0) this.waiting.splice(index, 1);
        reject(new EngineAbortedError("The run was cancelled while queued."));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      this.waiting.push(entry);
    });
  }

  release() {
    const next = this.waiting.shift();
    // Hand the slot straight to the next waiter; otherwise free it.
    if (next) next.grant();
    else this.active--;
  }
}

const queue = new RunQueue(LIMITS.maxConcurrentRuns, LIMITS.maxQueuedRuns);

export async function execEngine(args: string[], signal?: AbortSignal): Promise<RunResult> {
  const engine = await resolveEngine();
  if (!engine) {
    throw new EngineUnavailableError(
      "No Soundcheck engine found. Build it with `dune build` in the repository root, or set SOUNDCHECK_BIN.",
    );
  }
  await queue.acquire(signal);
  try {
    return await capture(engine.command, [...engine.prefix, ...args], { timeoutMs: LIMITS.runTimeoutMs, signal });
  } catch (error) {
    if (error instanceof EngineAbortedError) throw error;
    throw new EngineUnavailableError(`Could not start the engine (${engine.label}): ${(error as Error).message}`);
  } finally {
    queue.release();
  }
}

export function sha256(content: string | Uint8Array) {
  return createHash("sha256").update(content).digest("hex");
}

function fileSha256(file: string): Promise<string | null> {
  return new Promise((resolve) => {
    const hash = createHash("sha256");
    createReadStream(file)
      .on("data", (chunk) => hash.update(chunk))
      .on("end", () => resolve(hash.digest("hex")))
      .on("error", () => resolve(null));
  });
}

/**
 * Identifies a file's current contents cheaply: rebuilding or replacing a binary
 * at the same path changes at least one of these. Null when the file is absent.
 */
async function fingerprint(file: string | null): Promise<string | null> {
  if (!file) return null;
  try {
    const info = await stat(file, { bigint: true });
    return [info.dev, info.ino, info.size, info.mtimeNs, info.ctimeNs].join(":");
  } catch {
    return null;
  }
}

/** The z3 executable the engine will find on PATH, as the OS would resolve it. */
async function findOnPath(command: string): Promise<string | null> {
  const names = process.platform === "win32" ? [`${command}.exe`, `${command}.cmd`, command] : [command];
  for (const dir of (process.env.PATH ?? "").split(path.delimiter).filter(Boolean)) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (await exists(candidate)) return candidate;
    }
  }
  return null;
}

let cachedIdentity: { key: string; identity: Promise<EngineIdentity> } | null = null;

/**
 * Identifies the engine for provenance. The cache is keyed by the engine choice
 * and by fingerprints of the engine executable and z3, so a rebuild in place or
 * a solver upgrade is noticed on the next call instead of reporting stale hashes.
 */
export async function engineIdentity(): Promise<EngineIdentity | null> {
  const engine = await resolveEngine();
  if (!engine) return null;
  const solver = engine.source === "script" ? null : await findOnPath("z3");
  const key = JSON.stringify([
    engine.command,
    engine.label,
    await fingerprint(engine.executable),
    solver,
    await fingerprint(solver),
  ]);
  if (!cachedIdentity || cachedIdentity.key !== key) {
    cachedIdentity = {
      key,
      identity: (async () => ({
        source: engine.source,
        label: engine.label,
        executableSha256: engine.executable ? await fileSha256(engine.executable) : null,
        solverVersion: engine.source === "script" ? null : await localSolverVersion(),
      }))(),
    };
  }
  return cachedIdentity.identity;
}

/**
 * Writes inputs to a private temp directory for the lifetime of `fn`. The root is
 * SOUNDCHECK_WORKDIR when set, so a containerized engine can see it via a mount.
 */
export async function withWorkspace<T>(
  files: Record<string, string>,
  fn: (paths: Record<string, string>, dir: string) => Promise<T>,
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
    return await fn(paths, dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const PROBE_CONFIG = '_format_version: "3.0"\nservices: []\n';

/** A wrapper script may run the engine elsewhere, so ask it to solve something real. */
async function solverWorksThroughEngine() {
  try {
    return await withWorkspace({ "probe.yaml": PROBE_CONFIG }, async (paths) => {
      const result = await execEngine(["verify", paths["probe.yaml"], "--format", "json"]);
      return result.exitCode === 0 && !result.timedOut && !result.outputExceeded;
    });
  } catch {
    return false;
  }
}

async function localSolverVersion() {
  const solver = await probe("z3", ["-version"]);
  return solver ? solver.stdout.trim() : null;
}

async function solverStatusFor(engine: Engine | null): Promise<EngineStatus["solver"]> {
  if (engine?.source === "script") {
    return { available: await solverWorksThroughEngine(), version: null };
  }
  const version = await localSolverVersion();
  return { available: version !== null, version: version?.replace(/^Z3 version\s*/i, "") ?? null };
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
    let profile: string | null = null;
    let problem: string | null = null;
    if (result.exitCode === 0 && !result.timedOut && !result.outputExceeded) {
      try {
        profile = parseJson(result.stdout, assuranceProfile).id;
      } catch (error) {
        problem = `The engine's profile did not match the expected schema: ${(error as Error).message}`;
      }
    }
    return {
      available: profile !== null,
      source: engine.source,
      label: engine.label,
      profile,
      solver: solverStatus,
      message: profile
        ? solverStatus.available
          ? null
          : engine.source === "script"
            ? "The engine wrapper could not complete a verification. Is the engine container running?"
            : "The z3 binary is not on PATH, so verification and comparison will fail."
        : problem ?? (result.stderr.trim() || "The engine did not return a profile."),
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
