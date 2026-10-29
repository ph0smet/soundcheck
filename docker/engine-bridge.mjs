#!/usr/bin/env node
// Engine bridge for live dev: stands in for the soundcheck binary and runs each
// command in the long-lived engine container started by `./start.sh --dev`.
//
// The web app writes its inputs under SOUNDCHECK_WORKDIR, which is bind-mounted
// at /work/jobs, so file arguments are rewritten to their container paths.
// Output and exit codes pass straight through.
//
// Capacity: each job runs through soundcheck-slot (docker/engine-slot.sh), which
// holds one of SOUNDCHECK_MAX_CONCURRENCY slots inside the container for as long
// as the job really runs. Ending this bridge only ends the docker client, so the
// web server's own queue cannot be what limits concurrent solver jobs; the slots
// are. On cancellation the bridge also signals the container-side job, so its
// slot frees promptly when this process gets the chance to (a forced kill, as on
// Windows, skips that, and the slot then frees when the job ends or times out).

import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import path from "node:path";

const container = process.env.SOUNDCHECK_ENGINE_CONTAINER ?? "soundcheck-engine";
const workdir = process.env.SOUNDCHECK_WORKDIR;
const MOUNT = "/work/jobs";

function positiveInt(raw, fallback) {
  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function toContainer(arg) {
  if (!workdir) return arg;
  const relative = path.relative(workdir, arg);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return arg;
  return `${MOUNT}/${relative.split(path.sep).join("/")}`;
}

// Bounded inside the container as well: the web adapter's deadline plus a second.
const limit = `${Math.ceil(positiveInt(process.env.SOUNDCHECK_TIMEOUT_MS, 60_000) / 1000) + 1}s`;
const slots = String(positiveInt(process.env.SOUNDCHECK_MAX_CONCURRENCY, 4));
const job = randomUUID();

const args = process.argv.slice(2).map(toContainer);
const child = spawn("docker", ["exec", container, "soundcheck-slot", slots, job, limit, "--", "soundcheck", ...args], {
  stdio: ["ignore", "inherit", "pipe"],
  windowsHide: true,
});

let cancelled = false;
function cancel(signal) {
  if (cancelled) return;
  cancelled = true;
  // Stop the job where it runs; killing the docker client alone would leave it.
  spawnSync(
    "docker",
    ["exec", container, "sh", "-c", 'p="$(cat "/tmp/soundcheck-slots/job-$1.pid" 2>/dev/null)" && kill -TERM "$p"', "sh", job],
    { stdio: "ignore", windowsHide: true, timeout: 5_000 },
  );
  child.kill(signal);
}
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => cancel(signal));
}

let stderr = "";
child.stderr.on("data", (chunk) => {
  stderr += chunk;
});

child.on("error", (error) => {
  process.stderr.write(`engine bridge: could not run docker: ${error.message}\n`);
  process.exit(125);
});

child.on("close", (code) => {
  // Docker's own failures must not look like engine exit codes (1 = parse error).
  if (/No such container|is not running|Cannot connect to the Docker daemon|error during connect/i.test(stderr)) {
    process.stderr.write(
      `engine bridge: the engine container "${container}" is not running. Start it with ./start.sh --dev\n`,
    );
    process.exit(125);
  }
  if (/soundcheck-slot: not found|executable file not found/i.test(stderr)) {
    process.stderr.write(
      `engine bridge: the engine container "${container}" is from an older image. Rerun ./start.sh --dev to rebuild it.\n`,
    );
    process.exit(125);
  }
  process.stderr.write(stderr);
  process.exit(code ?? 125);
});
