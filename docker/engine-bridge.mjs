#!/usr/bin/env node
// Engine bridge for live dev: stands in for the soundcheck binary and runs each
// command in the long-lived engine container started by `./start.sh --dev`.
//
// The web app writes its inputs under SOUNDCHECK_WORKDIR, which is bind-mounted
// at /work/jobs, so file arguments are rewritten to their container paths.
// Output and exit codes pass straight through.

import { spawn } from "node:child_process";
import path from "node:path";

const container = process.env.SOUNDCHECK_ENGINE_CONTAINER ?? "soundcheck-engine";
const workdir = process.env.SOUNDCHECK_WORKDIR;
const MOUNT = "/work/jobs";

function toContainer(arg) {
  if (!workdir) return arg;
  const relative = path.relative(workdir, arg);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return arg;
  return `${MOUNT}/${relative.split(path.sep).join("/")}`;
}

const args = process.argv.slice(2).map(toContainer);
const child = spawn("docker", ["exec", "-i", container, "soundcheck", ...args], {
  stdio: ["inherit", "inherit", "pipe"],
  windowsHide: true,
});

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
  process.stderr.write(stderr);
  process.exit(code ?? 125);
});
