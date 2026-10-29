import { describe, expect, it } from "vitest";

import { acceptVerify } from "../accept";
import { capture, EngineAbortedError, EngineBusyError, RunQueue } from "../engine";

// Each fake engine is a Node one-liner, so the tests run anywhere Node does.
const node = process.execPath;
const PROVED = JSON.stringify({
  result: "proved",
  schema_version: 9,
  property: "no-anonymous-access",
  assurance: null,
  frozen_spec: null,
  clause: null,
  counterexample: null,
});

describe("capture", () => {
  it("returns stdout and the exit code of a normal run", async () => {
    const result = await capture(node, ["-e", `process.stdout.write(${JSON.stringify(PROVED)})`], { timeoutMs: 10_000 });
    expect(result.exitCode).toBe(0);
    expect(result.timedOut).toBe(false);
    expect(acceptVerify(result, "x", { mode: "property", property: "no-anonymous-access" }).ok).toBe(true);
  });

  it("kills an engine that prints a proof and then hangs, and the proof is rejected", async () => {
    const script = `process.stdout.write(${JSON.stringify(PROVED)}); setInterval(() => {}, 1000);`;
    const result = await capture(node, ["-e", script], { timeoutMs: 500, killGraceMs: 500 });
    expect(result.timedOut).toBe(true);
    expect(result.stdout).toContain('"proved"');
    const accepted = acceptVerify(result, "x", { mode: "property", property: "no-anonymous-access" });
    expect(accepted.ok).toBe(false);
  });

  it("escalates to a hard kill when the engine ignores SIGTERM", async () => {
    const script = `process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);`;
    const started = performance.now();
    const result = await capture(node, ["-e", script], { timeoutMs: 300, killGraceMs: 300 });
    expect(result.timedOut).toBe(true);
    expect(performance.now() - started).toBeLessThan(10_000);
  });

  it("stops a run whose output exceeds the cap and flags it", async () => {
    const script = `const s = "x".repeat(65536); const w = () => process.stdout.write(s, w); w();`;
    const result = await capture(node, ["-e", script], { timeoutMs: 10_000, maxOutputBytes: 256 * 1024 });
    expect(result.outputExceeded).toBe(true);
    expect(result.stdout.length).toBeLessThanOrEqual(256 * 1024);
  });

  it("kills the run when the caller aborts", async () => {
    const controller = new AbortController();
    const pending = capture(node, ["-e", "setInterval(() => {}, 1000)"], {
      timeoutMs: 30_000,
      killGraceMs: 300,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 200);
    const result = await pending;
    expect(result.aborted).toBe(true);
    expect(result.timedOut).toBe(false);
  });

  it("refuses to start an already-aborted run", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(capture(node, ["-e", ""], { timeoutMs: 1000, signal: controller.signal })).rejects.toBeInstanceOf(
      EngineAbortedError,
    );
  });
});

describe("RunQueue", () => {
  it("refuses work beyond the queue bound instead of queueing it", async () => {
    const queue = new RunQueue(1, 1);
    await queue.acquire();
    const waiting = queue.acquire();
    await expect(queue.acquire()).rejects.toBeInstanceOf(EngineBusyError);
    queue.release();
    await waiting;
    queue.release();
  });

  it("drops a queued run when its caller aborts", async () => {
    const queue = new RunQueue(1, 4);
    await queue.acquire();
    const controller = new AbortController();
    const waiting = queue.acquire(controller.signal);
    expect(queue.pending).toBe(1);
    controller.abort();
    await expect(waiting).rejects.toBeInstanceOf(EngineAbortedError);
    expect(queue.pending).toBe(0);
    queue.release();
    // The slot is free again.
    await queue.acquire();
    queue.release();
  });

  it("hands a released slot to the next waiter", async () => {
    const queue = new RunQueue(1, 4);
    await queue.acquire();
    let granted = false;
    const waiting = queue.acquire().then(() => {
      granted = true;
    });
    expect(granted).toBe(false);
    queue.release();
    await waiting;
    expect(granted).toBe(true);
    queue.release();
  });
});

describe("capture with orphaned output pipes", () => {
  it("still ends when a wrapper exits but its child keeps the pipes open", async () => {
    // The wrapper starts a child that inherits stdout/stderr, then exits at once.
    // The child exits on its own after 15 s so it never outlives the test run.
    const grandchild = "setTimeout(() => process.exit(0), 15000)";
    const wrapper = `require("child_process").spawn(process.execPath, ["-e", ${JSON.stringify(grandchild)}], { stdio: "inherit" }); process.exit(0);`;
    const started = performance.now();
    const result = await capture(node, ["-e", wrapper], { timeoutMs: 300, killGraceMs: 300 });
    expect(performance.now() - started).toBeLessThan(10_000);
    expect(acceptVerify(result, "x", { mode: "property", property: "no-anonymous-access" }).ok).toBe(false);
  });
});
