import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterAll, describe, expect, it } from "vitest";

// The engine module reads SOUNDCHECK_BIN when it detects the engine, so point it
// at a scratch "executable" before importing.
const dir = mkdtempSync(path.join(os.tmpdir(), "soundcheck-identity-"));
const bin = path.join(dir, "soundcheck");
writeFileSync(bin, "first build");
process.env.SOUNDCHECK_BIN = bin;
const { engineIdentity } = await import("../engine");

const sha = (text: string) => createHash("sha256").update(text).digest("hex");

afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("engine identity", () => {
  it("reports the executable's current hash after it is rebuilt in place (review repro)", async () => {
    expect((await engineIdentity())?.executableSha256).toBe(sha("first build"));
    // Same path, new contents, as `dune build` or a reinstall would leave it.
    writeFileSync(bin, "second build, different bytes");
    expect((await engineIdentity())?.executableSha256).toBe(sha("second build, different bytes"));
  });

  it("does not rehash an unchanged executable", async () => {
    const first = await engineIdentity();
    expect(await engineIdentity()).toBe(first);
  });
});
