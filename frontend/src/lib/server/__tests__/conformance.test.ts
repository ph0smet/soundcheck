// Runs the real engine and checks that every output the web adapter consumes is
// accepted by its validators, so schema drift between the CLI and the frontend
// fails CI instead of reaching users. Set SOUNDCHECK_TEST_BIN to the built CLI
// (CI does); without it, and without a local `dune build`, the suite is skipped.

import { existsSync, readdirSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { COMPARE_MODES, PROPERTY_IDS } from "@/lib/api";
import { assuranceProfile, evidenceManifest, verifyReport } from "@/lib/contract";
import { parseJson } from "@/lib/schema";

import { accept, acceptCompare, acceptVerify } from "../accept";
import { capture } from "../engine";

const REPO = path.resolve(__dirname, "../../../../..");
const BIN = process.env.SOUNDCHECK_TEST_BIN ?? path.join(REPO, "_build", "default", "cli", "main.exe");
const available = existsSync(BIN);
const KONG = path.join(REPO, "bench", "kong");

const fixture = (...parts: string[]) => path.join(KONG, ...parts);
const UNSAFE = fixture("workflows", "frozen-admin", "unsafe.yaml");
const REPAIRED = fixture("workflows", "frozen-admin", "repaired.yaml");
const CONTRACT = fixture("contracts", "admin-get.yaml");

function engine(args: string[]) {
  return capture(BIN, args, { timeoutMs: 120_000, cwd: REPO });
}

const PROPERTY_ARGS: Record<(typeof PROPERTY_IDS)[number], string[]> = {
  "no-anonymous-access": ["--path-prefix", "/admin"],
  "rate-limit-on-public": [],
  "no-shadowed-routes": [],
  "admin-api-not-reachable": ["--trusted-cidr", "127.0.0.1/32"],
  "authenticated-access": ["--path-prefix", "/admin"],
  "network-restricted-access": ["--path-prefix", "/admin", "--trusted-cidr", "10.0.0.0/8"],
};

// The corpus's checked-in golden outputs are real engine reports, so they are
// checked on every run, with or without a built engine.
describe("golden corpus reports", () => {
  const cases = readdirSync(fixture("cases")).filter((name) => existsSync(fixture("cases", name, "expected.json")));

  it("covers the corpus", () => {
    expect(cases.length).toBeGreaterThan(20);
  });

  for (const name of cases) {
    it(`${name}/expected.json matches the verify schema`, async () => {
      const report = parseJson(await readFile(fixture("cases", name, "expected.json"), "utf8"), verifyReport);
      expect(report.schema_version).toBe(9);
    });
  }
});

describe.skipIf(!available)("engine conformance", () => {
  let scratch = "";
  beforeAll(async () => {
    scratch = await mkdtemp(path.join(os.tmpdir(), "soundcheck-conformance-"));
  });
  afterAll(async () => {
    if (scratch) await rm(scratch, { recursive: true, force: true });
  });

  it("documents exactly the comparison modes and properties the frontend knows", async () => {
    const usage = (await engine([])).stderr;
    const modes = usage.match(/--mode ([a-z|-]+)\]/)?.[1].split("|");
    expect(modes?.sort()).toEqual([...COMPARE_MODES].sort());
    for (const property of PROPERTY_IDS) expect(usage).toContain(property);
  });

  it("emits a profile matching the schema", async () => {
    const result = await engine(["profile", "kong", "--format", "json"]);
    const accepted = accept(result, "profile", { validate: assuranceProfile, verdictExits: [0], exitFor: () => 0 });
    expect(accepted).toMatchObject({ ok: true });
  });

  for (const config of ["admin-no-auth", "admin-key-auth", "regex-unsupported-construct"]) {
    for (const property of PROPERTY_IDS) {
      it(`verify ${property} on ${config}`, async () => {
        const args = ["verify", fixture("cases", config, "config.yaml"), "--property", property, ...PROPERTY_ARGS[property], "--format", "json"];
        const result = await engine(args);
        const accepted = acceptVerify(result, args.join(" "), { mode: "property", property });
        expect(accepted, result.stdout + result.stderr).toMatchObject({ ok: true });
      });
    }
  }

  for (const config of [UNSAFE, REPAIRED]) {
    it(`verify a frozen contract with evidence on ${path.basename(config)}`, async () => {
      const evidence = path.join(scratch, `evidence-${path.basename(config, ".yaml")}`);
      const args = ["verify", config, "--contract", CONTRACT, "--evidence-dir", evidence, "--format", "json"];
      const result = await engine(args);
      const accepted = acceptVerify(result, args.join(" "), { mode: "contract" });
      expect(accepted, result.stdout + result.stderr).toMatchObject({ ok: true });
      const manifest = parseJson(await readFile(path.join(evidence, "manifest.json"), "utf8"), evidenceManifest);
      if (accepted.ok) expect(manifest.result).toBe(accepted.report.result);
    });
  }

  for (const mode of COMPARE_MODES) {
    it(`compare --mode ${mode}`, async () => {
      const args = ["compare", UNSAFE, REPAIRED, "--mode", mode, "--format", "json"];
      const result = await engine(args);
      expect(acceptCompare(result, args.join(" "), mode, false), result.stdout + result.stderr).toMatchObject({ ok: true });
    });

    it(`compare --mode ${mode} with a frozen contract`, async () => {
      const args = ["compare", UNSAFE, REPAIRED, "--mode", mode, "--contract", CONTRACT, "--format", "json"];
      const result = await engine(args);
      expect(acceptCompare(result, args.join(" "), mode, true), result.stdout + result.stderr).toMatchObject({ ok: true });
    });
  }
});
