import "server-only";

import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import type { PropertyId, PropertySpec, Sample } from "@/lib/api";
import type { VerifyReport } from "@/lib/contract";
import { humanize, sentence } from "@/lib/domain";

import { REPO_ROOT } from "./engine";

const KONG_BENCH = path.join(REPO_ROOT, "bench", "kong");
const CASES_DIR = path.join(KONG_BENCH, "cases");

export interface CorpusCase {
  id: string;
  title: string;
  scenario: string;
  expectation: string | null;
  config: string;
  expected: VerifyReport;
  spec: PropertySpec;
}

async function optional(dir: string, name: string) {
  try {
    return (await readFile(path.join(dir, name), "utf8")).trim();
  } catch {
    return undefined;
  }
}

// Defaults match bench/corpus.ml so a live run is comparable with the golden.
function specFor(property: PropertyId, sidecar: Record<string, string | undefined>): PropertySpec {
  switch (property) {
    case "no-anonymous-access":
      return { mode: "property", property, pathPrefix: "/admin" };
    case "admin-api-not-reachable":
      return { mode: "property", property, trustedCidr: "10.0.0.0/8" };
    case "authenticated-access":
      return {
        mode: "property",
        property,
        pathPrefix: sidecar["path-prefix"] ?? "/admin",
        method: sidecar.method,
        host: sidecar.host,
      };
    case "network-restricted-access":
      return {
        mode: "property",
        property,
        pathPrefix: sidecar["path-prefix"] ?? "/internal",
        method: sidecar.method,
        host: sidecar.host,
        trustedCidr: sidecar["trusted-cidr"] ?? "10.0.0.0/8",
      };
    default:
      return { mode: "property", property };
  }
}

function describe(config: string) {
  const lines: string[] = [];
  for (const line of config.split(/\r?\n/)) {
    if (!line.startsWith("#")) break;
    lines.push(line.replace(/^#\s?/, ""));
  }
  const text = lines.join("\n");
  const expectationMatch = text.match(/Expected:\s*([\s\S]*)$/);
  const scenario = text
    .replace(/Expected:[\s\S]*$/, "")
    .replace(/^Scenario:\s*/, "")
    .split(/\n\s*\n/)
    .map((paragraph) => sentence(paragraph.replace(/\s*\n\s*/g, " ").trim()))
    .filter(Boolean)
    .join("\n\n");
  return {
    scenario,
    expectation: expectationMatch ? expectationMatch[1].replace(/\s*\n\s*/g, " ").trim() : null,
  };
}

async function loadCase(id: string): Promise<CorpusCase> {
  const dir = path.join(CASES_DIR, id);
  const [config, expectedText] = await Promise.all([
    readFile(path.join(dir, "config.yaml"), "utf8"),
    readFile(path.join(dir, "expected.json"), "utf8"),
  ]);
  const sidecarNames = ["property", "path-prefix", "method", "host", "trusted-cidr"];
  const sidecarValues = await Promise.all(sidecarNames.map((name) => optional(dir, name)));
  const sidecar = Object.fromEntries(sidecarNames.map((name, i) => [name, sidecarValues[i]]));
  const property = (sidecar.property ?? "no-anonymous-access") as PropertyId;
  return {
    id,
    title: humanize(id),
    ...describe(config),
    config,
    expected: JSON.parse(expectedText) as VerifyReport,
    spec: specFor(property, sidecar),
  };
}

export async function caseIds(): Promise<string[]> {
  try {
    const entries = await readdir(CASES_DIR, { withFileTypes: true });
    return entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  } catch {
    return [];
  }
}

export async function listCases(): Promise<CorpusCase[]> {
  return Promise.all((await caseIds()).map(loadCase));
}

/** Only ids that exist on disk are loaded, so a crafted id cannot escape the corpus. */
export async function getCase(id: string): Promise<CorpusCase | null> {
  return (await caseIds()).includes(id) ? loadCase(id) : null;
}

async function yamlFiles(dir: string) {
  try {
    const names = (await readdir(dir)).filter((name) => name.endsWith(".yaml")).sort();
    return Promise.all(
      names.map(async (name) => ({ name, content: await readFile(path.join(dir, name), "utf8") })),
    );
  } catch {
    return [];
  }
}

export interface Samples {
  configs: Sample[];
  contracts: Sample[];
}

export async function loadSamples(): Promise<Samples> {
  const [contracts, workflows, cases] = await Promise.all([
    yamlFiles(path.join(KONG_BENCH, "contracts")),
    yamlFiles(path.join(KONG_BENCH, "workflows", "frozen-admin")),
    listCases(),
  ]);
  const order = ["unsafe.yaml", "repaired.yaml", "deny-all.yaml"];
  return {
    contracts: contracts.map((file) => ({
      id: `contract:${file.name}`,
      label: file.name,
      group: "Frozen contracts",
      content: file.content,
    })),
    configs: [
      ...workflows
        .sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name))
        .map((file) => ({
          id: `workflow:${file.name}`,
          label: humanize(file.name.replace(/\.yaml$/, "")),
          group: "Frozen admin workflow",
          content: file.content,
        })),
      ...cases.map((item) => ({
        id: `case:${item.id}`,
        label: item.title,
        group: "Corpus cases",
        content: item.config,
      })),
    ],
  };
}
