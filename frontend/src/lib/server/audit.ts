import "server-only";

import type { Spec } from "@/lib/api";
import {
  auditChecks,
  DEFAULT_AUDIT_OPTIONS,
  type AuditEvent,
  type AuditFile,
  type AuditOptions,
} from "@/lib/audit";
import { gateway as findGateway, type GatewayId } from "@/lib/gateways";

import { loadSamples } from "./corpus";
import { engineIdentity, sha256 } from "./engine";
import { fieldProblem, loadProfile, runVerify } from "./operations";
import { readZip, ZipError, type ZipEntry } from "./zip";

export const AUDIT_LIMITS = {
  uploadBytes: 25 * 1024 * 1024,
  entries: 2000,
  fileBytes: 512 * 1024,
  extractedBytes: 100 * 1024 * 1024,
  contractBytes: 64 * 1024,
};
const LIMITS = AUDIT_LIMITS;
const WORKERS = 4;

export class AuditInputError extends Error {}

export interface Entry {
  path: string;
  bytes: number;
  sha256: string | null;
  text: string | null;
}

const KONG_YAML = /^(?:_format_version|services|routes|plugins|upstreams|consumers)\s*:/m;
const KONG_JSON = /"(?:_format_version|services|routes|plugins)"\s*:/;
const REPOSE_XML = /openrepose|<system-model|repose-container/i;

function decode(bytes: Uint8Array): string | null {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes).replace(/^﻿/, "");
  return text.includes("\u0000") ? null : text;
}

function entry(path: string, data: Uint8Array): Entry {
  return {
    path,
    bytes: data.length,
    sha256: sha256(data),
    text: data.length > LIMITS.fileBytes ? null : decode(data),
  };
}

function classify(entry: Entry, index: number): AuditFile {
  const base = { index, path: entry.path, bytes: entry.bytes, sha256: entry.sha256 };
  const skipped = (reason: NonNullable<AuditFile["skip"]>["reason"], detail: string, gateway: GatewayId | null = null): AuditFile => ({
    ...base,
    status: "skipped",
    gateway,
    skip: { reason, detail },
  });
  const extension = entry.path.toLowerCase().match(/\.([a-z0-9]+)$/)?.[1] ?? "";

  if (entry.bytes > LIMITS.fileBytes) return skipped("too-large", "Larger than 512 KB, so it was not audited.");
  if (entry.text === null) return skipped("unreadable", "Binary or unreadable content, so it was not audited.");

  if (["yaml", "yml", "json"].includes(extension)) {
    const kong = extension === "json" ? KONG_JSON.test(entry.text) : KONG_YAML.test(entry.text);
    return kong
      ? { ...base, status: "audit", gateway: "kong" }
      : skipped("not-a-config", "No Kong services, routes or plugins recognised, so it was not audited.");
  }
  if (extension === "xml") {
    return REPOSE_XML.test(entry.text)
      ? skipped("coming-soon", "Repose configuration. Repose is not supported yet, so it was not audited.", "repose")
      : skipped("unsupported-type", "XML that is not a recognised gateway configuration.");
  }
  return skipped("unsupported-type", extension ? `.${extension} is not a supported config format.` : "No file extension.");
}

function isZip(name: string, bytes: Uint8Array) {
  return name.toLowerCase().endsWith(".zip") || (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04);
}

/** macOS archive metadata: resource forks and Finder state, never configs. */
function isArchiveMetadata(name: string) {
  return name.startsWith("__MACOSX/") || name === ".DS_Store" || name.endsWith("/.DS_Store");
}

export function extractZip(bytes: Uint8Array): Entry[] {
  let read: ZipEntry[];
  try {
    read = readZip(bytes, { entries: LIMITS.entries, fileBytes: LIMITS.fileBytes, totalBytes: LIMITS.extractedBytes });
  } catch (error) {
    // An inconsistent archive is refused outright: auditing a different set of
    // bytes than the uploader packed would make any verdict meaningless.
    if (error instanceof ZipError) throw new AuditInputError(`The zip was rejected: ${error.message}.`);
    throw error;
  }
  return read
    .filter((item) => !isArchiveMetadata(item.path))
    .map((item): Entry =>
      item.status === "read"
        ? entry(item.path, item.data)
        : { path: item.path, bytes: item.declaredBytes, sha256: null, text: null },
    )
    .sort((a, b) => a.path.localeCompare(b.path));
}

async function sampleEntries(): Promise<Entry[]> {
  const { configs } = await loadSamples();
  return configs.map((sample) => {
    const [kind, id] = sample.id.split(":");
    const path = kind === "case" ? `cases/${id}/config.yaml` : `workflows/frozen-admin/${id}`;
    return entry(path, new TextEncoder().encode(sample.content));
  });
}

function text(form: FormData, key: string): string | null {
  const value = form.get(key);
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

export interface PreparedAudit {
  plan: Extract<AuditEvent, { type: "plan" }>;
  configs: Map<number, string>;
  contract: string | null;
}

export async function prepareAudit(form: FormData, signal?: AbortSignal): Promise<PreparedAudit> {
  const gatewayId = text(form, "gateway") ?? "kong";
  const gateway = findGateway(gatewayId);
  if (!gateway) throw new AuditInputError(`Unknown gateway "${gatewayId}".`);
  if (gateway.status !== "supported") throw new AuditInputError(`${gateway.name} support is coming soon.`);

  const options: AuditOptions = {
    pathPrefix: text(form, "pathPrefix") ?? DEFAULT_AUDIT_OPTIONS.pathPrefix,
    trustedCidr: text(form, "trustedCidr") ?? DEFAULT_AUDIT_OPTIONS.trustedCidr,
  };
  const problem = fieldProblem(options.pathPrefix, "pathPrefix") ?? fieldProblem(options.trustedCidr, "trustedCidr");
  if (problem) throw new AuditInputError(problem);

  let contract: string | null = null;
  const contractFile = form.get("contract");
  if (contractFile instanceof File && contractFile.size > 0) {
    if (contractFile.size > LIMITS.contractBytes) throw new AuditInputError("The contract is larger than 64 KB.");
    contract = await contractFile.text();
  } else {
    contract = text(form, "contractText");
    if (contract && Buffer.byteLength(contract) > LIMITS.contractBytes) {
      throw new AuditInputError("The contract is larger than 64 KB.");
    }
  }
  const contractKind = contract ? (contract.match(/^kind:\s*["']?([\w-]+)/m)?.[1] ?? null) : null;
  if (contract && !contractKind) throw new AuditInputError("The contract has no kind field.");

  let source: string;
  let sourceSha256: string;
  let entries: Entry[];
  const upload = form.get("file");
  if (text(form, "source") === "samples") {
    source = "Soundcheck sample bundle";
    entries = await sampleEntries();
    sourceSha256 = sha256(entries.map((item) => `${item.sha256}  ${item.path}\n`).join(""));
  } else if (upload instanceof File && upload.size > 0) {
    if (upload.size > LIMITS.uploadBytes) throw new AuditInputError("The upload is larger than 25 MB.");
    source = upload.name;
    const bytes = new Uint8Array(await upload.arrayBuffer());
    sourceSha256 = sha256(bytes);
    entries = isZip(upload.name, bytes) ? extractZip(bytes) : [entry(upload.name, bytes)];
  } else {
    throw new AuditInputError("Choose a YAML, JSON or zip file to audit.");
  }
  if (entries.length === 0) throw new AuditInputError("The upload contains no files.");

  const files = entries.map(classify);
  const configs = new Map<number, string>();
  files.forEach((file) => {
    if (file.status === "audit") configs.set(file.index, entries[file.index].text!);
  });

  const profile = await loadProfile(signal);
  if (!profile.ok) throw new AuditInputError(profile.message);
  const engine = await engineIdentity();
  if (!engine) throw new AuditInputError("No Soundcheck engine found.");

  return {
    plan: {
      type: "plan",
      source,
      gateway: gateway.id,
      profile: profile.profile.id,
      options,
      contract,
      checks: auditChecks(options, contractKind),
      files,
      provenance: {
        sourceSha256,
        engine,
        profile: profile.profile.id,
        contractSha256: contract ? sha256(contract) : null,
      },
    },
    configs,
    contract,
  };
}

/**
 * Streams one NDJSON event per finished check. `done` is sent only when every
 * planned check has a result; a cancelled or failed run ends without it, so a
 * client can never mistake a partial run for a complete one.
 */
export function auditStream(prepared: PreparedAudit, signal: AbortSignal): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  // Aborted when the client disconnects or the stream is cancelled; in-flight
  // engine runs are killed rather than left to finish unobserved.
  const stop = new AbortController();
  const onAbort = () => stop.abort();
  signal.addEventListener("abort", onAbort, { once: true });

  return new ReadableStream({
    async start(controller) {
      const send = (event: AuditEvent) => {
        if (stop.signal.aborted) return;
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
        } catch {
          stop.abort();
        }
      };
      const started = performance.now();
      send(prepared.plan);

      const jobs: { file: number; check: string; config: string; spec: Spec }[] = [];
      for (const [file, config] of prepared.configs) {
        for (const check of prepared.plan.checks) {
          const spec: Spec = check.spec ?? { mode: "contract", contract: prepared.contract! };
          jobs.push({ file, check: check.id, config, spec });
        }
      }

      let next = 0;
      let completed = 0;
      const worker = async () => {
        while (next < jobs.length && !stop.signal.aborted) {
          const job = jobs[next++];
          const response = await runVerify({ config: job.config, spec: job.spec }, stop.signal);
          if (stop.signal.aborted) return;
          completed++;
          send({ type: "result", file: job.file, check: job.check, response });
        }
      };
      try {
        await Promise.all(Array.from({ length: WORKERS }, worker));
        if (completed === jobs.length) {
          send({ type: "done", durationMs: Math.round(performance.now() - started), completed, expected: jobs.length });
        } else if (!stop.signal.aborted) {
          send({ type: "error", message: `Only ${completed} of ${jobs.length} checks finished.` });
        }
      } catch (error) {
        send({ type: "error", message: (error as Error).message });
      } finally {
        signal.removeEventListener("abort", onAbort);
      }
      try {
        controller.close();
      } catch {
        // Already closed by a cancelled client.
      }
    },
    cancel() {
      stop.abort();
    },
  });
}
