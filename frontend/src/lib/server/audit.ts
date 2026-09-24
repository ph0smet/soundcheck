import "server-only";

import { unzipSync } from "fflate";

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
import { fieldProblem, loadProfile, runVerify } from "./operations";

const LIMITS = {
  uploadBytes: 25 * 1024 * 1024,
  entries: 2000,
  fileBytes: 512 * 1024,
  extractedBytes: 100 * 1024 * 1024,
  contractBytes: 64 * 1024,
};
const WORKERS = 4;

export class AuditInputError extends Error {}

interface Entry {
  path: string;
  bytes: number;
  text: string | null;
}

const KONG_YAML = /^(?:_format_version|services|routes|plugins|upstreams|consumers)\s*:/m;
const KONG_JSON = /"(?:_format_version|services|routes|plugins)"\s*:/;
const REPOSE_XML = /openrepose|<system-model|repose-container/i;

function decode(bytes: Uint8Array): string | null {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes).replace(/^﻿/, "");
  return text.includes("\u0000") ? null : text;
}

function classify(entry: Entry, index: number): AuditFile {
  const base = { index, path: entry.path, bytes: entry.bytes };
  const skipped = (reason: NonNullable<AuditFile["skip"]>["reason"], detail: string, gateway: GatewayId | null = null): AuditFile => ({
    ...base,
    status: "skipped",
    gateway,
    skip: { reason, detail },
  });
  const extension = entry.path.toLowerCase().match(/\.([a-z0-9]+)$/)?.[1] ?? "";

  if (entry.bytes > LIMITS.fileBytes) return skipped("too-large", "Larger than 512 KB.");
  if (entry.text === null) return skipped("unreadable", "Binary or unreadable content.");

  if (["yaml", "yml", "json"].includes(extension)) {
    const kong = extension === "json" ? KONG_JSON.test(entry.text) : KONG_YAML.test(entry.text);
    return kong
      ? { ...base, status: "audit", gateway: "kong" }
      : skipped("not-a-config", "No Kong services, routes or plugins found.");
  }
  if (extension === "xml") {
    return REPOSE_XML.test(entry.text)
      ? skipped("coming-soon", "Repose configuration. Repose support is coming soon.", "repose")
      : skipped("unsupported-type", "XML that is not a recognised gateway configuration.");
  }
  return skipped("unsupported-type", extension ? `.${extension} is not a supported config format.` : "No file extension.");
}

function isZip(name: string, bytes: Uint8Array) {
  return name.toLowerCase().endsWith(".zip") || (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04);
}

function extractZip(bytes: Uint8Array): Entry[] {
  let entries = 0;
  let declared = 0;
  const oversized: Entry[] = [];
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(bytes, {
      filter: (file) => {
        const name = file.name;
        if (name.endsWith("/") || name.startsWith("__MACOSX/") || /(^|\/)\./.test(name)) return false;
        entries++;
        declared += file.originalSize;
        // Oversized entries are reported as skipped without being inflated.
        if (file.originalSize > LIMITS.fileBytes) {
          oversized.push({ path: name, bytes: file.originalSize, text: null });
          return false;
        }
        return entries <= LIMITS.entries && declared <= LIMITS.extractedBytes;
      },
    });
  } catch (error) {
    throw new AuditInputError(`The zip could not be read: ${(error as Error).message}`);
  }
  if (entries > LIMITS.entries) throw new AuditInputError(`The zip has more than ${LIMITS.entries} files.`);
  if (declared > LIMITS.extractedBytes) throw new AuditInputError("The zip expands to more than 100 MB.");

  return [
    ...Object.entries(files).map(([path, data]) => ({
      path,
      bytes: data.length,
      text: data.length > LIMITS.fileBytes ? null : decode(data),
    })),
    ...oversized,
  ].sort((a, b) => a.path.localeCompare(b.path));
}

async function sampleEntries(): Promise<Entry[]> {
  const { configs } = await loadSamples();
  return configs.map((sample) => {
    const [kind, id] = sample.id.split(":");
    const path = kind === "case" ? `cases/${id}/config.yaml` : `workflows/frozen-admin/${id}`;
    return { path, bytes: Buffer.byteLength(sample.content), text: sample.content };
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

export async function prepareAudit(form: FormData): Promise<PreparedAudit> {
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
  }
  const contractKind = contract ? (contract.match(/^kind:\s*["']?([\w-]+)/m)?.[1] ?? null) : null;
  if (contract && !contractKind) throw new AuditInputError("The contract has no kind field.");

  let source: string;
  let entries: Entry[];
  const upload = form.get("file");
  if (text(form, "source") === "samples") {
    source = "Soundcheck sample bundle";
    entries = await sampleEntries();
  } else if (upload instanceof File && upload.size > 0) {
    if (upload.size > LIMITS.uploadBytes) throw new AuditInputError("The upload is larger than 25 MB.");
    source = upload.name;
    const bytes = new Uint8Array(await upload.arrayBuffer());
    entries = isZip(upload.name, bytes)
      ? extractZip(bytes)
      : [{ path: upload.name, bytes: bytes.length, text: bytes.length > LIMITS.fileBytes ? null : decode(bytes) }];
  } else {
    throw new AuditInputError("Choose a YAML, JSON or zip file to audit.");
  }
  if (entries.length === 0) throw new AuditInputError("The upload contains no files.");

  const files = entries.map(classify);
  const configs = new Map<number, string>();
  files.forEach((file) => {
    if (file.status === "audit") configs.set(file.index, entries[file.index].text!);
  });

  const profile = await loadProfile();
  if (!profile.ok) throw new AuditInputError(profile.message);

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
    },
    configs,
    contract,
  };
}

export function auditStream(prepared: PreparedAudit, signal: AbortSignal): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  let cancelled = false;

  return new ReadableStream({
    async start(controller) {
      const send = (event: AuditEvent) => {
        if (cancelled) return;
        try {
          controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
        } catch {
          cancelled = true;
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
      const worker = async () => {
        while (next < jobs.length && !cancelled && !signal.aborted) {
          const job = jobs[next++];
          const response = await runVerify({ config: job.config, spec: job.spec });
          send({ type: "result", file: job.file, check: job.check, response });
        }
      };
      try {
        await Promise.all(Array.from({ length: WORKERS }, worker));
        send({ type: "done", durationMs: Math.round(performance.now() - started) });
      } catch (error) {
        send({ type: "error", message: (error as Error).message });
      }
      if (!cancelled) controller.close();
    },
    cancel() {
      cancelled = true;
    },
  });
}
