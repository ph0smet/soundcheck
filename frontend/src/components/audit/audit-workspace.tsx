"use client";

import {
  FileArchive,
  FileDown,
  FileText,
  FileUp,
  FlaskConical,
  Loader2,
  Play,
  ScrollText,
  Settings2,
  X,
} from "lucide-react";
import { useMemo, useRef, useState, type DragEvent } from "react";

import type { Sample } from "@/lib/api";
import {
  cellOutcome,
  DEFAULT_AUDIT_OPTIONS,
  resultKey,
  STATUS_COPY,
  totals,
  type AuditEvent,
  type AuditOptions,
  type AuditRun,
  type CellOutcome,
} from "@/lib/audit";
import { VERDICTS, type Tone } from "@/lib/domain";
import { GATEWAYS, type GatewayId } from "@/lib/gateways";
import { buildReport } from "@/lib/report/model";
import { renderMarkdown } from "@/lib/report/markdown";

import { Failure, OfflineHint } from "../results/states";
import { VerifyOutcome } from "../results/verify-result";
import { engineReady, useEngine } from "../shell/engine-status";
import { Button, Eyebrow, Field, PageHeader, Panel, TONE_BG, TONE_TEXT, TONE_TINT } from "../ui";

type Phase = { status: "idle" } | { status: "running" } | { status: "done" } | { status: "error"; message: string };

const STATUS_TONE: Record<string, Tone> = { pass: "proved", review: "vacuous", fail: "violated" };

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function download(name: string, data: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function reportName(run: AuditRun, extension: string) {
  const slug = run.source.toLowerCase().replace(/\.[a-z0-9]+$/, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "audit";
  return `soundcheck-audit-${slug}-${run.startedAt.slice(0, 10)}.${extension}`;
}

export function AuditWorkspace({ contracts }: { contracts: Sample[] }) {
  const [gatewayId, setGatewayId] = useState<GatewayId>("kong");
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [options, setOptions] = useState<AuditOptions>(DEFAULT_AUDIT_OPTIONS);
  const [contractText, setContractText] = useState<string | null>(null);
  const [contractName, setContractName] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>({ status: "idle" });
  const [run, setRun] = useState<AuditRun | null>(null);
  const [selected, setSelected] = useState<{ file: number; check: string } | null>(null);
  const [onlyFindings, setOnlyFindings] = useState(false);
  const [exporting, setExporting] = useState<"md" | "pdf" | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const contractInput = useRef<HTMLInputElement>(null);
  const abort = useRef<AbortController | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const { status } = useEngine();
  const ready = engineReady(status);
  const running = phase.status === "running";

  async function start(source: "upload" | "samples") {
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    const form = new FormData();
    form.set("gateway", gatewayId);
    form.set("pathPrefix", options.pathPrefix);
    form.set("trustedCidr", options.trustedCidr);
    if (contractText) form.set("contractText", contractText);
    if (source === "samples") form.set("source", "samples");
    else if (file) form.set("file", file);

    setPhase({ status: "running" });
    setRun(null);
    setSelected(null);
    const startedAt = new Date().toISOString();

    try {
      const response = await fetch("/api/audit", { method: "POST", body: form, signal: controller.signal });
      if (!response.ok || !response.headers.get("content-type")?.includes("ndjson") || !response.body) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null;
        setPhase({ status: "error", message: body?.error ?? `The audit failed (HTTP ${response.status}).` });
        return;
      }
      resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let finished = false;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          const event = JSON.parse(line) as AuditEvent;
          if (event.type === "plan") {
            setRun({
              source: event.source,
              gateway: event.gateway,
              profile: event.profile,
              options: event.options,
              contract: event.contract,
              checks: event.checks,
              files: event.files,
              results: {},
              startedAt,
              durationMs: null,
            });
          } else if (event.type === "result") {
            setRun((current) =>
              current && { ...current, results: { ...current.results, [resultKey(event.file, event.check)]: event.response } },
            );
          } else if (event.type === "done") {
            finished = true;
            setRun((current) => current && { ...current, durationMs: event.durationMs });
          } else if (event.type === "error") {
            setPhase({ status: "error", message: event.message });
            return;
          }
        }
      }
      setPhase(finished ? { status: "done" } : { status: "error", message: "The audit stream ended early." });
    } catch (error) {
      if ((error as Error).name === "AbortError") return;
      setPhase({ status: "error", message: "The request to the web server failed." });
    }
  }

  function cancel() {
    abort.current?.abort();
    setPhase({ status: "done" });
  }

  async function exportReport(kind: "md" | "pdf") {
    if (!run) return;
    setExporting(kind);
    try {
      const report = buildReport(run);
      if (kind === "md") {
        download(reportName(run, "md"), renderMarkdown(report), "text/markdown;charset=utf-8");
      } else {
        const { renderPdf } = await import("@/lib/report/pdf");
        const bytes = await renderPdf(report);
        download(reportName(run, "pdf"), bytes.slice().buffer, "application/pdf");
      }
    } finally {
      setExporting(null);
    }
  }

  function onDrop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) setFile(dropped);
  }

  const summary = run ? totals(run) : null;
  const total = summary ? summary.audited * (run?.checks.length ?? 0) : 0;
  const completed = run ? Object.keys(run.results).length : 0;
  const auditedFiles = useMemo(() => run?.files.filter((item) => item.status === "audit") ?? [], [run]);
  const visibleFiles = onlyFindings
    ? auditedFiles.filter((item) =>
        run!.checks.some((check) => {
          const outcome = cellOutcome(run!.results[resultKey(item.index, check.id)]);
          return outcome !== "proved" && outcome !== "pending";
        }),
      )
    : auditedFiles;
  const skipped = run?.files.filter((item) => item.status === "skipped") ?? [];
  const selectedResponse = selected && run ? run.results[resultKey(selected.file, selected.check)] : undefined;

  return (
    <div className="flex min-h-dvh flex-col">
      <PageHeader
        title="Audit"
        description="Upload a gateway config, or a zip of them. Soundcheck finds every config, runs each check on it and produces a report you can share as Markdown or PDF."
      />

      <div className="space-y-4 p-4 md:p-6">
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <Panel title="Source" bodyClassName="space-y-4 p-4">
            <div>
              <Eyebrow className="mb-2">Gateway</Eyebrow>
              <div role="radiogroup" aria-label="Gateway" className="grid gap-2 sm:grid-cols-2">
                {GATEWAYS.map((item) => {
                  const supported = item.status === "supported";
                  const active = item.id === gatewayId;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      role="radio"
                      aria-checked={active}
                      aria-disabled={!supported}
                      disabled={!supported}
                      onClick={() => setGatewayId(item.id)}
                      className={`rounded-lg border px-3 py-2.5 text-left transition-colors disabled:cursor-not-allowed ${
                        active ? "border-ink bg-surface-2" : "border-line hover:bg-surface-2 disabled:hover:bg-transparent"
                      }`}
                    >
                      <span className="flex items-center gap-2">
                        <span className={`text-[13px] font-medium ${supported ? "" : "text-ink-3"}`}>{item.name}</span>
                        <span
                          className={`rounded-full px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide ${
                            supported ? "tint-proved text-proved" : "bg-surface-3 text-ink-3"
                          }`}
                        >
                          {supported ? "Supported" : "Coming soon"}
                        </span>
                      </span>
                      <span className={`mt-0.5 block text-xs leading-snug ${supported ? "text-ink-2" : "text-ink-3"}`}>
                        {item.formats}
                      </span>
                    </button>
                  );
                })}
              </div>
              <p className="mt-2 text-2xs text-ink-3">More gateways will follow as their connectors land in the engine.</p>
            </div>

            <div
              onDragOver={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className={`rounded-xl border border-dashed transition-colors ${
                dragging ? "border-ink bg-surface-2" : "border-line-strong"
              }`}
            >
              <input
                ref={input}
                type="file"
                accept=".yaml,.yml,.json,.zip,application/zip"
                className="sr-only"
                tabIndex={-1}
                onChange={(event) => {
                  const chosen = event.target.files?.[0];
                  if (chosen) setFile(chosen);
                  event.target.value = "";
                }}
              />
              {file ? (
                <div className="flex items-center gap-3 p-4">
                  <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-surface-3">
                    {/\.zip$/i.test(file.name) ? <FileArchive className="size-5 text-ink-2" /> : <FileText className="size-5 text-ink-2" />}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[13px] font-medium">{file.name}</p>
                    <p className="text-xs text-ink-3">
                      {formatBytes(file.size)} · {/\.zip$/i.test(file.name) ? "every config inside is audited" : "single config"}
                    </p>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => input.current?.click()}>
                    Replace
                  </Button>
                  <Button size="sm" variant="ghost" aria-label="Remove file" onClick={() => setFile(null)}>
                    <X className="size-3.5" />
                  </Button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => input.current?.click()}
                  className="flex w-full flex-col items-center gap-2 px-6 py-9 text-center"
                >
                  <span className="flex size-11 items-center justify-center rounded-full bg-surface-3">
                    <FileUp className="size-5 text-ink-2" />
                  </span>
                  <span className="text-[13.5px] font-medium">Drop a file here, or browse</span>
                  <span className="text-xs text-ink-3">
                    Kong decK <span className="font-mono">.yaml</span>, <span className="font-mono">.json</span>, or a{" "}
                    <span className="font-mono">.zip</span> of configs. Up to 25 MB.
                  </span>
                </button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button variant="primary" onClick={() => void start("upload")} disabled={!ready || !file || running}>
                {running ? <Loader2 className="size-3.5 animate-spin" /> : <Play className="size-3.5 fill-current" />}
                {running ? "Auditing" : "Run audit"}
              </Button>
              <Button onClick={() => void start("samples")} disabled={!ready || running} title="Audit the configs that ship with Soundcheck">
                <FlaskConical className="size-3.5" />
                No config? Try the sample bundle
              </Button>
              {running && (
                <Button variant="ghost" onClick={cancel}>
                  Cancel
                </Button>
              )}
            </div>
            {!ready && <OfflineHint />}
          </Panel>

          <Panel
            title={
              <span className="flex items-center gap-2">
                <Settings2 className="size-3.5 text-ink-3" />
                Checks
              </span>
            }
            bodyClassName="space-y-4 p-4"
          >
            <ul className="space-y-1.5 text-[13px]">
              <li><span className="font-medium">No anonymous access</span> <span className="text-ink-2">under the protected prefix</span></li>
              <li><span className="font-medium">Rate limit on public</span> <span className="text-ink-2">for every anonymously reachable route</span></li>
              <li><span className="font-medium">No shadowed routes</span> <span className="text-ink-2">read from the config&rsquo;s own auth intent</span></li>
              <li><span className="font-medium">Admin API not reachable</span> <span className="text-ink-2">from outside the trusted block</span></li>
              <li>
                <span className="font-medium">Frozen contract</span>{" "}
                <span className="text-ink-2">{contractName ? `from ${contractName}` : "optional, when you attach one"}</span>
              </li>
            </ul>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label="Protected path prefix"
                value={options.pathPrefix}
                onChange={(event) => setOptions({ ...options, pathPrefix: event.target.value })}
                placeholder="/admin"
              />
              <Field
                label="Trusted CIDR"
                value={options.trustedCidr}
                onChange={(event) => setOptions({ ...options, trustedCidr: event.target.value })}
                placeholder="127.0.0.1/32"
                hint="For the Admin API check"
              />
            </div>
            <div className="space-y-2 rounded-lg border border-line p-3">
              <div className="flex items-center gap-2">
                <ScrollText className="size-3.5 text-ink-3" />
                <p className="text-xs font-medium">Frozen contract</p>
                {contractName && (
                  <Button size="sm" variant="ghost" className="ml-auto" onClick={() => { setContractText(null); setContractName(null); }}>
                    <X className="size-3" />
                    Remove
                  </Button>
                )}
              </div>
              <p className="text-2xs leading-relaxed text-ink-3">
                Paired checks such as authenticated access describe intended behavior, which Soundcheck never guesses from a
                config. Attach a contract to check every config against it.
              </p>
              <div className="flex flex-wrap gap-1.5">
                <input
                  ref={contractInput}
                  type="file"
                  accept=".yaml,.yml"
                  className="sr-only"
                  tabIndex={-1}
                  onChange={async (event) => {
                    const chosen = event.target.files?.[0];
                    if (chosen) {
                      setContractText(await chosen.text());
                      setContractName(chosen.name);
                    }
                    event.target.value = "";
                  }}
                />
                <Button size="sm" onClick={() => contractInput.current?.click()}>
                  Upload contract
                </Button>
                {contracts.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    aria-pressed={contractName === item.label}
                    onClick={() => { setContractText(item.content); setContractName(item.label); }}
                    className={`rounded-md border px-2 py-1 font-mono text-2xs transition ${
                      contractName === item.label ? "border-ink text-ink" : "border-line text-ink-2 hover:border-line-strong hover:text-ink"
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>
          </Panel>
        </div>

        <div ref={resultsRef} className="scroll-mt-4 space-y-4">
          {phase.status === "error" && <Failure failure={{ ok: false, stage: "input", exitCode: null, message: phase.message }} />}

          {run && summary && (
            <>
              <section className="animate-reveal overflow-hidden rounded-xl border border-line bg-surface shadow-card">
                <div className="relative flex flex-col gap-4 p-5 md:flex-row md:items-center">
                  <span className={`absolute inset-y-0 left-0 w-1 ${running ? "bg-ink-3" : TONE_BG[STATUS_TONE[summary.status]]}`} />
                  <div className="min-w-0 flex-1">
                    <p className="text-2xs text-ink-3">
                      {run.source} · {GATEWAYS.find((item) => item.id === run.gateway)?.name} · <span className="font-mono">{run.profile}</span>
                    </p>
                    <p className={`mt-1 font-mono text-[22px] font-semibold uppercase tracking-[0.04em] ${running ? "text-ink-2" : TONE_TEXT[STATUS_TONE[summary.status]]}`}>
                      {running ? "Auditing" : STATUS_COPY[summary.status].label}
                    </p>
                    <p className="mt-0.5 text-[13px] text-ink-2">
                      {running
                        ? `${completed} of ${total} checks complete`
                        : `${STATUS_COPY[summary.status].summary}${run.durationMs !== null ? ` Finished in ${(run.durationMs / 1000).toFixed(1)} s.` : ""}`}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button onClick={() => void exportReport("md")} disabled={running || exporting !== null}>
                      <FileDown className="size-3.5" />
                      Markdown
                    </Button>
                    <Button onClick={() => void exportReport("pdf")} disabled={running || exporting !== null}>
                      {exporting === "pdf" ? <Loader2 className="size-3.5 animate-spin" /> : <FileDown className="size-3.5" />}
                      PDF
                    </Button>
                  </div>
                </div>
                {running && (
                  <div className="h-0.5 bg-surface-3">
                    <div className="h-full bg-ink transition-[width] duration-300" style={{ width: `${total ? (completed / total) * 100 : 0}%` }} />
                  </div>
                )}
                <dl className="grid grid-cols-3 divide-x divide-y divide-line border-t border-line sm:grid-cols-6 sm:divide-y-0">
                  {[
                    ["Configs", summary.audited, null],
                    ["Skipped", summary.skipped, null],
                    ["Proved", summary.outcomes.proved, "proved"],
                    ["Violated", summary.outcomes.violated + summary.outcomes.inconsistent, "violated"],
                    ["Unknown", summary.outcomes.unknown + summary.outcomes.vacuous, "unknown"],
                    ["Errors", summary.outcomes.error, null],
                  ].map(([label, value, tone]) => (
                    <div key={label as string} className="px-4 py-3">
                      <dt className="text-2xs text-ink-3">{label}</dt>
                      <dd className={`font-mono text-[18px] font-semibold tabular-nums ${tone && (value as number) > 0 ? TONE_TEXT[tone as Tone] : ""}`}>
                        {value}
                      </dd>
                    </div>
                  ))}
                </dl>
              </section>

              {auditedFiles.length > 0 ? (
                <div className="grid gap-4 2xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
                  <Panel
                    title={`Results · ${auditedFiles.length} config${auditedFiles.length === 1 ? "" : "s"}`}
                    actions={
                      <label className="flex cursor-pointer items-center gap-2 text-xs text-ink-2">
                        <input
                          type="checkbox"
                          checked={onlyFindings}
                          onChange={(event) => setOnlyFindings(event.target.checked)}
                          className="size-3.5 accent-[var(--ink)]"
                        />
                        Only files with findings
                      </label>
                    }
                  >
                    <div className="scrollbar-thin max-h-[640px] overflow-auto">
                      <table className="w-full min-w-[640px] text-left text-[13px]">
                        <thead className="sticky top-0 z-10 bg-surface-2 text-2xs text-ink-3">
                          <tr>
                            <th scope="col" className="px-4 py-2 font-medium">File</th>
                            {run.checks.map((check) => (
                              <th key={check.id} scope="col" className="px-2 py-2 font-medium" title={check.description}>
                                {check.label}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-line">
                          {visibleFiles.map((item) => (
                            <tr key={item.index}>
                              <th scope="row" className="max-w-[260px] truncate px-4 py-2 text-left font-mono text-xs font-normal text-ink" title={item.path}>
                                {item.path}
                              </th>
                              {run.checks.map((check) => {
                                const outcome = cellOutcome(run.results[resultKey(item.index, check.id)]);
                                const active = selected?.file === item.index && selected.check === check.id;
                                return (
                                  <td key={check.id} className="px-2 py-1.5">
                                    <OutcomeCell
                                      outcome={outcome}
                                      active={active}
                                      onClick={() => setSelected({ file: item.index, check: check.id })}
                                    />
                                  </td>
                                );
                              })}
                            </tr>
                          ))}
                          {visibleFiles.length === 0 && (
                            <tr>
                              <td colSpan={run.checks.length + 1} className="px-4 py-8 text-center text-[13px] text-ink-3">
                                {running ? "Waiting for results." : "No findings. Every check was proved."}
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </Panel>

                  <Panel title="Detail" bodyClassName="p-4">
                    {selected && selectedResponse ? (
                      <div className="space-y-3">
                        <p className="truncate font-mono text-xs text-ink-2" title={run.files[selected.file].path}>
                          {run.files[selected.file].path}
                        </p>
                        {selectedResponse.ok ? (
                          <VerifyOutcome
                            key={`${selected.file}:${selected.check}`}
                            report={selectedResponse.report}
                            exitCode={selectedResponse.exitCode}
                            durationMs={selectedResponse.durationMs}
                          />
                        ) : (
                          <Failure failure={selectedResponse} />
                        )}
                      </div>
                    ) : (
                      <p className="text-[13px] leading-relaxed text-ink-2">
                        Select a result to see the verdict, the counterexample request and the assurance findings.
                      </p>
                    )}
                  </Panel>
                </div>
              ) : (
                <Panel bodyClassName="p-5">
                  <p className="text-[13px] font-medium">No Kong configuration found</p>
                  <p className="mt-1 text-[13px] text-ink-2">
                    Nothing in this upload looks like a Kong declarative config. The skipped files are listed below.
                  </p>
                </Panel>
              )}

              {skipped.length > 0 && (
                <details className="group rounded-xl border border-line bg-surface shadow-card">
                  <summary className="flex list-none items-center gap-2 px-4 py-3 text-[13px] font-medium [&::-webkit-details-marker]:hidden">
                    Skipped files
                    <span className="font-mono text-2xs text-ink-3">{skipped.length}</span>
                    <span className="ml-auto text-2xs text-ink-3 group-open:hidden">Show</span>
                    <span className="ml-auto hidden text-2xs text-ink-3 group-open:inline">Hide</span>
                  </summary>
                  <ul className="divide-y divide-line border-t border-line">
                    {skipped.map((item) => (
                      <li key={item.index} className="flex flex-col gap-0.5 px-4 py-2 md:flex-row md:items-center md:gap-4">
                        <span className="truncate font-mono text-xs md:w-1/2" title={item.path}>{item.path}</span>
                        <span className="flex items-center gap-2 text-xs text-ink-2">
                          {item.skip?.reason === "coming-soon" && (
                            <span className="rounded-full bg-surface-3 px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide text-ink-3">
                              Coming soon
                            </span>
                          )}
                          {item.skip?.detail}
                        </span>
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function OutcomeCell({ outcome, active, onClick }: { outcome: CellOutcome; active: boolean; onClick: () => void }) {
  if (outcome === "pending") {
    return (
      <span className="inline-flex h-6 items-center gap-1.5 px-2 text-2xs text-ink-3">
        <span className="size-1.5 animate-pulse rounded-full bg-ink-3" />
        queued
      </span>
    );
  }
  const tone = outcome === "error" ? null : VERDICTS[outcome].tone;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`inline-flex h-6 items-center gap-1.5 rounded-full px-2 text-2xs font-semibold uppercase tracking-[0.05em] transition ${
        tone ? `${TONE_TINT[tone]} ${TONE_TEXT[tone]}` : "bg-surface-3 text-ink-2"
      } ${active ? "outline-2 outline-offset-1 outline-ink" : "hover:brightness-95"}`}
    >
      <span className={`size-1.5 rounded-full ${tone ? TONE_BG[tone] : "bg-ink-3"}`} />
      {outcome === "error" ? "Error" : VERDICTS[outcome].label}
    </button>
  );
}
