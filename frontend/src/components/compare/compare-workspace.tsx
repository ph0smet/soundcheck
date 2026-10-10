"use client";

import { ArrowLeftRight, GitCompareArrows, Lock } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import type { CompareMode, CompareResponse, Sample } from "@/lib/api";
import { COMPARE_MODE_INFO } from "@/lib/domain";

import { CodeEditor } from "../code-editor";
import { DocumentPanel } from "../document-panel";
import { CompareOutcome } from "../results/compare-result";
import { Failure, Idle, OfflineHint, Running } from "../results/states";
import { engineReady, useEngine } from "../shell/engine-status";
import { Button, Eyebrow, Kbd, PageHeader, Panel, Segmented } from "../ui";

export interface ComparePreset {
  id: string;
  title: string;
  description: string;
  before: string;
  after: string;
  mode: CompareMode;
  contract: string | null;
}

type RunState =
  | { status: "idle" }
  | { status: "running" }
  | { status: "done"; response: CompareResponse };

export function CompareWorkspace({
  presets,
  samples,
  contracts,
}: {
  presets: ComparePreset[];
  samples: Sample[];
  contracts: Sample[];
}) {
  const first = presets[0];
  const [before, setBefore] = useState(first?.before ?? "");
  const [after, setAfter] = useState(first?.after ?? "");
  const [mode, setMode] = useState<CompareMode>(first?.mode ?? "decision");
  const [bound, setBound] = useState(Boolean(first?.contract));
  const [contract, setContract] = useState(first?.contract ?? contracts[0]?.content ?? "");
  const [activePreset, setActivePreset] = useState<string | null>(first?.id ?? null);
  const [run, setRun] = useState<RunState>({ status: "idle" });
  const resultRef = useRef<HTMLDivElement>(null);
  const { status } = useEngine();
  const ready = engineReady(status);
  const canRun = ready && before.trim() && after.trim() && (!bound || contract.trim()) && run.status !== "running";

  const execute = useCallback(async () => {
    setRun({ status: "running" });
    resultRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    try {
      const response = await fetch("/api/compare", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ before, after, mode, contract: bound ? contract : undefined }),
      });
      setRun({ status: "done", response: (await response.json()) as CompareResponse });
    } catch {
      setRun({
        status: "done",
        response: { ok: false, stage: "engine", exitCode: null, message: "The request to the web server failed." },
      });
    }
  }, [before, after, mode, bound, contract]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter" && canRun) {
        event.preventDefault();
        void execute();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [execute, canRun]);

  function applyPreset(preset: ComparePreset) {
    setBefore(preset.before);
    setAfter(preset.after);
    setMode(preset.mode);
    setBound(Boolean(preset.contract));
    if (preset.contract) setContract(preset.contract);
    setActivePreset(preset.id);
    setRun({ status: "idle" });
  }

  const edited = () => setActivePreset(null);

  return (
    <div className="flex min-h-dvh flex-col">
      <PageHeader
        title="Compare"
        description="Prove two Kong configs make the same security decision for every modeled request, or get the one request that tells them apart."
        actions={
          <Button variant="primary" onClick={() => void execute()} disabled={!canRun}>
            <GitCompareArrows className="size-3.5" />
            {run.status === "running" ? "Comparing" : "Compare"}
            <Kbd>Ctrl ↵</Kbd>
          </Button>
        }
      />

      <div className="space-y-4 p-4 md:p-6">
        {presets.length > 0 && (
          <div className="scrollbar-thin -mx-1 flex gap-2 overflow-x-auto px-1 pb-1">
            {presets.map((preset) => {
              const active = preset.id === activePreset;
              return (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => applyPreset(preset)}
                  aria-pressed={active}
                  className={`w-64 shrink-0 rounded-lg border px-3 py-2.5 text-left transition-colors ${
                    active ? "border-ink bg-surface" : "border-line bg-surface/60 hover:border-line-strong hover:bg-surface"
                  }`}
                >
                  <span className="flex items-center gap-1.5 text-[13px] font-medium">
                    {preset.contract && <Lock className="size-3 text-ink-3" />}
                    {preset.title}
                  </span>
                  <span className="mt-0.5 line-clamp-2 block text-xs leading-snug text-ink-2">{preset.description}</span>
                </button>
              );
            })}
          </div>
        )}

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
          <DocumentPanel
            name="before.yaml"
            value={before}
            onChange={(value) => { setBefore(value); edited(); }}
            samples={samples}
            className="h-[400px]"
          />
          <div className="hidden items-center lg:flex">
            <Button
              variant="ghost"
              size="sm"
              aria-label="Swap before and after"
              title="Swap before and after"
              onClick={() => { setBefore(after); setAfter(before); edited(); }}
            >
              <ArrowLeftRight className="size-4" />
            </Button>
          </div>
          <DocumentPanel
            name="after.yaml"
            value={after}
            onChange={(value) => { setAfter(value); edited(); }}
            samples={samples}
            className="h-[400px]"
          />
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
          <Panel title="Comparison" bodyClassName="divide-y divide-line">
            <div className="space-y-2.5 p-4">
              <Eyebrow>What must be preserved</Eyebrow>
              <div role="radiogroup" aria-label="Comparison mode" className="space-y-1">
                {(Object.keys(COMPARE_MODE_INFO) as CompareMode[]).map((value) => {
                  const info = COMPARE_MODE_INFO[value];
                  const active = value === mode;
                  return (
                    <label
                      key={value}
                      className={`flex cursor-pointer gap-3 rounded-lg border px-3 py-2.5 transition-colors ${
                        active ? "border-ink bg-surface-2" : "border-transparent hover:bg-surface-2"
                      }`}
                    >
                      <input
                        type="radio"
                        name="compare-mode"
                        checked={active}
                        onChange={() => { setMode(value); edited(); }}
                        className="mt-1 size-3.5 shrink-0 accent-[var(--ink)]"
                      />
                      <span>
                        <span className="block text-[13px] font-medium">{info.label}</span>
                        <span className="block text-xs leading-snug text-ink-2">{info.description}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
            <div className="space-y-3 p-4">
              <div className="flex items-center gap-3">
                <div className="min-w-0 flex-1">
                  <p className="text-[13px] font-medium">Bind to a frozen contract</p>
                  <p className="text-xs leading-snug text-ink-2">
                    Verify the replacement against the contract, then prove nothing changed outside its scope.
                  </p>
                </div>
                <Segmented
                  label="Contract binding"
                  size="sm"
                  value={bound ? "on" : "off"}
                  onChange={(value) => { setBound(value === "on"); edited(); }}
                  options={[{ value: "off", label: "Off" }, { value: "on", label: "On" }]}
                />
              </div>
              {bound && (
                <div className="overflow-hidden rounded-lg border border-line">
                  {contracts.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 border-b border-line px-3 py-2">
                      {contracts.map((item) => (
                        <button
                          key={item.id}
                          type="button"
                          onClick={() => { setContract(item.content); edited(); }}
                          className="rounded-md border border-line bg-surface px-2 py-0.5 font-mono text-2xs text-ink-2 hover:border-line-strong hover:text-ink"
                        >
                          {item.label}
                        </button>
                      ))}
                    </div>
                  )}
                  <div className="h-44">
                    <CodeEditor label="Contract YAML" value={contract} onChange={(value) => { setContract(value); edited(); }} />
                  </div>
                </div>
              )}
            </div>
          </Panel>

          <div ref={resultRef} className="min-w-0 scroll-mt-6">
            <Panel title="Result" bodyClassName="p-4">
              {run.status === "idle" &&
                (ready ? (
                  <Idle eyebrow="Ready">
                    Equivalence is attempted only when both configs stay within the assurance profile and route order is
                    resolved. Otherwise the answer is <span className="font-medium text-ink">unknown</span>, never a guess.
                  </Idle>
                ) : (
                  <OfflineHint />
                ))}
              {run.status === "running" && <Running label="Comparing" />}
              {run.status === "done" &&
                (run.response.ok ? (
                  <CompareOutcome
                    report={run.response.report}
                    exitCode={run.response.exitCode}
                    durationMs={run.response.durationMs}
                    command={run.response.command}
                  />
                ) : (
                  <Failure failure={run.response} />
                ))}
            </Panel>
          </div>
        </div>
      </div>
    </div>
  );
}
