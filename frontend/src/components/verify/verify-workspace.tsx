"use client";

import { Play, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { PropertySpec, Sample, Spec, VerifyResponse } from "@/lib/api";
import { EMPTY_CONTRACT } from "@/lib/contract-yaml";

import type { LineFlag } from "../code-editor";
import { DocumentPanel } from "../document-panel";
import { Failure, Idle, OfflineHint, Running } from "../results/states";
import { VerifyOutcome } from "../results/verify-result";
import { engineReady, useEngine } from "../shell/engine-status";
import { Button, Kbd, PageHeader, Panel } from "../ui";
import { resolveSpec, SpecPanel, type SpecState } from "./spec-panel";

const DRAFT_KEY = "soundcheck-verify-draft";

export interface VerifyInitial {
  config: string;
  spec: PropertySpec;
  origin: string | null;
}

function initialState(spec: PropertySpec): SpecState {
  return {
    mode: "property",
    property: spec,
    contractSource: "builder",
    contractDraft: EMPTY_CONTRACT,
    contractText: "",
  };
}

type RunState =
  | { status: "idle" }
  | { status: "running" }
  | { status: "done"; response: VerifyResponse; key: string };

export function VerifyWorkspace({
  initial,
  samples,
  contracts,
}: {
  initial: VerifyInitial;
  samples: Sample[];
  contracts: Sample[];
}) {
  const [config, setConfig] = useState(initial.config);
  const [spec, setSpec] = useState<SpecState>(() => initialState(initial.spec));
  const [origin, setOrigin] = useState(initial.origin);
  const [run, setRun] = useState<RunState>({ status: "idle" });
  const [specError, setSpecError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);
  const { status } = useEngine();
  const ready = engineReady(status);

  // Restore the last draft, unless a specific case was requested via the URL.
  useEffect(() => {
    if (initial.origin?.startsWith("case:")) return;
    try {
      const raw = localStorage.getItem(DRAFT_KEY);
      if (!raw) return;
      const draft = JSON.parse(raw) as { config: string; spec: SpecState };
      // eslint-disable-next-line react-hooks/set-state-in-effect -- one-time hydration from storage
      setConfig(draft.config);
      setSpec(draft.spec);
      setOrigin(null);
    } catch {}
  }, [initial.origin]);

  useEffect(() => {
    const timer = setTimeout(() => {
      try {
        localStorage.setItem(DRAFT_KEY, JSON.stringify({ config, spec }));
      } catch {}
    }, 400);
    return () => clearTimeout(timer);
  }, [config, spec]);

  const resolved = useMemo(() => resolveSpec(spec), [spec]);
  const inputKey = JSON.stringify({ config, spec: "spec" in resolved ? resolved.spec : null });

  const execute = useCallback(async () => {
    if ("error" in resolved) {
      setSpecError(resolved.error);
      return;
    }
    setSpecError(null);
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    setRun({ status: "running" });
    const key = inputKey;
    try {
      const response = await fetch("/api/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ config, spec: resolved.spec satisfies Spec }),
        signal: controller.signal,
      });
      setRun({ status: "done", response: (await response.json()) as VerifyResponse, key });
    } catch (error) {
      if ((error as Error).name === "AbortError") return;
      setRun({
        status: "done",
        key,
        response: { ok: false, stage: "engine", exitCode: null, message: "The request to the web server failed." },
      });
    }
  }, [config, resolved, inputKey]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        event.preventDefault();
        if (ready && config.trim()) void execute();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [execute, ready, config]);

  const flags = useMemo<LineFlag[]>(() => {
    if (run.status !== "done" || !run.response.ok) return [];
    const ce = run.response.report.counterexample;
    if (!ce) return [];
    const list: LineFlag[] = [];
    if (ce.route) list.push({ term: ce.route, kind: "primary" });
    if (ce.shadowed_route) list.push({ term: ce.shadowed_route, kind: "secondary" });
    return list;
  }, [run]);

  const stale = run.status === "done" && run.key !== inputKey;

  return (
    <div className="flex min-h-dvh flex-col">
      <PageHeader
        title="Verify"
        description="Prove a security invariant over every request a Kong config can receive, or get the exact request that breaks it."
        actions={
          <Button
            variant="primary"
            onClick={() => void execute()}
            disabled={!ready || !config.trim() || run.status === "running"}
            title={ready ? undefined : "Connect the engine to run verification"}
          >
            <Play className="size-3.5 fill-current" />
            {run.status === "running" ? "Verifying" : "Verify"}
            <Kbd>Ctrl ↵</Kbd>
          </Button>
        }
      />

      <div className="grid flex-1 gap-4 p-4 md:p-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
        <DocumentPanel
          name="config.yaml"
          badge={origin && <span className="truncate text-2xs text-ink-3">from {origin.replace(/^\w+:/, "")}</span>}
          value={config}
          onChange={(value) => {
            setConfig(value);
            setOrigin(null);
          }}
          samples={samples}
          flags={flags}
          className="h-[520px] xl:sticky xl:top-6 xl:h-[calc(100dvh-10.5rem)]"
          footer={flags.length > 0 && <span className="text-violated">counterexample route highlighted</span>}
        />

        <div className="min-w-0 space-y-4">
          <SpecPanel state={spec} onChange={setSpec} contracts={contracts} />
          {specError && <p className="text-xs text-violated">{specError}</p>}

          <Panel
            title="Result"
            actions={
              stale && (
                <Button size="sm" variant="ghost" onClick={() => void execute()} disabled={!ready}>
                  <RotateCcw className="size-3.5" />
                  Inputs changed, re-run
                </Button>
              )
            }
            bodyClassName="p-4"
          >
            <div className={stale ? "opacity-60 transition-opacity" : "transition-opacity"}>
              {run.status === "idle" &&
                (ready ? (
                  <Idle eyebrow="Ready">
                    Choose a property or a frozen contract, then run <span className="font-medium text-ink">Verify</span>.
                    The result is one of five verdicts: proved, violated, vacuous, inconsistent or unknown. Each maps to a
                    distinct exit code for CI.
                  </Idle>
                ) : (
                  <OfflineHint />
                ))}
              {run.status === "running" && <Running label="Solving" />}
              {run.status === "done" &&
                (run.response.ok ? (
                  <VerifyOutcome
                    report={run.response.report}
                    exitCode={run.response.exitCode}
                    durationMs={run.response.durationMs}
                    command={run.response.command}
                  />
                ) : (
                  <Failure failure={run.response} />
                ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
