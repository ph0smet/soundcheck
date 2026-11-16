"use client";

import { ChevronDown, CircleStop, FileCheck2, LockKeyhole, Play, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import type { EngineFailure } from "@/lib/api";
import { RBAC_MODES, type RbacExample, type RbacMode, type RbacReview, type RbacReviewResponse, type RbacRunResponse } from "@/lib/rbac/api";
import { contextKey, MODE_DESCRIPTIONS, MODE_LABELS, RequestEpoch, runKey } from "@/lib/rbac/presentation";

import { Failure, Idle, OfflineHint, StaleNotice } from "../results/states";
import { engineReady, useEngine } from "../shell/engine-status";
import { Button, CodeBlock, Eyebrow, Kbd, PageHeader, Panel } from "../ui";
import { RbacDocument } from "./document";
import { RbacProfileView, RbacResult } from "./result";

type ReviewState = { status: "idle" } | { status: "running" } | { status: "failed"; failure: EngineFailure } | { status: "ready"; key: string; review: RbacReview };
type RunState = { status: "idle" } | { status: "running"; key: string } | { status: "done"; key: string; response: RbacRunResponse };

const requestFailure = (): EngineFailure => ({ ok: false, stage: "engine", exitCode: null, message: "The request to the local web server failed. No result was accepted." });

export function RbacWorkspace({ examples }: { examples: RbacExample[] }) {
  const starter = examples.find((item) => item.mode === "sequence") ?? examples[0];
  const [mode, setMode] = useState<RbacMode>(starter?.mode ?? "verify");
  const [contract, setContract] = useState(starter?.contract ?? "");
  const [baseline, setBaseline] = useState(starter?.baseline ?? "");
  const [candidate, setCandidate] = useState(starter?.candidate ?? "");
  const [example, setExample] = useState<RbacExample | null>(starter ?? null);
  const [inputTab, setInputTab] = useState<"contract" | "baseline">("contract");
  const [review, setReview] = useState<ReviewState>({ status: "idle" });
  const [locked, setLocked] = useState(false);
  const [run, setRun] = useState<RunState>({ status: "idle" });
  const epochs = useRef(new RequestEpoch());
  const controller = useRef<AbortController | null>(null);
  const { status } = useEngine();
  const ready = engineReady(status);
  const needsBaseline = mode !== "verify";
  const busy = review.status === "running" || run.status === "running";
  const key = contextKey(mode, contract, baseline);
  const currentRunKey = runKey(mode, contract, baseline, candidate);
  const currentReview = review.status === "ready" && review.key === key ? review.review : null;
  const canRun = ready && locked && currentReview !== null && candidate.trim() !== "" && !busy;
  const stale = run.status === "done" && run.key !== currentRunKey;

  const resetContext = useCallback(() => {
    epochs.current.invalidate();
    controller.current?.abort();
    setLocked(false);
    setReview({ status: "idle" });
    setRun({ status: "idle" });
  }, []);

  useEffect(() => () => {
    epochs.current.invalidate();
    controller.current?.abort();
  }, []);

  const reviewInputs = async () => {
    if (!ready || busy) return;
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    const epoch = epochs.current.begin();
    const requestedKey = key;
    setReview({ status: "running" });
    setLocked(false);
    setRun({ status: "idle" });
    try {
      const response = await fetch("/api/rbac/review", {
        method: "POST", headers: { "content-type": "application/json" }, signal: abort.signal,
        body: JSON.stringify({ mode, contract, ...(needsBaseline ? { baseline } : {}) }),
      });
      const body = await response.json() as RbacReviewResponse;
      if (!epochs.current.accepts(epoch)) return;
      setReview(body.ok ? { status: "ready", key: requestedKey, review: body.review } : { status: "failed", failure: body });
    } catch (error) {
      if (!epochs.current.accepts(epoch) || (error as Error).name === "AbortError") return;
      setReview({ status: "failed", failure: requestFailure() });
    }
  };

  const execute = useCallback(async () => {
    if (!canRun || !currentReview) return;
    controller.current?.abort();
    const abort = new AbortController();
    controller.current = abort;
    const epoch = epochs.current.begin();
    const requestedKey = currentRunKey;
    setRun({ status: "running", key: requestedKey });
    try {
      const response = await fetch("/api/rbac/run", {
        method: "POST", headers: { "content-type": "application/json" }, signal: abort.signal,
        body: JSON.stringify({ mode, contract, candidate, ...(needsBaseline ? { baseline } : {}), reviewed: {
          contractSha256: currentReview.contractSha256, baselineSha256: currentReview.baselineSha256,
        } }),
      });
      const body = await response.json() as RbacRunResponse;
      if (!epochs.current.accepts(epoch)) return;
      setRun({ status: "done", key: requestedKey, response: body });
    } catch (error) {
      if (!epochs.current.accepts(epoch) || (error as Error).name === "AbortError") return;
      setRun({ status: "done", key: requestedKey, response: requestFailure() });
    }
  }, [canRun, currentReview, currentRunKey, mode, contract, candidate, needsBaseline, baseline]);

  const cancel = () => {
    epochs.current.invalidate();
    controller.current?.abort();
    const failure: EngineFailure = { ok: false, stage: "cancelled", exitCode: null, message: "This request was cancelled. No result from it will be accepted." };
    if (review.status === "running") setReview({ status: "failed", failure });
    if (run.status === "running") setRun({ status: "done", key: run.key, response: failure });
  };

  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && canRun) {
        event.preventDefault(); void execute();
      }
    };
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, [execute, canRun]);

  const loadExample = (selected: RbacExample) => {
    resetContext(); setMode(selected.mode); setContract(selected.contract); setBaseline(selected.baseline ?? "");
    setCandidate(selected.candidate); setExample(selected); setInputTab("contract");
  };

  return (
    <div className="flex min-h-dvh flex-col">
      <PageHeader title="Kubernetes RBAC" description="Review frozen intent, verify a policy change, and inspect access throughout a migration."
        actions={busy ? <Button onClick={cancel}><CircleStop className="size-3.5" /> Cancel</Button> : (
          <Button variant="primary" onClick={() => void execute()} disabled={!canRun} title={!locked ? "Review and lock the contract first" : undefined}>
            <Play className="size-3.5 fill-current" /> Run verification <Kbd>Ctrl ↵</Kbd>
          </Button>
        )} />

      <div className="space-y-5 p-4 md:p-6">
        <section aria-label="RBAC workflow" className="rounded-xl border border-line bg-surface p-3 shadow-card sm:p-4">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
            <div role="group" aria-label="Verification mode" className="grid grid-cols-2 gap-1 rounded-lg border border-line bg-surface-2 p-1 sm:grid-cols-4">
              {RBAC_MODES.map((value) => <button key={value} type="button" aria-pressed={mode === value} onClick={() => {
                if (mode === value) return;
                resetContext(); setMode(value); setExample(null); setInputTab("contract");
              }} className={`rounded-md px-3 py-2 text-xs font-medium transition ${mode === value ? "bg-surface text-ink shadow-card" : "text-ink-2 hover:bg-surface-3"}`}>{MODE_LABELS[value]}</button>)}
            </div>
            <p className="min-w-0 flex-1 text-xs leading-relaxed text-ink-2">{MODE_DESCRIPTIONS[mode]}</p>
            {examples.length > 0 && <div className="relative shrink-0">
              <select aria-label="Load synthetic RBAC example" value="" onChange={(event) => {
                const selected = examples.find((item) => item.id === event.target.value); if (selected) loadExample(selected);
              }} className="h-9 w-full max-w-full appearance-none rounded-md border border-line bg-surface pl-3 pr-8 text-xs text-ink outline-none hover:border-line-strong xl:max-w-56">
                <option value="" disabled>Load synthetic example</option>
                {RBAC_MODES.map((value) => <optgroup key={value} label={MODE_LABELS[value]}>{examples.filter((item) => item.mode === value).map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</optgroup>)}
              </select><ChevronDown className="pointer-events-none absolute right-2.5 top-3 size-3.5 text-ink-3" />
            </div>}
          </div>
          {example && <p className="mt-3 border-t border-line pt-3 text-xs leading-relaxed text-ink-3"><span className="font-medium text-ink-2">Synthetic example: {example.label}.</span> {example.description}</p>}
        </section>

        <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
          <div className="min-w-0 space-y-4">
            <Panel title={<span className="flex items-center gap-2"><span className="flex size-5 items-center justify-center rounded-full border border-line-strong text-2xs">1</span> Review the fixed inputs</span>}
              actions={locked ? <Button size="sm" onClick={resetContext}><RotateCcw className="size-3" /> Replace inputs</Button> : undefined} bodyClassName="space-y-3 p-3 sm:p-4">
              {locked ? <div className="flex items-start gap-2.5 rounded-lg border border-line bg-surface-2 p-3"><LockKeyhole className="mt-0.5 size-4 shrink-0 text-ink-2" /><p className="text-xs leading-relaxed text-ink-2">The contract{needsBaseline ? " and baseline are" : " is"} locked for this review. Edit the candidate below, or replace these inputs to start a new review.</p></div> : <p className="text-xs leading-relaxed text-ink-2">Supply independently reviewed intent{needsBaseline ? " and the complete original snapshot" : ""}. Structural review checks the contract; it does not prove access.</p>}
              <div role="group" aria-label="Fixed input document" className="flex gap-2">
                <Button size="sm" variant={inputTab === "contract" ? "secondary" : "ghost"} aria-pressed={inputTab === "contract"} onClick={() => setInputTab("contract")}>Contract</Button>
                {needsBaseline && <Button size="sm" variant={inputTab === "baseline" ? "secondary" : "ghost"} aria-pressed={inputTab === "baseline"} onClick={() => setInputTab("baseline")}>Baseline</Button>}
              </div>
              {inputTab === "contract" || !needsBaseline ? <RbacDocument key={`${mode}:contract`} name="contract.json" description="Frozen requirements, trusted identities and approved change scope." value={contract} readOnly={locked} onChange={(value) => { resetContext(); setContract(value); setExample(null); }} className="h-72" /> : <RbacDocument key={`${mode}:baseline`} name="baseline.json" description="The complete original RBAC snapshot used for authorization and preservation." value={baseline} readOnly={locked} onChange={(value) => { resetContext(); setBaseline(value); setExample(null); }} className="h-72" />}
              {!locked && <Button onClick={() => void reviewInputs()} disabled={!ready || busy || !contract.trim() || (needsBaseline && !baseline.trim())}><FileCheck2 className="size-3.5" /> {review.status === "running" ? "Reviewing inputs…" : "Review inputs"}</Button>}
              {review.status === "running" && <p role="status" className="text-xs text-ink-3">Reading the contract and its assurance boundary. No verification is running.</p>}
              {review.status === "failed" && <Failure failure={review.failure} />}
              {currentReview && <div className="space-y-3 border-t border-line pt-3">
                <div className="flex flex-wrap items-center gap-2"><Eyebrow>Structural review only</Eyebrow><span className="text-2xs text-ink-3">No access verdict</span></div>
                <details open={!locked}><summary className="cursor-pointer text-xs font-medium text-ink-2">Requirements, identities and approved scope</summary><CodeBlock className="mt-2 max-h-80 whitespace-pre-wrap break-words">{currentReview.reviewText}</CodeBlock></details>
                <RbacProfileView profile={currentReview.profile} accessProfile={currentReview.accessProfile} />
                {!locked && <Button variant="primary" onClick={() => setLocked(true)}><LockKeyhole className="size-3.5" /> Lock reviewed inputs</Button>}
              </div>}
            </Panel>

            <div className="space-y-2">
              <div className="flex items-center gap-2 px-1"><span className="flex size-5 items-center justify-center rounded-full border border-line-strong text-2xs">2</span><h2 className="text-[13px] font-semibold">{mode === "verify" ? "Check the snapshot" : "Edit the candidate"}</h2></div>
              <RbacDocument key={`${mode}:candidate`} name={mode === "verify" ? "snapshot.json" : "candidate.json"} description="A complete strict RBAC List. Uploading a partial manifest does not establish the assumed inventory." value={candidate} onChange={(value) => { setCandidate(value); setExample(null); }} className="h-[420px]" />
              <p className="px-1 text-2xs text-ink-3">Documents are not saved to browser storage. The contract and baseline are sent to the local verifier for review; the candidate is also sent when you run verification.</p>
            </div>
          </div>

          <Panel title={<span className="flex items-center gap-2"><span className="flex size-5 items-center justify-center rounded-full border border-line-strong text-2xs">3</span> Verification result</span>} bodyClassName="space-y-4 p-3 sm:p-4">
            {stale && <StaleNotice onRerun={() => void execute()} disabled={!canRun} />}
            <div className={stale ? "opacity-60" : ""}>
              {run.status === "idle" && (ready ? <Idle eyebrow={locked ? "Ready to verify" : "Review before running"}>{locked ? "Run the candidate against the locked inputs. Every result remains attached to the exact documents used for that run." : "Review the contract and lock the fixed inputs, then run verification. A structural review is never a passing result."}</Idle> : <OfflineHint />)}
              {run.status === "running" && <div role="status" aria-live="polite" className="rounded-lg border border-line bg-surface-2 p-5"><p className="text-sm font-medium">Checking {MODE_LABELS[mode].toLowerCase()}…</p><p className="mt-2 text-xs leading-relaxed text-ink-2">The engine is checking the frozen obligations. A result appears only after its report, exit code and evidence agree.</p><div className="relative mt-4 h-0.5 overflow-hidden rounded-full bg-surface-3"><span className="animate-sweep absolute inset-y-0 w-2/5 bg-ink" /></div></div>}
              {run.status === "done" && (run.response.ok ? <RbacResult response={run.response} /> : <Failure failure={run.response} />)}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
