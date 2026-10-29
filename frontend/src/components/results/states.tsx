"use client";

import {
  AlertTriangle,
  Ban,
  FileWarning,
  Hourglass,
  PlugZap,
  RotateCcw,
  ShieldAlert,
  SlidersHorizontal,
  TerminalSquare,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

import type { EngineFailure } from "@/lib/api";

import { Button, CodeBlock, Eyebrow } from "../ui";

export function Running({ label }: { label: string }) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const started = performance.now();
    const timer = setInterval(() => setElapsed(performance.now() - started), 100);
    return () => clearInterval(timer);
  }, []);
  return (
    <div role="status" aria-live="polite" className="rounded-lg border border-line bg-surface px-5 py-5">
      <div className="flex items-center gap-3">
        <p className="font-mono text-[13px] font-semibold uppercase tracking-[0.06em] text-ink">{label}</p>
        <span className="ml-auto font-mono text-2xs tabular-nums text-ink-3">{(elapsed / 1000).toFixed(1)} s</span>
      </div>
      <div className="relative mt-3 h-0.5 overflow-hidden rounded-full bg-surface-3">
        <span className="animate-sweep absolute inset-y-0 w-2/5 rounded-full bg-ink" />
      </div>
      <p className="mt-3 text-[13px] text-ink-2">
        Lowering the config, encoding the negated property as SMT-LIB2 and asking Z3 for a witness.
      </p>
    </div>
  );
}

const STAGES: Record<EngineFailure["stage"], { title: string; icon: typeof FileWarning }> = {
  parse: { title: "The config could not be parsed", icon: FileWarning },
  usage: { title: "The engine rejected this request", icon: SlidersHorizontal },
  input: { title: "Check the inputs", icon: SlidersHorizontal },
  engine: { title: "The engine did not produce a result", icon: PlugZap },
  protocol: { title: "The engine's output was rejected", icon: ShieldAlert },
  busy: { title: "The verifier is busy", icon: Hourglass },
  cancelled: { title: "The run was cancelled", icon: Ban },
};

export function Failure({ failure }: { failure: EngineFailure }) {
  const { title, icon: Icon } = STAGES[failure.stage];
  return (
    <div role="alert" className="animate-reveal space-y-4 rounded-lg border border-line bg-surface p-5">
      <div className="flex items-start gap-3">
        <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-surface-3">
          <Icon className="size-4 text-ink-2" />
        </span>
        <div className="min-w-0">
          <p className="text-[14px] font-semibold">{title}</p>
          <p className="mt-0.5 text-[13px] text-ink-2">
            {failure.stage === "parse"
              ? "This is a tool error, not a verification outcome. Fix the YAML and run again."
              : failure.stage === "protocol"
                ? "The output failed validation against the engine's versioned schema, so it is not shown as a verdict. Nothing was verified."
                : failure.stage === "engine" || failure.stage === "cancelled"
                  ? "Nothing was verified."
                  : failure.stage === "busy"
                    ? "Too many runs are queued. Nothing was verified; try again shortly."
                    : "No verification was attempted."}
            {failure.exitCode !== null && ` Exit code ${failure.exitCode}.`}
          </p>
        </div>
      </div>
      <CodeBlock className="whitespace-pre-wrap">{failure.message}</CodeBlock>
      {failure.command && (
        <p className="font-mono text-2xs text-ink-3">$ {failure.command}</p>
      )}
    </div>
  );
}

/**
 * Shown above a result whose inputs have since changed. The result still
 * describes the previous inputs, so it must never read as current.
 */
export function StaleNotice({ onRerun, disabled }: { onRerun: () => void; disabled: boolean }) {
  return (
    <div
      role="status"
      className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-vacuous/40 bg-vacuous/10 px-3 py-2 text-[13px]"
    >
      <AlertTriangle className="size-4 shrink-0 text-vacuous" />
      <span className="min-w-0 flex-1 text-ink">
        The inputs changed after this result. It describes the previous inputs, not the current ones.
      </span>
      <Button size="sm" onClick={onRerun} disabled={disabled}>
        <RotateCcw className="size-3.5" />
        Re-run
      </Button>
    </div>
  );
}

export function OfflineHint() {
  return (
    <div className="rounded-lg border border-dashed border-line-strong p-4">
      <div className="flex items-center gap-2">
        <TerminalSquare className="size-4 text-ink-2" />
        <p className="text-[13px] font-medium">Connect the engine</p>
      </div>
      <p className="mt-1.5 text-[13px] leading-relaxed text-ink-2">
        Live runs need the OCaml engine and the Z3 solver. Build it once from the repository root, or point{" "}
        <code className="font-mono text-ink">SOUNDCHECK_BIN</code> at an existing binary.
      </p>
      <CodeBlock className="mt-3">{`opam install dune yaml && brew install z3   # or: apt install z3
dune build                                  # from the repository root`}</CodeBlock>
    </div>
  );
}

export function Idle({ eyebrow, children }: { eyebrow: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line-strong px-5 py-6">
      <Eyebrow>{eyebrow}</Eyebrow>
      <div className="mt-2 text-[13px] leading-relaxed text-ink-2">{children}</div>
    </div>
  );
}
