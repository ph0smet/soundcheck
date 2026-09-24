"use client";

import { RefreshCw } from "lucide-react";
import { createContext, use, useCallback, useEffect, useState, type ReactNode } from "react";

import type { EngineStatus } from "@/lib/api";

interface EngineContextValue {
  status: EngineStatus | null;
  refresh: () => void;
  checking: boolean;
}

const EngineContext = createContext<EngineContextValue>({
  status: null,
  refresh: () => {},
  checking: true,
});

export function EngineProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [checking, setChecking] = useState(true);

  const load = useCallback(() => {
    fetch("/api/engine", { cache: "no-store" })
      .then((response) => response.json() as Promise<EngineStatus>)
      .then(setStatus)
      .catch(() =>
        setStatus({
          available: false,
          source: "none",
          label: "Unreachable",
          profile: null,
          solver: { available: false, version: null },
          message: "The web server did not respond.",
        }),
      )
      .finally(() => setChecking(false));
  }, []);

  const refresh = useCallback(() => {
    setChecking(true);
    load();
  }, [load]);

  useEffect(load, [load]);

  return <EngineContext value={{ status, refresh, checking }}>{children}</EngineContext>;
}

export function useEngine() {
  return use(EngineContext);
}

export function engineReady(status: EngineStatus | null) {
  return Boolean(status?.available && status.solver.available);
}

export function EngineStatusCard() {
  const { status, refresh, checking } = useEngine();
  const ready = engineReady(status);
  const partial = status?.available && !status.solver.available;
  const tone = checking && !status ? "bg-ink-3" : ready ? "bg-proved" : partial ? "bg-vacuous" : "bg-violated";
  const title = !status ? "Checking engine" : ready ? "Engine ready" : partial ? "Solver missing" : "Engine offline";

  return (
    <details className="group rounded-lg border border-line bg-surface-2 text-xs open:bg-surface open:shadow-card">
      <summary className="flex list-none items-center gap-2.5 px-3 py-2.5 [&::-webkit-details-marker]:hidden">
        <span className="relative flex size-2">
          {ready && <span className="absolute inset-0 animate-ping rounded-full bg-proved opacity-30 motion-reduce:hidden" />}
          <span className={`relative size-2 rounded-full ${tone}`} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block font-medium text-ink">{title}</span>
          <span className="block truncate font-mono text-2xs text-ink-3">
            {status?.profile ?? status?.label ?? "…"}
          </span>
        </span>
      </summary>
      {status && (
        <div className="space-y-2 border-t border-line px-3 py-2.5">
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-2xs">
            <dt className="text-ink-3">Engine</dt>
            <dd className="truncate font-mono text-ink-2" title={status.label}>{status.label}</dd>
            <dt className="text-ink-3">Solver</dt>
            <dd className="truncate font-mono text-ink-2">
              {status.solver.available
                ? status.solver.version
                  ? `z3 ${status.solver.version}`
                  : "z3 via engine"
                : "z3 unavailable"}
            </dd>
          </dl>
          {status.message && <p className="text-2xs leading-relaxed text-ink-2">{status.message}</p>}
          <button
            type="button"
            onClick={refresh}
            disabled={checking}
            className="inline-flex items-center gap-1.5 text-2xs font-medium text-ink-2 hover:text-ink disabled:opacity-50"
          >
            <RefreshCw className={`size-3 ${checking ? "animate-spin" : ""}`} />
            Recheck
          </button>
        </div>
      )}
    </details>
  );
}
