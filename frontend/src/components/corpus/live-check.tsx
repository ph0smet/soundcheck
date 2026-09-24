"use client";

import { Check, FlaskConical, X } from "lucide-react";
import { useState } from "react";

import type { PropertySpec, VerifyResponse } from "@/lib/api";
import type { VerifyReport } from "@/lib/contract";

import { Failure, Running } from "../results/states";
import { formatDuration } from "../results/verify-result";
import { engineReady, useEngine } from "../shell/engine-status";
import { Button, Panel } from "../ui";

// Witness strings are solver-chosen and legitimately vary between Z3 versions,
// so, like bench/corpus.ml, only the deterministic fields are compared.
const MASKED = new Set(["path", "action", "source_ip", "host", "scheme", "sni"]);

function stable(value: unknown): string {
  return JSON.stringify(value, (key, inner) => (MASKED.has(key) ? "<witness>" : inner));
}

function checks(golden: VerifyReport, live: VerifyReport) {
  const ce = (report: VerifyReport) => report.counterexample;
  return [
    { label: "Verdict", golden: golden.result, live: live.result },
    { label: "Property", golden: golden.property, live: live.property },
    { label: "Schema version", golden: String(golden.schema_version), live: String(live.schema_version) },
    { label: "Assurance", golden: stable(golden.assurance), live: stable(live.assurance), display: [golden.assurance?.status, live.assurance?.status] },
    { label: "Clause", golden: golden.clause?.name ?? "none", live: live.clause?.name ?? "none" },
    { label: "Route", golden: ce(golden)?.route ?? "none", live: ce(live)?.route ?? "none" },
    { label: "Service", golden: ce(golden)?.service ?? "none", live: ce(live)?.service ?? "none" },
    { label: "Shadowed route", golden: ce(golden)?.shadowed_route ?? "none", live: ce(live)?.shadowed_route ?? "none" },
    { label: "Full report", golden: stable(golden), live: stable(live), display: ["witness masked", "witness masked"] },
  ];
}

export function LiveCheck({ spec, config, golden }: { spec: PropertySpec; config: string; golden: VerifyReport }) {
  const [state, setState] = useState<{ status: "idle" } | { status: "running" } | { status: "done"; response: VerifyResponse }>({ status: "idle" });
  const { status } = useEngine();
  const ready = engineReady(status);

  async function run() {
    setState({ status: "running" });
    try {
      const response = await fetch("/api/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ config, spec }),
      });
      setState({ status: "done", response: (await response.json()) as VerifyResponse });
    } catch {
      setState({ status: "done", response: { ok: false, stage: "engine", exitCode: null, message: "The request to the web server failed." } });
    }
  }

  const rows = state.status === "done" && state.response.ok ? checks(golden, state.response.report) : null;
  const passed = rows?.every((row) => row.golden === row.live);

  return (
    <Panel
      title="Regression check"
      actions={
        <Button size="sm" onClick={() => void run()} disabled={!ready || state.status === "running"} title={ready ? undefined : "Connect the engine to run"}>
          <FlaskConical className="size-3.5" />
          Run against engine
        </Button>
      }
      bodyClassName="p-4"
    >
      {state.status === "idle" && (
        <p className="text-[13px] leading-relaxed text-ink-2">
          Re-run this case on the connected engine and diff it against the golden. Solver-chosen witness strings are masked,
          the same rule the <code className="font-mono text-ink">dune test</code> gate applies.
        </p>
      )}
      {state.status === "running" && <Running label="Re-verifying" />}
      {state.status === "done" && !state.response.ok && <Failure failure={state.response} />}
      {rows && state.status === "done" && state.response.ok && (
        <div className="animate-reveal space-y-3">
          <div className="flex items-center gap-2">
            <span className={`flex size-6 items-center justify-center rounded-full ${passed ? "tint-proved text-proved" : "tint-violated text-violated"}`}>
              {passed ? <Check className="size-3.5" /> : <X className="size-3.5" />}
            </span>
            <p className="text-[13.5px] font-medium">{passed ? "Matches the golden" : "Diverges from the golden"}</p>
            <span className="ml-auto font-mono text-2xs text-ink-3">{formatDuration(state.response.durationMs)}</span>
          </div>
          <div className="overflow-hidden rounded-lg border border-line">
            <table className="w-full table-fixed text-[12.5px]">
              <thead className="bg-surface-2 text-left text-2xs text-ink-3">
                <tr>
                  <th scope="col" className="w-32 px-3 py-1.5 font-medium">Field</th>
                  <th scope="col" className="px-3 py-1.5 font-medium">Golden</th>
                  <th scope="col" className="px-3 py-1.5 font-medium">Live</th>
                  <th scope="col" className="w-8 px-3 py-1.5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map((row) => {
                  const ok = row.golden === row.live;
                  const [g, l] = row.display ?? [row.golden, row.live];
                  return (
                    <tr key={row.label} className={ok ? undefined : "tint-violated"}>
                      <th scope="row" className="px-3 py-1.5 text-left text-xs font-normal text-ink-2">{row.label}</th>
                      <td className="truncate px-3 py-1.5 font-mono text-ink-2" title={g}>{g}</td>
                      <td className="truncate px-3 py-1.5 font-mono text-ink" title={l}>{l}</td>
                      <td className="px-3 py-1.5">
                        {ok ? <Check className="size-3.5 text-proved" /> : <X className="size-3.5 text-violated" />}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Panel>
  );
}
