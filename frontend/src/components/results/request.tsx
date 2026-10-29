import { ArrowRight } from "lucide-react";
import type { ReactNode } from "react";

import type { Header } from "@/lib/contract";

export interface RequestShape {
  principal: string;
  action: string;
  path: string;
  host: string;
  scheme: string;
  sni: string;
  headers: Header[];
  source_ip: string;
}

// Every value shown is the solver's concrete witness, as the engine reported
// it. The only generalization is the engine's own: an empty method means the
// witness holds for any method (it prints "<any-method>"). Nothing is labelled
// unconstrained, because the frontend cannot know which values the model's
// constraints pinned (an IP-restricted route, say, pins the source address).
function AnyMethod() {
  return (
    <span className="text-ink-3" title="The engine reports this witness for any method.">
      {"<any-method>"}
    </span>
  );
}

function Empty() {
  return (
    <span className="text-ink-3" title="This value is empty in the solver's witness.">
      (empty)
    </span>
  );
}

/** A solver witness rendered as the HTTP request it stands for. */
export function RequestLine({ request }: { request: RequestShape }) {
  const anonymous = request.principal === "anonymous";
  return (
    <div className="overflow-hidden rounded-lg border border-line bg-surface-2">
      <div className="scrollbar-thin overflow-x-auto px-3.5 py-3 font-mono text-[12.5px] leading-6">
        <div className="whitespace-nowrap">
          {request.action ? <span className="font-semibold text-ink">{request.action}</span> : <AnyMethod />}{" "}
          <span className="text-ink">{request.path || "/"}</span>{" "}
          <span className="text-ink-3">{request.scheme ? `${request.scheme.toUpperCase()}/1.1` : "HTTP/1.1"}</span>
        </div>
        <div className="whitespace-nowrap">
          <span className="text-ink-3">Host:</span> {request.host ? <span className="text-ink-2">{request.host}</span> : <Empty />}
        </div>
        {request.headers.map((header) => (
          <div key={`${header.name}:${header.value}`} className="whitespace-nowrap">
            <span className="text-ink-3">{header.name}:</span> <span className="text-ink-2">{header.value}</span>
          </div>
        ))}
        {!anonymous && (
          <div className="whitespace-nowrap">
            <span className="text-ink-3">Authorization:</span> <span className="text-ink-2">‹valid credential›</span>
          </div>
        )}
      </div>
      <dl className="flex flex-wrap gap-x-5 gap-y-1 border-t border-line px-3.5 py-2 text-2xs">
        <Meta label="Principal">
          <span className="text-ink">{request.principal}</span>
        </Meta>
        <Meta label="Scheme">{request.scheme || <Empty />}</Meta>
        {request.sni && <Meta label="SNI">{request.sni}</Meta>}
        <Meta label="Source">{request.source_ip}</Meta>
      </dl>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <dt className="text-ink-3">{label}</dt>
      <dd className="font-mono text-ink-2">{children}</dd>
    </div>
  );
}

export function TraceStep({ label, value, strong }: { label: string; value: ReactNode; strong?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-2xs text-ink-3">{label}</p>
      <p className={`truncate font-mono text-[12.5px] ${strong ? "font-semibold" : "text-ink"}`}>{value}</p>
    </div>
  );
}

export function Trace({ steps }: { steps: ReactNode[] }) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-line px-3.5 py-2.5">
      {steps.map((step, index) => (
        <div key={index} className="flex min-w-0 items-center gap-3">
          {index > 0 && <ArrowRight className="size-3.5 shrink-0 text-ink-3" />}
          {step}
        </div>
      ))}
    </div>
  );
}
