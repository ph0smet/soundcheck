"use client";

import { ChevronDown, FileCode2, Upload } from "lucide-react";
import { useId, useRef, type ReactNode } from "react";

import type { Sample } from "@/lib/api";

import { CodeEditor, type LineFlag } from "./code-editor";
import { Button } from "./ui";

export function SamplePicker({
  samples,
  onPick,
  label = "Load sample",
}: {
  samples: Sample[];
  onPick: (sample: Sample) => void;
  label?: string;
}) {
  const groups = [...new Set(samples.map((sample) => sample.group))];
  return (
    <div className="relative">
      <select
        aria-label={label}
        value=""
        onChange={(event) => {
          const sample = samples.find((item) => item.id === event.target.value);
          if (sample) onPick(sample);
        }}
        className="h-7 max-w-40 appearance-none rounded-md border border-line bg-surface pl-2.5 pr-7 text-xs font-medium text-ink shadow-card outline-none transition hover:border-line-strong"
      >
        <option value="" disabled>
          {label}
        </option>
        {groups.map((group) => (
          <optgroup key={group} label={group}>
            {samples
              .filter((sample) => sample.group === group)
              .map((sample) => (
                <option key={sample.id} value={sample.id}>
                  {sample.label}
                </option>
              ))}
          </optgroup>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2 top-1/2 size-3.5 -translate-y-1/2 text-ink-3" />
    </div>
  );
}

export function DocumentPanel({
  name,
  badge,
  value,
  onChange,
  samples,
  flags,
  className = "",
  footer,
}: {
  name: string;
  badge?: ReactNode;
  value: string;
  onChange: (value: string) => void;
  samples?: Sample[];
  flags?: LineFlag[];
  className?: string;
  footer?: ReactNode;
}) {
  const inputId = useId();
  const input = useRef<HTMLInputElement>(null);
  const lines = value ? value.split("\n").length : 0;

  return (
    <section className={`flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-line bg-surface shadow-card ${className}`}>
      <header className="flex min-h-11 items-center gap-2 border-b border-line px-3 py-2">
        <FileCode2 className="size-4 shrink-0 text-ink-3" />
        <h2 className="truncate font-mono text-[12.5px] font-medium">{name}</h2>
        {badge}
        <div className="ml-auto flex items-center gap-1.5">
          {samples && samples.length > 0 && <SamplePicker samples={samples} onPick={(sample) => onChange(sample.content)} />}
          <input
            id={inputId}
            ref={input}
            type="file"
            accept=".yaml,.yml,.json,text/yaml"
            className="sr-only"
            tabIndex={-1}
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (file) onChange(await file.text());
              event.target.value = "";
            }}
          />
          <Button size="sm" variant="ghost" aria-label={`Upload ${name}`} title="Upload a file" onClick={() => input.current?.click()}>
            <Upload className="size-3.5" />
          </Button>
        </div>
      </header>
      <div className="min-h-0 flex-1 overflow-hidden">
        <CodeEditor label={name} value={value} onChange={onChange} flags={flags} placeholder="Paste a Kong decK YAML config, drop a file, or load a sample." />
      </div>
      <footer className="flex items-center gap-3 border-t border-line px-3 py-1.5 font-mono text-2xs text-ink-3">
        <span>YAML</span>
        <span>{lines} lines</span>
        {footer && <span className="ml-auto flex items-center gap-2">{footer}</span>}
      </footer>
    </section>
  );
}
