"use client";

import { FileCode2 } from "lucide-react";

import { CodeEditor, type LineFlag } from "../code-editor";
import { CopyButton } from "../ui";

export function CaseConfig({ config, flags }: { config: string; flags: LineFlag[] }) {
  return (
    <section className="overflow-hidden rounded-xl border border-line bg-surface shadow-card">
      <header className="flex min-h-11 items-center gap-2 border-b border-line px-3 py-2">
        <FileCode2 className="size-4 text-ink-3" />
        <h2 className="font-mono text-[12.5px] font-medium">config.yaml</h2>
        <span className="text-2xs text-ink-3">read only</span>
        <div className="ml-auto">
          <CopyButton text={config} />
        </div>
      </header>
      <CodeEditor label="Case config" value={config} readOnly flags={flags} />
    </section>
  );
}
