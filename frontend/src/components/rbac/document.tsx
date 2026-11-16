"use client";

import { FileCode2, LockKeyhole, Upload } from "lucide-react";
import { useId, useLayoutEffect, useRef, useState } from "react";

import { CodeEditor } from "../code-editor";
import { Button } from "../ui";

import { MAX_RBAC_DOCUMENT_BYTES } from "@/lib/rbac/api";
import { decodeRbacUpload } from "@/lib/rbac/presentation";

/** A bounded, private document editor. No contents are written to browser storage. */
export function RbacDocument({ name, description, value, onChange, readOnly = false, className = "" }: {
  name: string;
  description: string;
  value: string;
  onChange: (value: string) => void;
  readOnly?: boolean;
  className?: string;
}) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const uploadGeneration = useRef(0);
  // Async reads may complete after the document has been locked/replaced.
  const current = useRef({ readOnly, value });
  useLayoutEffect(() => { current.current = { readOnly, value }; uploadGeneration.current++; }, [readOnly, value]);
  useLayoutEffect(() => () => { uploadGeneration.current++; }, []);

  return (
    <section className={`flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-line bg-surface shadow-card ${className}`}>
      <header className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        {readOnly ? <LockKeyhole className="size-4 text-ink-3" /> : <FileCode2 className="size-4 text-ink-3" />}
        <h2 className="font-mono text-[12.5px] font-medium">{name}</h2>
        {readOnly ? <span className="ml-auto text-2xs text-ink-3">Locked for this review</span> : (
          <div className="ml-auto">
            <input id={id} ref={input} type="file" accept=".json,application/json" className="sr-only" tabIndex={-1}
              onChange={async (event) => {
                const file = event.target.files?.[0];
                event.target.value = "";
                if (!file || current.current.readOnly) return;
                const generation = ++uploadGeneration.current;
                if (file.size > MAX_RBAC_DOCUMENT_BYTES) { setError("This file exceeds the 512 KB document limit."); return; }
                const startingValue = current.current.value;
                const ownsUpload = () => generation === uploadGeneration.current && !current.current.readOnly && current.current.value === startingValue;
                let bytes: ArrayBuffer;
                try { bytes = await file.arrayBuffer(); }
                catch { if (ownsUpload()) setError("The file could not be read."); return; }
                if (!ownsUpload()) return;
                let text: string;
                try { text = decodeRbacUpload(bytes); }
                catch { setError("The file is not valid UTF-8. Save it as UTF-8 and upload again."); return; }
                setError(null);
                onChange(text);
              }} />
            <Button size="sm" variant="ghost" aria-label={`Upload ${name}`} onClick={() => input.current?.click()}>
              <Upload className="size-3.5" /> Upload
            </Button>
          </div>
        )}
      </header>
      <p className="border-b border-line bg-surface-2 px-3 py-2 text-2xs leading-relaxed text-ink-3">{description}</p>
      <div className="min-h-0 flex-1 overflow-hidden">
        <CodeEditor label={name} value={value} readOnly={readOnly} onChange={(text) => { uploadGeneration.current++; setError(null); onChange(text); }} placeholder={`Paste ${name} or upload a JSON file.`} />
      </div>
      <footer className="flex flex-wrap items-center gap-3 border-t border-line px-3 py-1.5 font-mono text-2xs text-ink-3">
        <span>JSON</span><span>{value ? value.split("\n").length : 0} lines</span>
        {error && <span role="alert" className="font-sans text-violated">{error}</span>}
      </footer>
    </section>
  );
}
