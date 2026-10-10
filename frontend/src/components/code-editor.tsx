"use client";

import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { RangeSetBuilder, StateField, type Extension } from "@codemirror/state";
import { Decoration, EditorView, placeholder as placeholderExt, type DecorationSet } from "@codemirror/view";
import { tags } from "@lezer/highlight";
import CodeMirror from "@uiw/react-codemirror";
import { useMemo } from "react";

export interface LineFlag {
  term: string;
  kind: "primary" | "secondary";
}

const highlight = HighlightStyle.define([
  { tag: [tags.propertyName, tags.definition(tags.propertyName)], color: "var(--syn-key)", fontWeight: "500" },
  { tag: [tags.string, tags.special(tags.string)], color: "var(--syn-string)" },
  { tag: [tags.number], color: "var(--syn-number)" },
  { tag: [tags.bool, tags.null, tags.keyword], color: "var(--syn-bool)" },
  { tag: [tags.comment, tags.lineComment], color: "var(--syn-comment)", fontStyle: "italic" },
  { tag: [tags.punctuation, tags.separator, tags.bracket, tags.meta], color: "var(--syn-punct)" },
]);

const baseTheme = EditorView.theme({
  "&": { color: "var(--ink)" },
  ".cm-gutterElement": { padding: "0 10px 0 12px !important", fontSize: "11px" },
  ".cm-content": { padding: "12px 0" },
  ".cm-line": { padding: "0 14px 0 12px" },
});

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function flagExtension(flags: LineFlag[]): Extension {
  const matchers = flags.map((flag) => ({
    kind: flag.kind,
    pattern: new RegExp(`name:\\s*["']?${escapeRegExp(flag.term)}["']?\\s*(#.*)?$`),
  }));
  const primary = Decoration.line({ class: "cm-line-flag" });
  const secondary = Decoration.line({ class: "cm-line-flag-secondary" });

  const build = (doc: EditorView["state"]["doc"]): DecorationSet => {
    const builder = new RangeSetBuilder<Decoration>();
    for (let n = 1; n <= doc.lines; n++) {
      const line = doc.line(n);
      const hit = matchers.find((matcher) => matcher.pattern.test(line.text));
      if (hit) builder.add(line.from, line.from, hit.kind === "primary" ? primary : secondary);
    }
    return builder.finish();
  };

  return StateField.define<DecorationSet>({
    create: (state) => build(state.doc),
    update: (value, tr) => (tr.docChanged ? build(tr.state.doc) : value),
    provide: (field) => EditorView.decorations.from(field),
  });
}

export function CodeEditor({
  value,
  onChange,
  readOnly = false,
  flags = [],
  placeholder,
  label,
  className = "",
  minHeight,
}: {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  flags?: LineFlag[];
  placeholder?: string;
  label: string;
  className?: string;
  minHeight?: string;
}) {
  const flagKey = flags.map((flag) => `${flag.kind}:${flag.term}`).join("|");
  const extensions = useMemo(() => {
    const list: Extension[] = [
      yaml(),
      syntaxHighlighting(highlight),
      baseTheme,
      EditorView.lineWrapping,
      EditorView.contentAttributes.of({ "aria-label": label }),
    ];
    if (placeholder) list.push(placeholderExt(placeholder));
    if (flags.length) list.push(flagExtension(flags));
    return list;
    // flagKey captures every flag's content.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flagKey, placeholder, label]);

  return (
    <CodeMirror
      value={value}
      onChange={onChange}
      readOnly={readOnly}
      editable={!readOnly}
      theme="none"
      extensions={extensions}
      basicSetup={{
        foldGutter: false,
        highlightActiveLine: !readOnly,
        highlightActiveLineGutter: !readOnly,
        autocompletion: false,
        searchKeymap: true,
      }}
      minHeight={minHeight}
      className={`h-full ${className}`}
      height="100%"
    />
  );
}
