"use client";

import { Check, Copy } from "lucide-react";
import {
  useId,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";

import type { Tone } from "@/lib/domain";

export const TONE_TEXT: Record<Tone, string> = {
  proved: "text-proved",
  violated: "text-violated",
  vacuous: "text-vacuous",
  unknown: "text-unknown",
  inconsistent: "text-inconsistent",
};

export const TONE_BG: Record<Tone, string> = {
  proved: "bg-proved",
  violated: "bg-violated",
  vacuous: "bg-vacuous",
  unknown: "bg-unknown",
  inconsistent: "bg-inconsistent",
};

export const TONE_TINT: Record<Tone, string> = {
  proved: "tint-proved ring-tone-proved",
  violated: "tint-violated ring-tone-violated",
  vacuous: "tint-vacuous ring-tone-vacuous",
  unknown: "tint-unknown ring-tone-unknown",
  inconsistent: "tint-inconsistent ring-tone-inconsistent",
};

type ButtonVariant = "primary" | "secondary" | "ghost";

export function Button({
  variant = "secondary",
  size = "md",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: "sm" | "md" }) {
  const variants: Record<ButtonVariant, string> = {
    primary: "bg-inverse text-on-inverse hover:opacity-90 shadow-card",
    secondary: "border border-line bg-surface text-ink hover:bg-surface-2 hover:border-line-strong shadow-card",
    ghost: "text-ink-2 hover:bg-surface-3 hover:text-ink",
  };
  const sizes = { sm: "h-7 px-2.5 text-xs gap-1.5", md: "h-8 px-3 text-[13px] gap-2" };
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex shrink-0 items-center justify-center rounded-md font-medium transition disabled:pointer-events-none disabled:opacity-45 ${variants[variant]} ${sizes[size]} ${className}`}
    />
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="hidden rounded border border-current/25 px-1 font-mono text-[10px] leading-4 opacity-70 md:inline">
      {children}
    </kbd>
  );
}

export function Panel({
  title,
  actions,
  children,
  className = "",
  bodyClassName = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`flex min-w-0 flex-col rounded-xl border border-line bg-surface shadow-card ${className}`}>
      {(title || actions) && (
        <header className="flex min-h-11 flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-4 py-2">
          {title && <h2 className="text-[13px] font-semibold tracking-[-0.005em]">{title}</h2>}
          {actions && <div className="ml-auto flex items-center gap-1.5">{actions}</div>}
        </header>
      )}
      <div className={`min-h-0 flex-1 ${bodyClassName}`}>{children}</div>
    </section>
  );
}

export function Eyebrow({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <p className={`text-2xs font-medium uppercase tracking-[0.08em] text-ink-3 ${className}`}>{children}</p>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-4 border-b border-line bg-surface px-5 py-5 md:flex-row md:items-end md:px-8 md:py-6">
      <div className="min-w-0 max-w-3xl">
        <h1 className="text-[22px] font-semibold leading-tight tracking-[-0.02em]">{title}</h1>
        <p className="mt-1.5 text-[13.5px] leading-relaxed text-ink-2">{description}</p>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2 md:ml-auto">{actions}</div>}
    </header>
  );
}

export function Segmented<T extends string>({
  value,
  onChange,
  options,
  label,
  size = "md",
}: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: ReactNode; title?: string }[];
  label: string;
  size?: "sm" | "md";
}) {
  return (
    <div role="radiogroup" aria-label={label} className="flex rounded-lg border border-line bg-surface-2 p-0.5">
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={active}
            title={option.title}
            onClick={() => onChange(option.value)}
            className={`flex flex-1 items-center justify-center gap-1.5 whitespace-nowrap rounded-md px-2.5 font-medium transition-colors ${
              size === "sm" ? "h-6 text-xs" : "h-7 text-[13px]"
            } ${active ? "bg-surface text-ink shadow-card" : "text-ink-2 hover:text-ink"}`}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

export function Field({
  label,
  hint,
  error,
  optional,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  optional?: boolean;
}) {
  const id = useId();
  return (
    <div className="min-w-0">
      <label htmlFor={id} className="mb-1 flex items-baseline gap-2 text-xs font-medium text-ink-2">
        {label}
        {optional && <span className="font-normal text-ink-3">optional</span>}
      </label>
      <input
        id={id}
        spellCheck={false}
        autoComplete="off"
        aria-invalid={Boolean(error) || undefined}
        aria-describedby={hint || error ? `${id}-hint` : undefined}
        {...props}
        className="h-8 w-full rounded-md border border-line bg-surface-2 px-2.5 font-mono text-[12.5px] text-ink outline-none transition placeholder:text-ink-3 hover:border-line-strong focus:border-ink focus:bg-surface aria-invalid:border-violated"
      />
      {(error || hint) && (
        <p id={`${id}-hint`} className={`mt-1 text-2xs ${error ? "text-violated" : "text-ink-3"}`}>
          {error || hint}
        </p>
      )}
    </div>
  );
}

export function ToneBadge({
  tone,
  children,
  className = "",
}: {
  tone: Tone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.06em] ${TONE_TINT[tone]} ${TONE_TEXT[tone]} ${className}`}
    >
      <span className={`size-1.5 rounded-full ${TONE_BG[tone]}`} />
      {children}
    </span>
  );
}

export function Chip({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className="inline-flex items-center rounded border border-line bg-surface-2 px-1.5 py-px font-mono text-2xs text-ink-2"
    >
      {children}
    </span>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="sm"
      aria-label={label}
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1400);
        });
      }}
    >
      {copied ? <Check className="size-3.5 text-proved" /> : <Copy className="size-3.5" />}
      {copied ? "Copied" : label}
    </Button>
  );
}

export function Tabs<T extends string>({
  value,
  onChange,
  tabs,
  label,
}: {
  value: T;
  onChange: (value: T) => void;
  tabs: { value: T; label: ReactNode }[];
  label: string;
}) {
  return (
    <div role="tablist" aria-label={label} className="flex gap-4">
      {tabs.map((tab) => {
        const active = tab.value === value;
        return (
          <button
            key={tab.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(tab.value)}
            className={`-mb-px border-b-2 py-2.5 text-[13px] font-medium transition-colors ${
              active ? "border-ink text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
            }`}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

export function CodeBlock({ children, className = "" }: { children: string; className?: string }) {
  return (
    <pre
      className={`scrollbar-thin overflow-auto rounded-lg border border-line bg-surface-2 p-3 font-mono text-xs leading-relaxed text-ink-2 ${className}`}
    >
      {children}
    </pre>
  );
}
