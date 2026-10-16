"use client";

import { Lock, Sigma } from "lucide-react";

import type { PropertyId, PropertySpec, Sample, Spec } from "@/lib/api";
import { contractProblems, contractYaml, type ContractDraft } from "@/lib/contract-yaml";
import { PROPERTIES, formalStatement, propertyInfo } from "@/lib/domain";

import { CodeEditor } from "../code-editor";
import { CopyButton, Eyebrow, Field, Panel, Segmented } from "../ui";

export interface SpecState {
  mode: "property" | "contract";
  property: PropertySpec;
  contractSource: "builder" | "text";
  contractDraft: ContractDraft;
  contractText: string;
}

export function resolveSpec(state: SpecState): { spec: Spec } | { error: string } {
  if (state.mode === "property") {
    const info = propertyInfo(state.property.property);
    const spec: PropertySpec = { mode: "property", property: state.property.property };
    for (const param of info?.params ?? []) {
      const value = state.property[param]?.trim();
      if (value) spec[param] = value;
    }
    if (info?.requiredCidr && !spec.trustedCidr) return { error: "Enter a trusted CIDR." };
    return { spec };
  }
  if (state.contractSource === "builder") {
    const problems = contractProblems(state.contractDraft);
    if (problems.length) return { error: problems[0] };
    return { spec: { mode: "contract", contract: contractYaml(state.contractDraft) } };
  }
  if (!state.contractText.trim()) return { error: "Paste a contract or pick a saved one." };
  return { spec: { mode: "contract", contract: state.contractText } };
}

function withProperty(current: PropertySpec, id: PropertyId): PropertySpec {
  const info = propertyInfo(id)!;
  return {
    ...current,
    property: id,
    pathPrefix: info.defaults.pathPrefix ?? current.pathPrefix ?? "/admin",
    trustedCidr: info.defaults.trustedCidr ?? (id === "network-restricted-access" ? current.trustedCidr || "10.0.0.0/8" : current.trustedCidr),
  };
}

const PARAM_FIELDS = {
  pathPrefix: { label: "Path prefix", placeholder: "/admin", hint: "Normalized literal path" },
  method: { label: "Method", placeholder: "all methods", hint: undefined },
  host: { label: "Host", placeholder: "all hosts", hint: undefined },
  trustedCidr: { label: "Trusted CIDR", placeholder: "10.0.0.0/8", hint: "IPv4 block" },
} as const;

export function SpecPanel({
  state,
  onChange,
  contracts,
}: {
  state: SpecState;
  onChange: (state: SpecState) => void;
  contracts: Sample[];
}) {
  const set = (patch: Partial<SpecState>) => onChange({ ...state, ...patch });

  return (
    <Panel
      title="Specification"
      actions={
        <Segmented
          label="Specification mode"
          size="sm"
          value={state.mode}
          onChange={(mode) => set({ mode })}
          options={[
            { value: "property", label: "Property", title: "Explore with a mutable property" },
            { value: "contract", label: <><Lock className="size-3" />Frozen contract</>, title: "Bind to an immutable, human-confirmed contract" },
          ]}
        />
      }
    >
      {state.mode === "property" ? (
        <PropertyEditor spec={state.property} onChange={(property) => set({ property })} />
      ) : (
        <ContractEditor state={state} set={set} contracts={contracts} />
      )}
    </Panel>
  );
}

function PropertyEditor({ spec, onChange }: { spec: PropertySpec; onChange: (spec: PropertySpec) => void }) {
  const info = propertyInfo(spec.property)!;
  const clauses = formalStatement(spec);
  return (
    <div className="divide-y divide-line">
      <fieldset className="p-3">
        <legend className="sr-only">Property</legend>
        <div className="grid gap-1 sm:grid-cols-2">
          {PROPERTIES.map((property) => {
            const active = property.id === spec.property;
            return (
              <label
                key={property.id}
                className={`relative flex cursor-pointer flex-col rounded-lg border px-3 py-2.5 transition-colors ${
                  active ? "border-ink bg-surface-2" : "border-transparent hover:bg-surface-2"
                }`}
              >
                <input
                  type="radio"
                  name="property"
                  value={property.id}
                  checked={active}
                  onChange={() => onChange(withProperty(spec, property.id))}
                  className="sr-only"
                />
                <span className="flex items-center gap-2 text-[13px] font-medium">
                  {property.title}
                  {property.paired && (
                    <span className="rounded border border-line px-1 text-[10px] font-medium uppercase tracking-wide text-ink-3">
                      paired
                    </span>
                  )}
                </span>
                <span className="mt-0.5 line-clamp-2 text-xs leading-snug text-ink-2">{property.question}</span>
              </label>
            );
          })}
        </div>
      </fieldset>

      {info.params.length > 0 && (
        <div className="grid gap-3 p-4 sm:grid-cols-2">
          {info.params.map((param) => {
            const field = PARAM_FIELDS[param];
            const optional = param === "method" || param === "host";
            return (
              <Field
                key={param}
                label={field.label}
                optional={optional}
                placeholder={field.placeholder}
                hint={field.hint}
                value={spec[param] ?? ""}
                onChange={(event) => onChange({ ...spec, [param]: event.target.value })}
              />
            );
          })}
        </div>
      )}

      <div className="space-y-2.5 p-4">
        <div className="flex items-center gap-2">
          <Sigma className="size-3.5 text-ink-3" />
          <Eyebrow>Proof obligation</Eyebrow>
          <code className="ml-auto font-mono text-2xs text-ink-3">{spec.property}</code>
        </div>
        <div className="space-y-1.5 rounded-lg bg-surface-2 px-3.5 py-3">
          {clauses.map((clause) => (
            <div key={clause.text} className="flex gap-3 font-mono text-[12px] leading-relaxed">
              {clause.label && <span className="w-20 shrink-0 text-ink-3">{clause.label}</span>}
              <span className="min-w-0 break-words text-ink">{clause.text}</span>
            </div>
          ))}
        </div>
        <p className="text-xs leading-relaxed text-ink-2">
          The solver searches for a request the config allows but the property forbids.{" "}
          <span className="text-ink">UNSAT</span> is a proof over every modeled request;{" "}
          <span className="text-ink">SAT</span> is the counterexample.
          {info.note && <> {info.note}</>}
        </p>
      </div>
    </div>
  );
}

function ContractEditor({
  state,
  set,
  contracts,
}: {
  state: SpecState;
  set: (patch: Partial<SpecState>) => void;
  contracts: Sample[];
}) {
  const draft = state.contractDraft;
  const setDraft = (patch: Partial<ContractDraft>) => set({ contractDraft: { ...draft, ...patch } });
  const yaml = contractYaml(draft);
  const problems = contractProblems(draft);
  const network = draft.kind === "network-restricted-access";

  return (
    <div className="divide-y divide-line">
      <div className="flex flex-wrap items-center gap-3 px-4 py-3">
        <p className="min-w-0 flex-1 text-xs leading-relaxed text-ink-2">
          Contracts are strict, versioned artifacts. Unknown fields, versions and kinds fail closed, and the verdict carries
          the contract&rsquo;s canonical identity.
        </p>
        <Segmented
          label="Contract source"
          size="sm"
          value={state.contractSource}
          onChange={(contractSource) => set({ contractSource })}
          options={[
            { value: "builder", label: "Build" },
            { value: "text", label: "YAML" },
          ]}
        />
      </div>

      {state.contractSource === "builder" ? (
        <>
          <div className="space-y-3 p-4">
            <Segmented
              label="Contract kind"
              value={draft.kind}
              onChange={(kind) => setDraft({ kind })}
              options={[
                { value: "authenticated-access", label: "Authenticated access" },
                { value: "network-restricted-access", label: "Network restricted" },
              ]}
            />
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Path prefix" value={draft.pathPrefix} onChange={(e) => setDraft({ pathPrefix: e.target.value })} placeholder="/admin" />
              <Field label="Method" optional value={draft.method} onChange={(e) => setDraft({ method: e.target.value })} placeholder="every method" />
              <Field label="Host" optional value={draft.host} onChange={(e) => setDraft({ host: e.target.value })} placeholder="every host" />
              {network && (
                <Field label="Trusted CIDR" value={draft.trustedCidr} onChange={(e) => setDraft({ trustedCidr: e.target.value })} placeholder="10.0.0.0/8" />
              )}
            </div>
            {network && (
              <label className="flex cursor-pointer gap-2.5 rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-xs leading-relaxed text-ink-2">
                <input
                  type="checkbox"
                  checked={draft.acknowledged}
                  onChange={(e) => setDraft({ acknowledged: e.target.checked })}
                  className="mt-0.5 size-3.5 shrink-0 accent-[var(--ink)]"
                />
                <span>
                  <span className="font-medium text-ink">Source IP integrity is externally enforced.</span> The deployment, not
                  Soundcheck, ensures clients cannot spoof the client IP Kong derives. This assumption becomes part of the
                  frozen identity.
                </span>
              </label>
            )}
          </div>
          <div className="space-y-2 p-4">
            <div className="flex items-center gap-2">
              <Eyebrow>Artifact preview</Eyebrow>
              <div className="ml-auto flex items-center">
                <CopyButton text={yaml} />
              </div>
            </div>
            <pre className="scrollbar-thin overflow-auto rounded-lg bg-surface-2 px-3.5 py-3 font-mono text-xs leading-relaxed text-ink">{yaml}</pre>
            {problems.length > 0 && <p className="text-2xs text-vacuous">{problems[0]}</p>}
          </div>
        </>
      ) : (
        <div>
          {contracts.length > 0 && (
            <div className="flex flex-wrap gap-1.5 px-4 py-3">
              <span className="mr-1 self-center text-2xs text-ink-3">Saved contracts</span>
              {contracts.map((contract) => (
                <button
                  key={contract.id}
                  type="button"
                  onClick={() => set({ contractText: contract.content })}
                  className="rounded-md border border-line bg-surface px-2 py-1 font-mono text-2xs text-ink-2 transition hover:border-line-strong hover:text-ink"
                >
                  {contract.label}
                </button>
              ))}
            </div>
          )}
          <div className="h-56 border-t border-line">
            <CodeEditor
              label="Contract YAML"
              value={state.contractText}
              onChange={(contractText) => set({ contractText })}
              placeholder={"schema_version: 1\nkind: authenticated-access\nscope:\n  path_prefix: /admin"}
            />
          </div>
        </div>
      )}
    </div>
  );
}
