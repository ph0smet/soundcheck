# Soundcheck

> Verified AI output for declarative security policy. Soundcheck takes a
> declarative policy artifact (API-gateway config, K8s RBAC, …) — whether
> hand-written or AI-generated — and **proves** security invariants over it,
> returning either a machine-checkable proof or a concrete counterexample.

The name plays on **soundness** (a sound analysis reports no false negatives —
our core promise) and the everyday "sound check".

---

## Thesis / the value filter

Verified AI output only produces value when the use case has a **formalizable
specification**. If you cannot write a precise property, there is nothing to
prove and this machinery is overkill. Every scenario we take on must pass this
filter.

We deliberately operate in **Shape B — verified configuration/policy**, not
Shape A (verified computation over arbitrary program semantics):

- **Shape B (ours):** declarative policies reduce to a finite **decision
  function** `(principal, action, resource, context) -> Allow | Deny`. Reasoning
  is **decidable** — an SMT query is often *complete*. The verification loop
  **always terminates** with a proof *or* a concrete counterexample. No
  proof-search convergence problem.
- **Shape A (not ours, yet):** proofs over loops/recursion; undecidable in
  general; needs proof search that may not converge. This is Imandra's turf.

## What every target has in common

Kong routes, K8s RBAC, OPA/Rego, app-level authz, IAM — all are **decision
policies**. That shared essence is the reusable IP. This is why Soundcheck is a
**monorepo with a shared core + thin connectors**, NOT N separate projects.

Think of it as a compiler:

```
                     ┌─────────── shared core (the IP) ───────────┐
 Kong config ─┐      │  Decision IR  →  Property encoder  →  SMT   │
 K8s RBAC   ──┼─ connectors ─►│ (principal,  (invariant       (Z3) │──► UNSAT = proof
 OPA/Rego   ──┤  (parse→IR)   │  action,     templates)            │    SAT   = counterexample
 App authz  ──┘      │         resource,   ◄─ counterexample lift ─┤    (lifted to the
                     │         context,                            │     config's own words)
                     │         effect)                             │
                     └────────────────────────────────────────────┘
```

Multiple frontends → one IR → one solver backend → counterexamples lifted back
to each frontend's vocabulary.

---

## Key decisions (locked)

- **Language: OCaml.** Shape B is compiler/analysis/tooling work (parse → IR →
  encode → orchestrate solver → lift counterexamples), OCaml's home turf.
  Lean/Rocq matter only for *interactive theorem proving*, which we deliberately
  avoid. Z3 is our prover kernel; we don't need Lean's.
- **SMT backend: direct Z3** (via OCaml bindings), not Why3. We do finite-domain
  constraint solving, not verification-condition generation over imperative
  programs. This mirrors AWS Zelkova. Reversible — it lives behind the
  `encode/` + `solve/` boundary.
- **Monorepo, shared core + thin connectors.** Connectors depend on core; core
  NEVER depends on connectors.

## How verification works (the loop)

1. **Parse** = syntactic parse (e.g. YAML) **+ semantic lowering** into the IR.
2. **Property** = an invariant, universally quantified over all requests, e.g.
   `∀ req. (req.path matches "/admin*" ∧ req.principal = anonymous) ⇒ Deny`.
3. **Encode** the config's decision logic AND the **negation** of the property
   to Z3 — i.e. ask "does there *exist* a request the config allows but the
   property forbids?"
4. **Solve:**
   - **UNSAT** → no violating request exists → **proof** (holds for all requests).
   - **SAT**   → the satisfying assignment **is** a concrete counterexample.
5. **Lift** the SMT model back into the connector's vocabulary (actionable in the
   user's own config terms).

## What a new connector touches

- **New:** parser (syntactic + lowering), counterexample lifter, occasionally a
  target-specific property template.
- **Unchanged:** encoder, solver. **Mostly unchanged:** the IR (extended only
  when a target introduces a genuinely new concept) and the generic property
  templates (reachability, non-escalation, tenant-isolation, equivalence,
  shadowing, least-privilege).

---

## Two disciplines (non-negotiable)

1. **Extract the IR, don't predict it.** Build Kong end-to-end first and extract
   the IR from that reality (v0). Let connector #2 (tenant isolation) *refine* it
   to v1. No speculative universal IR up front.
2. **Ship the verifier before the AI loop.** "Point it at an existing config, get
   proof-or-counterexample" has standalone value with zero AI, is demoable/
   sellable, and builds the labeled corpus. The AI generation loop wraps the
   verifier as a second act.

## Other non-negotiables

- Connectors depend on core; core never depends on connectors. Keep a stable
  core API so target quirks don't leak into the IR.
- **Decidability boundary is explicit and sound.** Config fragments outside the
  decidable subset (esp. Rego) must be **flagged/rejected loudly**, never
  silently under-approximated. A false "verified" is worse than no product.
  "unsupported fragment" is a first-class result.
- **Spec-freeze** (for the future AI loop): once a property/intent is confirmed,
  the generate-verify loop may change the *config*, never the *property* — no
  weakening the spec to make buggy output pass.

---

## Invocation & AI interface

Soundcheck is a **library + thin adapters**, so it is consumable as a *component*
in any workflow — not just a standalone app. Two enforcement layers, used
together:

- **Soft / in-loop (MCP):** an MCP server exposes a `verify` tool that existing
  AI agents (Claude Code, Cursor, custom agents) call *while generating* a
  config, so they self-correct from the counterexample before delivering. Fast,
  best-effort, prompt-driven. **MCP is an adapter, not a new agent framework.**
- **Hard / gate (CI):** the CLI runs in CI / a pre-apply hook and **blocks
  merge/apply on non-zero exit**, regardless of what any agent did. This is the
  actual guarantee — never rely on a prompt for it.

**Integration surfaces** (all thin wrappers over `soundcheck_core` + connectors):
CLI (`soundcheck verify`), machine-readable **JSON output** (the universal
contract), the **MCP `verify` tool**, the **OCaml library**, a future **HTTP
service**, and a **GitHub Action**. A third-party PR-reviewer bot, custom agent,
IDE plugin, or CI all plug in via whichever surface fits.

**Design commitments that keep it embeddable (non-negotiable):**
- All logic stays in `soundcheck_core`; every adapter (`cli/`, `mcp/`, `http/`)
  stays thin — never bake verification logic into an adapter.
- The **JSON result schema is a stable, versioned contract**, e.g.
  `{ "result": "violated|proved|vacuous|inconsistent|unknown", "property": "...",
     "counterexample": { "principal": "...", "method": "...", "path": "...",
     "route": "...", "service": "..." } }`.
- `mcp/` lives **in this monorepo** (sibling of `cli/`), ideally as a subcommand
  of the single `soundcheck` binary (`soundcheck verify` vs `soundcheck mcp`) —
  one distributable, no extra runtime.
- The P1 **CEGIS loop** consumes the same JSON counterexample to drive
  regenerate-until-proved.

**Build order for the AI interface:** (1) `--format json` on the verifier →
(2) `mcp/` `verify` tool (all-OCaml first; thin TS wrapper over the JSON CLI as
fallback) → (3) CI-gate example (GitHub Action) → then more property templates →
P1 CEGIS loop.

---

## Repo structure

```
core/            shared engine (fat, valuable)
  ir/            decision model: principal, action, resource, context, effect
  properties/    invariant templates (reachability, non-escalation, isolation,
                 equivalence, shadowing, least-privilege)
  encode/        IR + property → SMT constraints
  solve/         Z3 orchestration + model extraction
  counterexample/ SMT model → abstract counterexample (in IR terms)
connectors/      thin frontends (parse→IR, lift counterexample→config)
  kong/          FIRST
  app_authz/     SECOND (tenant isolation)
  k8s_rbac/      later
  opa_rego/      later (decidable fragment only)
loop/            AI generate+verify+CEGIS (target-agnostic; PHASE 2)
evidence/        audit report emitter (proof + provenance + version hash)
cli/             `verify <config> --policy <p>`  (ship this first)
api/             service interface (later)
bench/           labeled corpora, mutation tests, regression
```

## Sequencing

- **P0 — Kong verifier, no AI.** IR v0 from Kong; ~4 invariant templates
  (public-route-has-auth, admin-API-not-reachable, no-shadowed-routes,
  rate-limit-on-public); counterexample lifting; `cli verify`. Ship it.
- **P1 — AI loop on top** (NL intent → Kong deck → verify → CEGIS feedback).
- **P2 — connector #2: app authz / tenant isolation** (refines IR v0 → v1).
- **P3 — evidence reporting, more templates, K8s RBAC / OPA connectors.**

---

## Working conventions

Global preferences (in `~/.claude/CLAUDE.md`) apply. Project-specific notes:

- Sole contributor is Sourav Kumar; no Claude attribution in commits/PRs.
- Branch by change type (`feat/`, `fix/`, `chore/`, `docs/`); never commit to
  `main` directly; commit/push only when asked; Sourav opens/merges PRs.
- `CLAUDE.md` is tracked in the repo; local Claude settings are gitignored.
