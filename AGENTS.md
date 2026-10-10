# Soundcheck

> Verified AI output for declarative security policy. Soundcheck takes a
> declarative policy artifact (API-gateway config, K8s RBAC, …) — whether
> hand-written or AI-generated — and **proves** security invariants within a
> versioned target model and explicit assumptions, returning a solver-backed
> verdict or a validated model-level counterexample candidate.

The name plays on **soundness** and the everyday "sound check". Our design
obligation is no false proof within the supported model and assumptions, not
an unconditional claim about every target deployment. Conservative candidates
are not guaranteed target replays; unsupported semantics fail closed.

---

## Thesis / the value filter

Verified AI output only produces value when the use case has a **formalizable
specification**. If you cannot write a precise property, there is nothing to
prove and this machinery is overkill. Every scenario we take on must pass this
filter.

We deliberately operate in **Shape B — verified configuration/policy**, not
Shape A (verified computation over arbitrary program semantics):

- **Shape B (ours):** finite declarative policies define a **decision
  function** `(principal, action, resource, context) -> Allow | Deny` over
  potentially unbounded request values. Reasoning
  is designed around a **decidable** SMT fragment rather than open-ended proof
  search. Results are explicit: proved, violated, vacuous, inconsistent, or
  unknown.
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
  Automated SMT is the pragmatic fit for the current decidable problem class;
  interactive proof assistants are not part of the runtime architecture.
- **SMT backend: Z3 CLI via SMT-LIB2 text**, not language bindings or Why3. We
  do symbolic decision-policy constraint solving, not verification-condition generation
  over imperative programs. The boundary is inspectable and replaceable behind
  the encoder and solver modules.
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
   - **UNSAT** → no violating request exists in the asserted model → a
     solver-backed proof relative to that model and its assumptions.
   - **SAT** → decode and validate the request against the actual obligation.
     Invalid models become unknown before verdicts, lifting, or evidence traces.
5. **Lift** the checked model into the connector's vocabulary. Conservative
   approximations may produce candidates that need target investigation.

Safety uses possible allowance; functionality uses definite allowance. Preserve
`must_allow ⊆ actual_allow ⊆ may_allow`: incomplete matches cannot suppress
possible winners, and incomplete guards cannot prove required access. Evidence
bundles permit formula replay; they are not independently checked UNSAT
certificates or a proof of the parser, encoder, or target model.

Frozen multi-clause verification first checks inhabitance, then consistency,
then the ordered policy clauses. Verdicts are explicit: **proved** (all required
obligations hold), **violated** (a validated modeled clause counterexample),
**vacuous** (an empty required request class), **inconsistent** (overlapping
must-allow/must-deny intent), or **unknown** (unsupported semantics, solver
failure/timeout, or invalid witness). Only proved exits zero at the gate.

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
2. **Keep verification model-independent.** "Point it at an existing config,
   get a formal verdict or counterexample" has standalone value with zero AI.
   External agents or optional downstream orchestrators may consume Soundcheck;
   model clients, prompts, credentials, and nondeterminism do not belong in the
   verification core.

## Other non-negotiables

- Connectors depend on core; core never depends on connectors. Keep a stable
  core API so target quirks don't leak into the IR.
- **Decidability boundary is explicit and sound.** Config fragments outside the
  decidable subset (esp. Rego) must be **flagged/rejected loudly**, never
  silently under-approximated. A false "verified" is worse than no product.
  "unsupported fragment" is a first-class result.
- **Spec-freeze:** once a property/intent is confirmed, load its strict,
  versioned contract artifact outside the model-controlled loop. The loop may
  change the *config*, never the *property* — no weakening the spec to make
  buggy output pass. Frozen reports carry the artifact's normalized identity.
  The CI Action reads the immutable PR base-commit contract (or the exact
  protected-default-branch push commit), not the candidate's contract file.
  Trusted workflow/action sources, fixed contract selection, required checks,
  fresh-base reruns, and separate contract approval are external prerequisites.

---

## Invocation & AI interface

Soundcheck is a **library + thin adapters**, so it is consumable as a *component*
in any workflow — not just a standalone app. Two enforcement layers, used
together:

- **Soft / in-loop (MCP):** `soundcheck mcp --contract <artifact>` loads the
  confirmed specification at startup and exposes a config-only `verify` tool.
  Existing AI agents call it while generating and self-correct from the
  counterexample; they cannot substitute property or scope arguments. MCP
  without `--contract` remains a manual exploration mode and is not frozen.
  **MCP is an adapter, not a new agent framework.**
- **Hard / gate (CI):** the CLI exits nonzero for every non-proof. A trusted,
  required, non-bypassable CI/pre-apply workflow uses that status to block
  merge/apply. Soundcheck does not install repository protection automatically.

**Integration surfaces** (all thin wrappers over `soundcheck_core` + connectors):
CLI (`soundcheck verify`), machine-readable **JSON output** (the universal
contract), the **MCP `verify` tool**, the **OCaml library**, a future **HTTP
service**, and a **GitHub Action**. A third-party PR-reviewer bot, custom agent,
IDE plugin, or CI all plug in via whichever surface fits.

**Design commitments that keep it embeddable (non-negotiable):**

- Generic decision/encoding/solver logic stays in `soundcheck_core`; parsing,
  target semantics, and lifting belong to connectors. Every adapter (`cli/`,
  `mcp/`, `http/`) stays thin — never bake verification logic into an adapter.
- The **JSON result schema is a stable, versioned contract**, e.g.
  `{ "result": "violated|proved|vacuous|inconsistent|unknown", "property": "...",
     "counterexample": { "principal": "...", "action": "...", "path": "...",
     "route": "...", "service": "..." } }`.
- Functionality is expressed as a frozen multi-clause contract, not inferred
  from the config under repair. `authenticated-access` pairs anonymous denial
  with definite authenticated allowance over one explicit path/method/host scope.
- Frozen contract files are strict and versioned. Unknown fields, versions, and
  kinds fail closed; CLI flags cannot override their property or scope.
- `mcp/` lives **in this monorepo** (sibling of `cli/`), ideally as a subcommand
  of the single `soundcheck` binary (`soundcheck verify` vs `soundcheck mcp`) —
  one distributable, no extra runtime.
- External repair loops consume the same JSON counterexample to drive
  regenerate-until-proved without weakening the frozen contract.

The JSON, MCP, functionality-contract, and structural spec-freeze foundations
are shipped. The active Kong-first sequence is tracked in Codex project memory;
the public near-term direction is summarized in `README.md`.

---

## Repository structure

Current ownership; connector #2 and later targets remain planned.

```
core/                 shared decision/verification engine
  ir.ml               request model, possible and definite allowance
  property.ml         single-property templates
  contract_verify.ml  ordered frozen multi-clause obligations and traces
  shadowing.ml        conservative candidate-pair selection
  smt_encode.ml       IR + obligations → SMT-LIB2
  solve.ml            Z3 orchestration (with solver_process/protocol modules)
  witness.ml          model-level SAT obligation validation
  report.ml           stable result serialization
  evidence.ml         audit artifacts, digests, provenance (not certificates)
connectors/kong/       parse, target boundary/lowering, comparisons, lifting
cli/                  verify / compare / profile / mcp subcommands
mcp/                  config-only frozen verification adapter
ci/                   GitHub annotation formatting
action.yml            approved-base-contract CI adapter
scripts/              local/full/clean-commit checks and gate helper
bench/                corpus and pinned real-Kong conformance
test/                 regressions, independent oracles, adapter acceptance
docs/plans/           approved bounded tasks and semantic acceptance evidence
```

## Sequencing

P0 Kong verification and the P1 verified-agent interface are shipped. Current
work deepens Kong coverage: an end-to-end frozen workflow, a versioned assurance
profile, more paired contracts, semantic conformance, configuration equivalence,
CI productization, and reproducible evidence. Connector #2 follows only after
the Kong verifier is ready for public promotion.

---

## Working conventions

- For substantial work, read the Soundcheck Codex memory index at
  `~/.codex/memories/projects/-Users-souravkumar-program-analysis-Soundcheck/MEMORY.md`.
  That is the active project tracker; do not use or update the retired Claude memory.
- Keep standing architectural and working rules here. Record approved bounded
  task scope, semantic acceptance notes, and evidence in `docs/plans/`; local
  project memory tracks roadmap status and session context, not a substitute
  specification that an implementation may silently weaken.
- Prefix OCaml commands with `eval $(opam env)`.
- Work on a focused `feat/`, `fix/`, `docs/`, or `chore/` branch; never commit
  directly to `main`.
- Once a bounded task's scope and semantic expectations are approved, implement,
  run local checks, and fix task-related failures without pausing between edits
  and tests. Present the tested diff for Sourav's review before committing.
- Pause for unresolved semantic decisions, scope expansion, unapproved changes
  to frozen contracts or public schemas, or actions needing additional permission.
  Do not weaken acceptance criteria or change expected results just to pass tests.
- Every commit must independently pass `dune test` in a clean throwaway worktree.
- Keep commit messages concise, and fetch/prune remote refs before pushing.
- Sourav opens and merges pull requests unless he explicitly delegates that action.
- Do not add AI-agent attribution, generated-by notices, or `Co-Authored-By`
  trailers unless explicitly requested.
- Preserve unrelated user changes.

### Bounded parallel work

- For substantial tasks, use subagents for independent research, test analysis,
  or review where useful. Keep one coordinating agent responsible for scope,
  acceptance criteria, and integration; start with at most three helpers.
- Give parallel implementation tasks separate branches/worktrees and explicit
  file ownership. A separate agent thread does not imply filesystem isolation.
  Serialize changes to shared interfaces and overlapping semantic modules.
- Run the current Kong conformance harness only once at a time on a host: its
  container names and ports are shared across worktrees.
- Review semantic changes against independently justified target expectations.
  Agreement between agents or between two readers of Soundcheck's own IR is not
  an independent conformance check.

### Validation and handoff

- `bash scripts/check.sh fast`: incremental build and existing regression suite;
  use focused tests during an edit loop when they are sufficient.
- `bash scripts/check.sh full`: build, force the existing regression suite to
  rerun, and run pinned real-Kong conformance. Requires a running Docker daemon.
- `bash scripts/check.sh conformance`: run only the pinned real-Kong harness.
- `bash scripts/check-commit.sh <revision>`: build and force the regression suite
  in a clean, detached throwaway worktree. Checks the specified committed revision,
  not uncommitted edits; it does not commit, push, or run Docker. Defaults to HEAD.
- These scripts use the existing opam environment; they do not install dependencies.
  Keep clean-commit regression validation separate from required conformance.
- Report the changed behavior, checks actually run, any skipped/blocked checks,
  and remaining decisions. A passing existing suite does not close a semantic
  finding without its independently justified regression coverage.
