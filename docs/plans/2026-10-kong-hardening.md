# Kong semantic hardening execution plan

## Approved outcome and boundaries

Complete the bounded engineering work in roadmap milestone 10, with milestone
11 target conformance and milestone 12 semantic acceptance applied throughout.
Starting revision: `8cd7b804c74ee2d0f10248d82b428f1df6577cea` (PR #51 merged).
The user reports the hosted checks green. This is a regression baseline, not a
claim that the verifier is sound for all Kong configurations.

Sourav activated this Goal on 2026-10-10. For this batch only, local checkpoint
commits may precede the final human review, provided each is validated in a
clean worktree. Do not push, open PRs, or merge. Keep computer use disabled.
Preserve unrelated changes, solver deadlines, frozen expectations, and the
model-independent core/connector architecture. Do not silently broaden target
coverage, change public schemas or frozen contracts, or weaken tests to pass.

Deployment pilots, new connectors, model runtimes, branding changes, and a
general-purpose agent framework are out of scope. Standing rules remain in
`AGENTS.md`; project memory owns the overall roadmap. This document records
only this batch's scope, evidence, decisions, and handoff.

## Work packages and ownership

| Package | Implementation boundary | Acceptance |
| --- | --- | --- |
| B1: strict inputs | Kong parser/validation and frozen-contract decoding | Malformed structures and duplicate keys fail closed; valid existing inputs retain their meaning; adapters agree. |
| B2: faithful solver strings | Solver protocol/model decoding | SMT-LIB string values decode faithfully or fail closed; malformed/incomplete models cannot become witnesses. |
| S1: path and route semantics | Kong fragment/lowering and shared regex | Expectations justified against Kong OSS 3.9.3 and both supported router flavors; legacy paths, escaping, anchors, and ranking regressions. |
| S2: approximation and selection | Shared IR/SMT/shadowing plus Kong lowering | Definite allowance is contained in actual allowance, which is contained in possible allowance; unknown matches/guards and service-less denials cannot yield false proofs. |
| S3: property recognition | Admin API target detection and shadowing candidates | Explicit service targets recognized; candidate pruning cannot omit a real violation; independently justified regressions. |
| C1: target-backed conformance | Pinned harness, fixtures, model-oracle adapter | Authentication/plugin execution and relevant interactions compared with real Kong; independent regex expectations; negative/mutation checks. |
| I1: witness/integration | Verification, comparison, lifting, adapter tests | Returned witnesses satisfy their actual obligations and identify the selected route; all four equivalence strengths and frozen CLI/MCP/evidence scenarios rerun. |
| D1: assurance and handoff | AGENTS/README/assurance descriptions | Model-relative results, conservative candidates, audit evidence, and independently checked proofs distinguished without rebranding. |
| G1: approved contract source | Gate integration, after user decision | An untrusted candidate workspace cannot approve its own contract; approval authority and revision are explicit. |

One coordinator owns overlapping semantic modules and integration. Independent
implementation agents use separate branches/worktrees and explicit file
ownership; no more than three helpers at once. B1, B2, and C1 can begin in
parallel with semantic research. I1 follows stable S1/S2/S3 semantics. C1 is an
acceptance dependency throughout, not a last-minute test phase. Run only one
real-Kong harness on this host at a time.

## Decision gates

- **Pending user choice:** authoritative approved-contract source and who may
  change it. Asked at batch start; do not implement G1 by inventing authority.
- Ask before an unresolved semantic choice changes the supported boundary or
  requires a public schema/frozen-contract change. Document the exact evidence
  and options. Continue independent approved work where possible.
- Do not classify an item complete merely because existing tests pass.
  Correcting a target-inconsistent golden requires independent justification;
  it is not permission to bless generated output.

## Validation protocol

For every semantic fix, record target version/source, lowering rule,
approximation direction, positive/negative regressions, and a check that the
regressions detect the original defect (a baseline failure or targeted mutation
where practical). Agreement between two agents or two readers of the same IR
is not independent target evidence.

- During editing: focused tests and `bash scripts/check.sh fast` as relevant.
- Integration: `dune build @all` and `dune test --force` in the opam environment.
- Target acceptance: `bash scripts/check.sh conformance`, serialized; Docker
  lifecycle mock tests do not substitute for real-Kong semantics.
- Each checkpoint: `bash scripts/check-commit.sh <revision>`; retain/report
  failed worktrees until investigated. No checkpoint is accepted unvalidated.
- Final: forced regression suite, real-Kong conformance, all comparison modes,
  frozen CLI/MCP/evidence checks, independent code review, and `git diff --check`.

Completion means every in-scope package has its evidence recorded and no
required check or unresolved decision is hidden. Report blocked checks and
remaining decisions explicitly; do not mark the Goal complete on partial work.

## Progress and evidence log

- 2026-10-10: Goal activated. Fetched/pruned origin; root worktree was clean.
  Created integration branch `fix/kong-semantic-hardening` from `origin/main`
  at `8cd7b80`. No remote writes.
- Baseline toolchain: OCaml 5.5.0, Dune 3.24.0, Z3 4.16.0. Initial Docker
  daemon check hit the filesystem sandbox; requested scoped permission.
- Docker 28.4.0 is available. The unchanged baseline passed build and forced
  full regression tests (50 corpus cases). Plan checkpoint `4e53890` also
  passed `scripts/check-commit.sh` in a clean throwaway worktree.
- B2 implemented and independently reviewed: byte-faithful SMT escapes and
  literal serialization, explicit failure for unrepresentable model values,
  and UTF-8-safe solver diagnostics. Before fixes, handwritten escape tests
  returned literal escape text, real Z3 changed literal `\\u0041` into `A`,
  and invalid diagnostic bytes produced invalid JSON. Positive/negative tests
  now cover every modeled string field, header bytes, single-pass escaping,
  non-byte values, process failures, and truncation within multibyte text.
  Source basis: SMT-LIB Unicode Strings theory and Z3 4.16.0 `zstring.cpp`;
  direct Z3 queries confirm raw UTF-8 input is represented byte-by-byte.
  The isolated patch passed full build/forced tests; integration validation
  is running. Obligation-level witness validation remains I1, not closed by B2.
- Independent B1 review caught a further scalar-resolution mismatch: the OCaml
  YAML library and Kong's pinned LYAML disagree on octal-looking numbers and
  single-letter booleans. The patch is being corrected before integration.
- S1 source check found that Kong 3.9.3 migrates explicit format 1.1/2.1 paths
  before routing. Therefore removing unconditional legacy regex inference must
  retain version-specific migration, rather than changing legacy fixture
  expectations. Modern format 3.0 uses only the explicit regex marker.

## Final review package (to fill as work lands)

- Ordered local commits and combined diff.
- Package-by-package acceptance evidence and independent review findings.
- Tests actually run, exact target/tool versions, and any skipped/blocked gates.
- Remaining limitations and user decisions; no implication of broader assurance
  from this finite regression/conformance matrix.
