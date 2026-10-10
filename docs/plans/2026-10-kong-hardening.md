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

- **Approved 2026-10-10:** the CI gate's authoritative specification is the
  protected base-branch contract. Contract changes require separate approval;
  candidate-workspace edits must not substitute the gate's specification.
  Repository protection and who may approve remain deployment responsibilities,
  not privileges granted to this Goal.
- **Approved 2026-10-10:** keep both router flavors in scope and fail closed on
  unmodeled differences, even where that reduces previously claimed coverage.
  Pinned source establishes different precedence and PCRE-versus-Unicode-Regex
  behavior. Do not silently choose one flavor or restrict all requests to ASCII
  to make the existing model appear exact. Record narrowed coverage and its
  independent evidence explicitly.
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
  passed. Checkpoint `da37727` also passed build and forced full regressions in
  a clean throwaway worktree. Obligation-level witness validation remains I1,
  not closed by B2.
- Independent B1 review caught a further scalar-resolution mismatch: the OCaml
  YAML library and Kong's pinned LYAML disagree on octal-looking numbers and
  single-letter booleans. Raw-style scalar decoding now follows LYAML 6.2.8 for
  the accepted forms and rejects ambiguous numeric forms. A second independent
  review and focused parser/contract checks passed. Integration build, forced
  full regressions (50 corpus cases), and whitespace checks passed. Duplicate
  keys, malformed consumed structures, tags, aliases/merges, and extra documents
  now reject consistently for config and frozen-contract readers. No public
  schema or frozen contract changed; this is not full Kong schema validation.
  Checkpoint `5ee1e02` passed clean-worktree build and forced full regressions.
- S1 source check found that Kong 3.9.3 migrates explicit format 1.1/2.1 paths
  before routing. Therefore removing unconditional legacy regex inference must
  retain version-specific migration, rather than changing legacy fixture
  expectations. Modern format 3.0 uses only the explicit regex marker.
- C1 independently ran the expanded fixture against pinned Kong 3.9.3 in both
  router flavors: 46/46 authentication comparisons passed. For routing, Kong
  matched all 27 fixed expectations per flavor; the baseline model failed only
  the two new literal-plus cases per flavor. This is evidence for S1's required
  correction, not a passing integrated conformance gate. Eleven mock lifecycle
  and negative-control checks pass. No conformance containers remain.
- S3 regressions reproduce false `proved` shadowing verdicts for unrelated
  guards (authentication versus a network, and two different networks). Pruning
  now requires a sufficient implication proof; otherwise it asks the solver.
  Explicit HTTP/HTTPS Admin API service targets and leading-zero URL ports also
  reproduced false `proved` results. Detection now reads explicit ports when
  URL shorthand is absent and recognizes numeric and scheme-relative URL ports,
  preserving shorthand precedence. Pinned sources: Kong 3.9.3 `services.lua`
  and `schema/init.lua`, LuaSocket 3.0-rc1 `src/url.lua`. The latter also corrected
  a proposed query fixture: `:8001/?x=1` is valid, whereas `:8001?x=1` is not.
  Shadowing fails closed when distinct entities share a display name, rather
  than dropping all pairs of unnamed routes. Independent review, focused tests,
  and full forced regressions passed (50 corpus cases); no golden changed.
  Negative-position approximation is still S2, not closed by this checkpoint.
  Checkpoint `084a886` passed clean-worktree build and forced full regressions.

## Integrated semantics and independent acceptance

The support boundary is now profile **`kong-traditional-http-v11`**, targeting
Kong OSS 3.9.3 and both router flavors. Report schema 9, profile schema 1,
comparison schemas, and frozen-contract schemas/artifacts are unchanged.

| Package | Integrated change and acceptance evidence |
| --- | --- |
| S1: parsing/migration | Modern `/a+b` stays literal; explicit 1.1/2.1 uses the pinned migration, including percent handling and the legacy final-LF classification. Baseline literal-plus tests failed; focused migration tests now pass. |
| S1: regex | Strict escape/class/group/repetition parsing, anchor parity, typed class endpoints, checked limits, and syntax metadata. Shared connector rejects flavor-dependent languages and unsafe transformations. Initial 58 parser/boundary failures plus six class cases reproduced defects; fixed tests include 5,000 deterministic malformed inputs and independently specified real-Z3 membership expectations. Two independent parser reviews passed. |
| S1: order | Retain only common criterion-count precedence, with detailed path order under identical non-path predicates. Regex pattern length is not a rank. Accepted regexes are non-suppressing may-matches because runtime failure is not modeled. Source-predicted reducer/category differences were reproduced against both pinned routers. |
| S2: may/must | Allowance is a union of possible allowing winners, not deny-overrides. Guard failure cannot invoke an allowing default; incomplete matches cannot suppress/prune, incomplete guards cannot establish functionality, and shadowing negates a must-guard. An independent concrete refinement oracle checks 91,200 worlds (2,160 exact deterministic worlds) and detects four broken controls: deny-overrides (4,872), default fallthrough (660), incomplete suppressors (84), mixed key shapes (112). |
| S2: connector | Remove disabled-service routes; use plugin subsystem activation; reject unknown active HTTP plugins, unresolved nested relationships and consumer/consumer-group plugins; weaken unknown allow lists without dropping their possible members. Conditional termination, anonymous fallback and rate-limit state cannot prove definite access. Focused public-verdict tests and independent review pass. |
| S2: header/Host | Mixed `~*` header arrays differ by flavor; retain all possible matches. Effective default Host ports and empty wildcard matches reproduced false paired-contract proofs in the old lowering. Port-bearing hosts are unconstrained/incomplete; wildcard hosts use a possibly empty upper bound. Regression verdicts are conservative violations, never false proofs. |
| I1: SAT validation | Validate inhabitance, consistency, safety, functionality, shadowing, exact-policy preflights and all four comparison obligations before verdicts or trace insertion. Lift by selected match/guard and structural rule filter; ambiguous service ownership is not invented. Initial tests failed 23 checks; 101 focused checks now pass, including real Z3 and frozen/manual MCP consistency. Independent code review found no blocker. |
| G1: contract source | Read the exact immutable event base commit, or protected-default push commit; fail closed on unsupported contexts, malformed/missing Git objects, nonregular blobs and unsafe config paths. Candidate contract edits/deletion/symlinks cannot replace the base contract. 61 local Git cases pass, including real CLI weakening/repair and shallow-fetch controls; no network used by this test. |
| G1: build trust | Trusted Action source owns helper/verifier. Reject preexisting workspace `_opam`; disable candidate autopinning and caches; select fresh switch explicitly. Metadata tests execute five guard cases. Smoke CI builds once and requires exit 3 for the negative case, so setup failure cannot masquerade as a successful rejection test. Independent review passed. |
| D1: claims | README/AGENTS now distinguish model-relative results, conservative candidates, audit artifacts, and absent independent proof certificates. The Action's external approval/protection prerequisites and narrowed v11 boundary are explicit. No branding or connector-roadmap change. Independent review passed. |

Ordering-only assurance findings may proceed to comparison's exactness check:
complete predicates and identical observations, or a solver-proved absence of
relevant overlap, are still required. Identical-effect ties can prove decision
equivalence; unresolved route identity cannot prove the stronger modes. Other
conservative/unsupported findings fail closed. This integration adjustment and
the incomplete-match shadowing-prune safeguard were independently reviewed.

### Reviewed expectation changes

No config semantics or frozen contract was weakened to pass tests. Original
corpus YAML is retained; only stale explanatory comments changed.

- All 50 expected reports carry profile v11.
- Six formerly accepted regex fixtures now expect unknown: final `$`, shorthand
  classes, or migrated dot syntax differ across target flavors. The existing
  backreference rejection remains unknown with updated guidance.
- `host-scoped-ranking` becomes a conservative violation through `admin-narrow`:
  its guarded regex is no longer assumed to suppress reliably. This is an
  upper-bound candidate, not a claim that this simple regex fails at runtime.
- `host-scoped-suppressor` retains its violating route and gains uncertainty
  findings. Equal-order shadowing gains the order finding without changing verdict.
- General rate-limit cases keep structural coverage verdicts while reporting
  that runtime quota cannot guarantee functionality.
- `wrong-plugin` becomes unknown/unsupported because an unmodeled active plugin
  cannot safely be assumed to alter only an authorization guard.
- Generic regex/SMT agreement now accepts the empty wildcard-host suffix in its
  shared upper bound; target observations are checked separately. Header ranking
  asserts retained alternatives rather than pretending both routers have one
  total order. Comparison tests preserve their semantic expectations; rejection
  reasons reflect the earlier, stricter boundary.

The updated 50-case corpus passes. Full final integration, expanded real-Kong
acceptance, and the next clean checkpoint are recorded below when completed.

### Primary semantic sources

Kong source is pinned to tag 3.9.3, commit
`a643428bc4d5397152164a63bcc0f8bc65fce69d`:

- [`traditional.lua`](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/traditional.lua): category sorting, request-global reduction, header arrays, synthesized Host ports, wildcard matching, PCRE execution.
- [`transform.lua`](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/router/transform.lua): compatible priority packing, wildcard prefix/suffix predicates, per-value header regexes, regex source rewriting.
- [`migrate_path_280_300.lua`](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/db/migrations/migrate_path_280_300.lua): legacy literal/regex classification and percent migration.
- [`plugins_iterator.lua`](https://github.com/Kong/kong/blob/a643428bc4d5397152164a63bcc0f8bc65fce69d/kong/runloop/plugins_iterator.lua), entity schemas and declarative lowering: plugin subsystem activation, disabled services, scoped/nested relationships and URL shorthand.
- PCRE2 10.44 and the pinned ATC router (`ffd11db657115769bf94f0c4f915f98300bc26b6`, Rust regex 1.11.1): escape/Unicode/anchor differences and compile limits. Syntax restrictions do not prove absence of runtime failures.
- LYAML 6.2.8 and LuaSocket 3.0-rc1: scalar resolution and service URL parsing; SMT-LIB Unicode Strings and Z3 4.16.0 source: solver literal/model boundaries.

An initial independent 26-observation target experiment confirmed Unicode dot,
shorthand and negated-class differences, `$` before a final LF, top-level
alternation anchoring, reducer selection, and wildcard-host/path category order.
These observations are not counted as exact model agreement merely because the
updated shared profile rejects or conservatively bounds them.

## Final review package (integration checks pending)

- Ordered local commits and combined diff.
- Package-by-package acceptance evidence and independent review findings.
- Tests actually run, exact target/tool versions, and any skipped/blocked gates.
- Remaining limitations and user decisions; no implication of broader assurance
  from this finite regression/conformance matrix.
