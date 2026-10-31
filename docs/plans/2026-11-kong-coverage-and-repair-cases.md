# Kong coverage and repair cases

Sourav approved this follow-up on 2026-11-01, using one feature branch and one
pull request with separate coherent commits. Kubernetes RBAC remains exploration
only. The synthetic-only pilot and deterministic external-agent evaluation
scope remain in force.

## Delivery and boundaries

1. Correct human CLI witness rendering: an empty method is an exact modeled
   value, not evidence that every method violates. Align verification, shadowing,
   comparison and repair explanations with the web UI's `(empty method)` label.
   Preserve JSON bytes, verdicts, request domains and report schemas.
2. Add pinned Kong 3.9.3 target observations for disabled services, plugin
   protocol selection, uppercase route hosts and repeated/case-insensitive
   headers. Source expectations independently before target execution. Keep
   conservative and unsupported cases explicit; new samples alone do not widen
   the supported model. A discovered mismatch needs an independently justified
   resolution, not a changed expectation to make the harness pass.
3. Expand the existing submitted-repair benchmark with network-restricted
   access and method/host preservation scenarios. The original baseline and
   owner-reviewed contract stay fixed. Retain all attempted, missing, failed
   and unknown cases in summaries. These remain hand-authored synthetic controls,
   not measured model repair performance or real deployment results.
4. Report Kubernetes RBAC exploration separately: pinned source behavior,
   candidate initial subset, request/principal dimensions, complete-policy
   assumptions and an independent oracle route. State which findings are source
   analysis versus executed experiments. Add no shipped connector, verifier
   runtime, cluster integration or shared-core changes for this exploration.

## Acceptance

- Each implementation item is a separately reviewable commit, with its own
  focused checks and `scripts/check-commit.sh` validation. Keep full solver-heavy
  suites sequential and run one real-Kong harness at a time on the host.
- The witness regression must distinguish an allowed empty-method request from
  a denied concrete method, preserve the empty JSON field, and cover each human
  rendering path rather than changing the symbolic value to a guessed method.
- New target probes exercise positive and negative behavior and detect their
  intended mistakes. Update the semantic inventory with exact probe classes and
  remaining gaps; retain existing corpus verdicts and contract identities.
- Benchmark process tests require the expected outcome of every candidate and
  demonstrate that scoped contract success cannot hide changes to another
  method, host or unrelated endpoint.
- Integrated acceptance includes full sequential OCaml regressions and pinned
  Kong conformance. Add frontend validation only if its code or consumed schemas
  change. Real pilots and live agent runs remain pending.
