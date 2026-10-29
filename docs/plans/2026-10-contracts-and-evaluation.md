# Kong contracts and evaluation

The approved direction is one feature branch combining the bounded reliability
follow-up, a protected-prefix contract with public exceptions, pilot preparation
and external-agent evaluation. Sourav requested this combined implementation on
2026-10-30. Each part retains separate acceptance evidence in the pull request.
He confirmed synthetic inputs only (the real pilot remains pending), and an
external-agent benchmark with deterministic validation rather than a live model
run. No model account, deployment access or external data is needed for this batch.

## Scope and semantics

- Assess YAML scalar fidelity and prevent silently truncated inputs. Preserve
  ordinary escaped text. Add focused target-backed authentication and conditional
  termination observations, plus mixed-CIDR and quota/definite-allow regressions.
- Add `protected-prefix-with-public-exceptions` as a strict schema-version-1
  contract kind. Its `scope` contains the existing normalized `path_prefix`,
  optional `method` and `host`, and required nonempty `public_path_prefixes`.
  Exception prefixes must be normalized, distinct and strictly contained in the
  outer literal prefix. Their order has no semantic significance and canonical
  identity sorts them. Overlapping exceptions are permitted: they require the
  same allowance. Prefixes use the existing literal string-prefix semantics,
  not an exact endpoint or implicit path-segment boundary.
- Require anonymous denial inside the outer scope except the public prefixes;
  authenticated allowance throughout the outer scope; and anonymous allowance
  on **each** public prefix, intersected with the same method/host scope. Keep
  inhabitance, consistency, conservative definite allowance, witness validation
  and unknown handling in the existing core. Contract comparison preserves
  behavior outside the entire outer scope, including its method/host limits.
- Expose the new kind through frozen CLI/MCP/Action verification, evidence and
  repair comparison, and the web contract builder. Do not add mutable exception
  flags to the manual property interface. Existing contract identities and report
  schema versions stay unchanged; the new canonical scope adds only the new
  kind's `public_path_prefixes` array.
- Reuse the advisory pilot runner and add an intake/review protocol. A real pilot
  requires authorized local inputs and separately reviewed requirements. No
  examples or synthetic walkthroughs count as real deployment evidence.
- Add an experimental local external-agent benchmark: evaluator-owned tasks
  freeze requirements and baselines; submissions supply candidate files only.
  Evaluate contract satisfaction and out-of-scope security-decision preservation
  through the existing verifier. Retain missing submissions and failures in the
  denominators. Deterministic fixtures establish evaluator behavior, not measured
  autonomous repair success. Model clients and credentials stay outside Soundcheck.
- Record criteria for selecting the next connector. A final selection depends on
  user needs, semantic feasibility and deployment feedback; this batch does not
  implement an unspecified second connector.

## Acceptance

1. Existing corpus outcomes, frozen identities and unsupported boundaries are
   preserved. New parser failures have independently explained input semantics.
2. New contract tests cover correct repair, exposed protected scope, denied public
   exceptions, deny-all, multiple exceptions, host/method boundaries, invalid
   artifacts, canonical ordering, conservative/unsupported configurations and
   the direct typed API. Changing a clause or excluding one exception must be
   detected. Frozen MCP rejects scope/contract replacement; CLI evidence and
   comparison retain the same identity.
3. Conformance expectations cite pinned Kong rules. Query-trigger probes remain
   conservative observations because query arguments are outside the current
   symbolic request model. No stronger target-model claim follows from a sample.
4. Benchmark inputs cannot select their own requirements, supply verdicts, bypass
   path restrictions or omit failed tasks from totals. Real-agent and deployment
   results are recorded only when actually run with authorized inputs.
5. Full sequential OCaml regressions, frontend checks/build, pinned Kong
   conformance, and the exact committed revision's clean-worktree regressions
   must pass before the branch is handed off for a pull request.

## Implementation evidence

The combined working tree passed the full build and forced sequential OCaml
suite, retaining all 50 corpus expectations. Added checks include 92 YAML scalar
cases, public-exception clause and repair-boundary regressions, 59 plugin-bound
checks, 122 repair-evaluator unit checks and 50 real-process evaluator checks.
Both synthetic repair tasks retain every unsuccessful attempt before accepting
their supplied valid candidate; neither is a measured agent trajectory.

The integrated pinned Kong run passed **304 observations** across both router
flavors: **176 exact, 58 conservative and 70 unsupported-boundary**. The inventory
still records 18 source-only features; this does not close every conformance gap.

Frontend lint/typechecking and all **209 tests** passed, including real CLI
verification, evidence and repair-schema checks for the new kind. The production
build passed with `npm run build -- --webpack`. The default Turbopack build hit
the local environment's helper-port restriction, including an escalated retry;
its normal hosted CI build remains required. No build configuration was changed
to hide that limitation.

Independent reviews covered contract semantics, benchmark trust/failure
accounting and scalar preservation. The scalar review's line-start BOM case
was fixed and included in the regressions. Benchmark assurance fields explicitly
describe candidate-contract assurance rather than baseline/preservation support.
Real deployment inputs, live agent results and a delivered second connector
remain outside this synthetic-only batch.
