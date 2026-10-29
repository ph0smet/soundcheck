# Kong conformance and advisory-pilot readiness: acceptance record

## Accepted scope

Following PR #52, baseline `c9589e0f0fbe49025c337cd1ce79111c1b8ecb44`, this
batch expanded finite Kong conformance and semantic evidence (M11/M12), prepared
local advisory evaluation (M13), and improved validation workflow (M14).
Evaluation inputs were approved as **synthetic fixtures only**; actual partner
pilots and production accuracy claims remained outside scope, along with model
runtimes, new connectors and agent benchmarks.

Report schema 9, profile `kong-traditional-http-v11`, frozen artifacts, verifier
semantics, solver deadlines and existing expected verdicts were preserved. New
manifest/coverage formats are internal experimental tooling. Independent pinned
target expectations, rather than Soundcheck output, established probe decisions,
identities and statuses.

## Technical decisions

### Pinned plugin conformance

Target: Kong OSS 3.9.3, source
`a643428bc4d5397152164a63bcc0f8bc65fce69d`, both supported router flavors.
Existing expectations and exact/conservative/unsupported classes were retained.

- **Source IP:** strict probe/oracle protocol for IPv4 allow/deny,
  deny-before-allow overlap, `/0`, `/32`, boundaries, global/service/route/combined scopes
  and disabled-plugin fallback. Fixture-only trusted real-IP setup on owned
  loopback containers tests the stated source-integrity assumption; it does not
  establish production trust. Negative controls detect malformed addresses,
  selection failures and omitted or mismatched source injection.
- **Conditional termination:** absent/present header triggers, effective scopes
  and precedence, including authentication/IP rejection before termination.
  Conditional decisions remain conservative; query triggers remain a gap.
- **Basic Auth/JWT:** singleton samples with public synthetic credentials cover
  missing/malformed/valid credentials and JWT OPTIONS bypass. These do not cover
  well-formed wrong passwords/signatures, richer identity, external providers,
  expiration clocks or Enterprise plugins. Runtime quota exhaustion is outside
  this finite matrix.

Independent sources include pinned `ip-restriction/handler.lua`,
`request-termination/handler.lua`, `jwt/handler.lua`, `basic-auth/access.lua`,
`runloop/plugins_iterator.lua` and `kong.conf.default`. Protocol, fixtures and
source references are maintained in the
[conformance runbook](../../bench/kong/conformance/README.md).

### Evidence inventory and advisory evaluation

The [semantic inventory](../../bench/kong/SEMANTIC-COVERAGE.md) records every
profile feature's class, pinned rule, lowering/approximation direction,
regressions, target probe classes/flavors and gaps. Its validator checks reference
integrity and rejects false coverage declarations. This is **inventory
integrity**, not proof of semantic completeness; unsupported probes are not
modeled agreement, and harness controls are not feature-specific mutations.

The experimental [pilot runner](../../bench/pilot/README.md) reuses
`Contract_spec`, `Verify` and `Report`. A strict explicit manifest supplies
pseudonymous IDs, config/contract paths and self-declared provenance. Contracts
freeze before their sequential per-case verification; summaries hash the exact
config bytes verified, use normalized contract identities, count all scheduled
cases including errors and unknowns, and exit zero only when every case is proved.
Default output minimizes sensitive data; IDs/hashes do not anonymize it. There is
no repair, input fetching, implicit traversal, automatic evidence retention or
overwrite. Provenance is not
verified authority, and human accuracy/usefulness metrics are not inferred.
The stale `bench/survey.ml` coverage claims were retired.

Internal metadata readers reject raw NUL/backslash syntax to contain decoded-NUL
truncation. Shared verifier parsing was unchanged in this milestone. The later
[scalar-fidelity assessment](2026-10-yaml-scalar-fidelity.md) adds a targeted
guard against NUL truncation; no false verdict for a valid live deployment was
established.

### Validation workflow

[Check wrappers](../../README.md#testing) preserve parallel builds and sequential
solver-heavy tests (`-j 1`), fast/full/conformance modes and requested-revision
clean-commit checks. They add no retries, tool installations, deadline changes or
skipped tests. Failure propagation and absence of false success are checked.
Independent review found ambient Git settings could redirect synthetic test
operations; clearing Git routing/configuration fixed this, with an owned-repository
isolation control.

## Historical local acceptance

These results describe the readiness candidate, before the separate
[corpus timeout fix](2026-10-kong-corpus-timeout.md):

- Full build, forced sequential regressions and pinned real-Kong conformance
  passed: all **50 unchanged corpus cases** and **282 target observations**
  (**160 exact, 52 conservative, 70 unsupported-boundary**) across both flavors.
  Focused plugin checks separately passed twice, with 140 observations per run.
- Source-IP oracle protocol: 22 checks; mocked harness: 35 controls.
- Inventory: **42 features** (18 source-only, 23 modeled-sample, one
  boundary-sample), 50 rejected corruption controls and three permitted-literal parser
  controls. Reference/class/flavor claims received independent review.
- Synthetic advisory tooling: 107 unit and 60 actual-process CLI checks.
- Validation wrappers: 28 checks, including the reviewed Git-isolation fix.
- A fresh detached worktree with the applied candidate passed build and forced
  sequential regressions, including the final Git-isolation control. This was
  candidate-diff validation, distinct from an exact committed-revision check.
  Dune 3.24.0 and Z3 4.16.0 were used; independent reviews found no remaining
  implementation or target-expectation blocker.

## Evidence gaps recorded at this milestone

The 18 source-only rows and feature-wide semantic mutation coverage remain open.
Basic/JWT negatives do not test well-formed wrong credentials. Query-trigger
termination, runtime quota/storage, broader providers/identity, commercial
plugins and production source-IP integrity remain gaps, as do focused mixed-CIDR
and quota/definite-allow lowering regressions. The inventory tracks details.
The [contracts/evaluation follow-up](2026-10-contracts-and-evaluation.md) adds
well-formed wrong credentials, query-trigger observations and the focused bound
regressions. The [current inventory](../../bench/kong/SEMANTIC-COVERAGE.md)
distinguishes these additions from the remaining target and runtime gaps.

Real pilots require authorized deployment inputs, owner-reviewed contracts and
independently adjudicated usefulness/accuracy measurements. Synthetic preparation
establishes none of those conclusions and does not complete M11/M12 universally.
