# Kubernetes RBAC reference comparison

This harness compares Soundcheck with Kubernetes **v1.34.0's production RBAC
authorizer** on the same original snapshot bytes. It also runs the real CLI and
replays its contract and preservation counterexamples through that authorizer.
It uses in-memory snapshots; it does not start a cluster or read a kubeconfig.

Run from the repository root:

```sh
bash bench/kubernetes-rbac/conformance/run.sh
```

Prerequisites are the project's existing opam environment, Dune, Z3, Python
3.11 or newer, and a Go toolchain supporting the pinned module's `go 1.24.0`
requirement. `GO`, `Z3`, and `PYTHON` select executable paths, for example:

```sh
GO=/path/to/go Z3=/path/to/z3 bash bench/kubernetes-rbac/conformance/run.sh
```

The script uses the supplied Go toolchain with automatic toolchain downloads
disabled. It downloads the pinned Go modules as needed, verifies their checksums,
runs the adapter tests, builds the reference and model executables, and runs the
comparison. Standard Go cache settings are respected. With an already populated,
verified module cache, `GOPROXY=off GOSUMDB=off` permits an offline rerun. Missing
tools and failed checks fail the command; they never silently skip conformance.

This explicit command is separate from `dune test`. Go and downloaded modules
are not dependencies of the shipped verifier or the ordinary OCaml test suite.
The dedicated CI job uses Go 1.27.3 and the checksummed Z3 4.16.0 installer.
Generated binaries, module metadata, and results go under
`_build/rbac-conformance/`; no downloaded toolchain or module cache is vendored.

## What is checked

The corpus, frozen contract, and request matrix live in the parent directory:
`fixtures/`, `cases.json`, `contracts/frontend-access.json`, and `requests.json`.
Each manifest is one strict JSON Kubernetes `v1/List`, regardless of whether its
filename ends in `.json` or `.yaml`. The harness checks the original fixture
hashes and passes those bytes directly to both implementations.

- For supported snapshots, compare every matrix request's concrete connector
  decision, its actual production SMT encoding evaluated by Z3, and Kubernetes'
  decision. Record the SMT scripts, exact commands, output, and mismatches.
- For expected unsupported cases, require the model and CLI to return unknown.
  Keep upstream API validity separate: a valid object may still be outside the
  connector's profile, such as an aggregated ClusterRole.
- Run `soundcheck rbac verify` and require the independently specified verdict,
  matching exit status, profile, and original frozen contract identity.
- Validate each counterexample's identity, exact groups, request domain, and
  clause scope; replay it through the connector and upstream authorizer.
- Run `soundcheck rbac compare` for cases with preservation expectations. The
  candidate contract is checked first. If it fails, record preservation as
  `not_reached` and replay that contract counterexample. Otherwise, a preservation
  witness must be outside the approved change scope, and upstream evaluation of
  both snapshots must show a decision change.
- Reject missing or duplicate response IDs, missing decisions, unexpected enum
  values, malformed status envelopes, nonzero success statuses, or unresolved
  adapter errors. A missing response cannot count as a matching decision.

The model adapter emits `matrix_smt` using the production encoder. The runner
requires exactly two ground Boolean outputs per request: domain membership must
be true, followed by allowance. Missing, extra, nonground, or failed solver
output rejects the run. Witness replays receive the same three-way check.
The real CLI additionally exercises the universally scoped SMT obligations;
expected verdicts and independently replayed SAT witnesses check that path on
the corpus. These checks do not prove parser or encoder correctness for all
possible inputs.

`results.json` starts with `complete:false` and becomes `complete:true` only
after all comparisons, replays, and unchanged-input checks pass. Detailed command
records live under `artifacts/<case>/`. Solver-chosen object names are checked
against their domain and obligation, not compared with arbitrary golden names.

## Reference adapter and provenance

`oracle/` imports the pinned upstream implementation rather than copying its
matching logic. It performs strict decoding of the original document, registered
defaulting, conversion, and upstream RBAC create validation. A native List is a
materialized store: explicit object names are required, duplicate identities
are rejected, and an empty snapshot uses `items: []`.

`StaticRoles` supplies in-memory storage to the production `RBACAuthorizer` and
`DefaultRuleResolver`. Request username and groups are supplied verbatim; the
adapter never invents authentication groups. Its process exit status describes
input validity, not an authorization decision:

| Status | Meaning |
|---|---|
| 0 | Valid input; decisions are in JSON |
| 1 | Invalid input; no authorization calls accepted |
| 2 | Invocation, file, or output failure |

Upstream is pinned to commit
`f28b4c9efbca5c5c0af716d9f2d5702667ee8a45` (`v1.34.0`). Every staging replacement
from its dependency manifest points to the matching `v0.34.0` module.
`oracle/module-pins.json` records the source revision, module checksums, original
dependency-manifest digest, and full replacement list. `go.sum` locks downloaded
dependencies. Each run retains module metadata and Go binary build information;
the Python runner checks the upstream module identity and digests before use.

The imported Kubernetes implementation is licensed under Apache-2.0; its license
is retained as `oracle/KUBERNETES-LICENSE`. The small Soundcheck adapter and
harness use this repository's license. Relevant upstream sources are
[the authorizer](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac.go),
[binding resolution](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go),
and [RBAC validation](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/validation/validation.go).

## Boundaries

This is a fixed-snapshot authorization comparison for named `get` requests on
core ConfigMaps and Secrets. Snapshot completeness and authentication identity
are external assumptions, not facts discovered by the oracle. The harness does
not model API discovery, object existence, HTTP-to-attribute conversion,
list/watch, live controllers, aggregation convergence, admission/escalation
checks, bootstrap bindings, or a composed authorization chain.

RBAC `NoOpinion` means no RBAC grant for the request; it is not a final API-server
denial. Missing role references may appear in upstream's reason string with an
empty error field, and a later applicable grant may yield `Allow`. The connector
conservatively rejects incomplete snapshots instead of treating that behavior
as a proof of no grant.

Runner acceptance tests can be run without Go or Z3:

```sh
python3 bench/kubernetes-rbac/conformance/test_runner.py
```
