# Kubernetes RBAC reference comparison

This harness compares Soundcheck with Kubernetes **v1.34.0's production RBAC
authorizer** on the same original snapshot bytes. It also runs the real CLI and
replays its contract and preservation counterexamples through that authorizer.
It uses in-memory snapshots; it does not start a cluster or read a kubeconfig.

The same command separately checks [offline JSON preparation](../preparation/README.md):
original and prepared upstream typed policies must agree, the receipt must bind
both exact byte sequences, and prepared connector/SMT decisions must match both
upstream inputs. The original 29-case results and counts retain their meaning.

Explicit [manifest preparation](../../../docs/kubernetes-rbac.md#prepare-rendered-manifests)
has a separate suite. It decodes the **original** YAML/JSON through pinned
Kubernetes conversion and unstructured List handling, then compares the prepared
inventory, typed policies and authorization decisions. Its fixtures are synthetic;
they are not the external public-config benchmark.

The [inventory suite](../inventory/README.md) regenerates the explicit two-role
bootstrap excerpt from pinned upstream policy, decodes each original source
independently and compares the assembled union. It checks source receipts,
retained supplemental grants, exact frozen identity groups and contract outcomes.
It contacts no cluster and establishes no installed-state or completeness claim.

The separate [read-access corpus](../read-access/README.md) checks v2 contracts
for get/list/watch and compares raw request targets through Kubernetes'
`RequestInfoFactory`, an explicit authorization-attribute value projection, and
the production RBAC authorizer. It has its own counts and witness artifacts.

The [named-write corpus](../write-access/README.md) separately checks v3 contracts
for named update/patch/delete alongside the read domain. Its URL cases distinguish
the initial write request from collection deletion, subresources, and additional
authorization checks needed by some operations. Old suites stay unchanged.

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

Preparation has its own `preparation/results.json`, including accepted/rejected
preparations, typed-policy comparisons, four-way request comparisons, witness
replays through both inputs, and deliberately corrupted preparation controls.
Read access has its own `read-access/results.json`, including raw URL extraction,
three-way decision comparisons, outside-domain checks and witness replays. The
named-write suite records the corresponding v3 checks and old-version controls
in `write-access/results.json`. The combined command exits nonzero if any suite
fails. The original matrix's `complete:true` alone does not establish preparation,
read-access, named-write or manifest-ingestion conformance.

Manifest preparation records `manifests/results.json`: source/output hashes,
schema-2 receipt audits, exact retained data after approved metadata removal,
typed-policy comparisons, original/prepared/connector/SMT request comparisons
and frozen-contract verdicts. Receipt corruption controls remove retained objects,
defaults, removals and exclusions and must fail the audit. The original and
prepared source files and tool binaries are checked for changes during the run.
This suite does not add independent counterexample replay counts; those remain
in the existing authorization suites.

Inventory assembly records `inventory/results.json`: regenerated bootstrap bytes
and provenance, source/output receipt audits, typed policy comparisons, finite
native/original/prepared/connector/SMT decisions, contract witness replays and
inspection reports. Missing sources, duplicate roles, changed pins and fabricated
receipts must fail. Its counts remain separate from manifest preparation.

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

A separate `rbac-oracle --compare-policies ORIGINAL.json PREPARED.json` mode
strictly decodes, defaults and validates each input independently, then compares
typed role/binding inventories. It retains object identity, subjects, role
references, every policy-rule field, aggregation rules, labels and annotations;
only bookkeeping/lifecycle metadata is excluded from that policy projection.
The Python preparation checker separately enforces the exact approved metadata
removals and rejects active lifecycle or incomplete-pagination input.

This mode returns `kind: typed_rbac_policy_comparison`, schema version 1, exact
input digests, typed-policy digests/object counts, `valid`, `policy_equal`,
validation errors and differing object identities. Exit 0 means both inputs
are valid and their typed policies match; exit 1 means invalid input or different
typed policy; exit 2 means invocation/I/O failure. Invalid input has a null
`policy_equal`, never a successful comparison. This mode does not change the
existing `MANIFEST.json REQUESTS.json` response protocol.

`rbac-oracle --manifest-reference json|yaml DEFAULT_NAMESPACE_OR_EMPTY SOURCE`
uses the pinned `YAMLToJSONStrict` conversion and
`UnstructuredJSONScheme` typed-List inference on original bytes. Its JSON result
contains source identity, decoded document chunks and a projected RBAC List,
including original metadata. The normal upstream typed decoder/validator then
checks that inventory. The explicit namespace context fills only empty
Role/RoleBinding metadata namespaces; subjects are untouched. This test adapter
does not define Soundcheck's accepted subset: it can decode inputs Soundcheck
conservatively rejects. In particular, Kubernetes's line reader can emit a
comment preamble as a null chunk even though it is not a YAML document. Receipt
path audits use fixtures with matching explicit document boundaries, and OCaml
tests separately check preambles and empty-document accounting.

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

The original suite is a fixed-snapshot authorization comparison for named `get`
requests on core ConfigMaps and Secrets. The separate v2 suite adds list/watch
and namespace/all-namespace collection attributes; v3 adds named writes.
The separate v4 scope suite retains the v3 domain and checks namespace
sets/complements, Cartesian namespace/name requirements, name complements,
empty collection names and out-of-scope preservation. It compares concrete
and SMT decisions with Kubernetes and replays clause/preservation witnesses.
These are synthetic acceptance cases, not a public-deployment benchmark.
Snapshot completeness and authentication identity are external assumptions,
not facts discovered by the oracle. The harness does not model API discovery,
object existence, write effects, live controllers, aggregation convergence,
admission/escalation or additional operation-specific checks, bootstrap bindings,
or a composed authorization chain.

RBAC `NoOpinion` means no RBAC grant for the request; it is not a final API-server
denial. Missing role references may appear in upstream's reason string with an
empty error field, and a later applicable grant may yield `Allow`. The connector
conservatively rejects incomplete snapshots instead of treating that behavior
as a proof of no grant.

Runner acceptance tests can be run without Go or Z3:

```sh
python3 bench/kubernetes-rbac/conformance/test_runner.py
python3 bench/kubernetes-rbac/conformance/test_preparation_runner.py
python3 bench/kubernetes-rbac/conformance/test_read_access_runner.py
python3 bench/kubernetes-rbac/conformance/test_write_access_runner.py
```
