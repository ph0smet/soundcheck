# Kubernetes RBAC

Soundcheck checks paired access requirements and repair preservation within
bounded static RBAC profiles. Contract schema 1 checks named `get`; schema 2
adds `list` and `watch`; schema 3 adds named `update`, `patch` and `delete` for
core ConfigMaps and Secrets. Schema 4 adds namespace sets/complements and
precise effective-name selectors over that same request domain.
CLI and library workflows share the decision IR,
encoder, Z3 backend and witness validation with the Kong connector.

## Try the workflow

Build using the [quickstart](../README.md#quickstart), then run from the repo root:

```sh
eval "$(opam env)"
dune exec soundcheck -- profile kubernetes-rbac
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/fixtures/01-unsafe.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
```

The example requires `system:serviceaccount:frontend:frontend-sa` to have `get`
access to every valid named ConfigMap in `frontend`, without a `get` grant for
any named Secret in `payments`. The unsafe snapshot violates that requirement
and exits `3`. Its counterexample names the identity, namespace, resource,
object name, groups and granting binding/role/rule. Solver-selected names vary.

```sh
dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/fixtures/01-unsafe.json \
  bench/kubernetes-rbac/fixtures/03-valid-repair.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
```

This exits `0`: the replacement meets both clauses and preserves decisions
outside the approved change scope. `verify` alone does not check preservation.

| Candidate fixture | Expected behavior |
| --- | --- |
| `01-unsafe.json` | Unwanted Secret grant violates the contract |
| `02-delete-workload-grants.json` | Required ConfigMap access is lost; repair fails |
| `03-valid-repair.json` | Contract holds and other decisions are preserved |
| `04-leftover-cluster-grant.json` | Another ClusterRoleBinding still grants access |
| `05-group-grant.json` | Group membership still grants access |
| `16-operator-regression.json` | Workload contract holds; comparison catches the operator's lost permission |

These are synthetic snapshots, not production or live-agent evaluation results.

## Prepare a JSON export

`rbac prepare` explicitly removes a small, validated set of metadata from an
otherwise-supported static RBAC inventory. It emits the same strict `v1/List`
that `verify`, `compare`, MCP and the Action already accept:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac prepare \
  bench/kubernetes-rbac/preparation/fixtures/01-export-unsafe.json \
  --receipt /tmp/rbac-preparation-receipt.json > /tmp/rbac-snapshot.json
dune exec soundcheck -- rbac verify /tmp/rbac-snapshot.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
```

The first command succeeds; the second still finds the unwanted grant and exits
`3`. Preparation does not repair or verify a policy. It preserves every object,
rule, subject, role reference, name, namespace, label and annotation. The complete
prepared result must pass the existing snapshot reader before any bytes reach
stdout. Preparation contacts neither Kubernetes nor Z3.

Accepted metadata removal is deliberately narrow:

| Metadata | Accepted form |
| --- | --- |
| Object `uid`, `resourceVersion`, `selfLink` | Strings; values are treated as opaque |
| Object `generation` | Nonnegative int64 |
| Object `creationTimestamp` | Null or supported RFC3339 timestamp |
| Object `generateName` | Empty string only; an explicit object name is still required |
| Object `deletionTimestamp`, `deletionGracePeriodSeconds` | Null only |
| Object `ownerReferences`, `finalizers`, `managedFields` | Null or empty array only |
| List `resourceVersion`, `selfLink` | Strings |
| List `continue` | Empty string only |
| List `remainingItemCount` | Null or integer zero only |

All fields may be absent. Timestamp parsing validates Gregorian dates in years
0001..9999, uppercase `T`/`Z`, seconds 0..59, optional 1..9 fractional digits,
and numeric timezone offsets with hours below 24 and minutes below 60. Unknown
or malformed metadata and populated lifecycle/managed-fields data are rejected.
These checks follow the pinned [Kubernetes metadata types](https://github.com/kubernetes/apimachinery/blob/v0.34.0/pkg/apis/meta/v1/types.go).

Input is one strict JSON `apiVersion: v1`, `kind: List`. YAML, typed lists such
as `RoleList`, individual objects and concatenated documents are unsupported.
The 16 MiB input limit and all existing policy checks still apply, including
aggregation rules, non-resource permissions, duplicate identities and unresolved
references. An ordinary whole-cluster export may therefore remain unsupported.
Do not filter out objects or fields simply to obtain an accepted snapshot.

The optional receipt is created exclusively with private permissions; its parent
must exist, and an existing file, directory or symlink is never replaced. Schema
1 records exact input/output SHA-256 hashes and byte counts, object count and
sorted paths of removed metadata fields. Its output hash includes the snapshot's
final newline. It explicitly records `verification_performed: false` and
`completeness_established: false`. This receipt is separate from verification
evidence, which binds the prepared bytes. A failed receipt write emits no
snapshot but can leave an incomplete new receipt file.

Exit `0` means preparation succeeded, `2` means unsupported/invalid input or
usage, and `1` means a read/output failure, including the file-size limit. Keep
the original export and receipt when the transformation needs to be audited.
The prepared snapshot is an analysis artifact; it is not a deployment-ready
replacement for the original resource metadata.

**Acquisition and completeness remain external.** Check the export command's
exit status before preparing its output. `kubectl` can print collected objects
before returning a retrieval error, and its generic List can omit pagination
context. Empty continuation also cannot distinguish a full collection from its
last page. The command does not discover missing resources, selectors, namespace
restrictions or cross-resource snapshot consistency. See the pinned
[`kubectl` implementation](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/kubectl/pkg/cmd/get/get.go)
and [pagination semantics](https://v1-34.docs.kubernetes.io/docs/reference/using-api/api-concepts/#retrieving-large-results-sets-in-chunks).

## Frozen contract

Start from the complete [example contract](../bench/kubernetes-rbac/contracts/frontend-access.json).
The original strict JSON contract (schema 1) requires:

- `schema_version: 1` and `kind: "kubernetes-rbac-access"`.
- `context`: schema version 1, `snapshot_complete: true`, and nonempty unique
  usernames with exact, duplicate-free group lists.
- `clauses`: uniquely named `must_allow` and `must_not_grant` requirements, with
  at least one of each. Every clause selects a declared `subject`, one
  `namespace`, a `resource` (`configmaps` or `secrets`), and `names` (`null` for
  all valid names, or a nonempty list of literal names).
- `change_scope`: the only request classes whose decisions a repair may change,
  using the same subject/namespace/resource/names selectors. An empty list
  requires complete decision preservation within the profile.

For schema 1 the verb is always `get`, the API group core (`""`), and the subresource empty.
Unknown versions and scope fields are rejected. RBAC rule `resourceNames: ["*"]`
is literal, whereas rule verbs, API groups and resources support `"*"` wildcards.

Review and protect the contract and baseline independently of the candidate.
The CLI accepts no identity/group/property/scope overrides. Reports carry the
canonical frozen contract, including its context and approved change scope.
This does not sandbox an agent that can replace those files or the verifier.

## Read-access contracts (schema 2)

The [runnable read-access repair demo](../bench/kubernetes-rbac/workflows/read-access/README.md)
pairs a frozen schema-2 contract with unsafe, partial-repair, valid-repair,
deny-all and operator-regression snapshots.

Schema 2 keeps the same `kind`, frozen identity context, paired clause kinds and
approved `change_scope`. Every clause and change-scope entry also requires a
singular `verb`: `get`, `list` or `watch`. The contract selects the
`kubernetes-rbac-v1.34-read-v1` profile. Existing schema-1 artifacts, canonical
identities, profiles and get-only preservation semantics keep their meaning;
upgrading a contract requires separate requirement review.

| Scope field | Schema-2 meaning |
| --- | --- |
| `namespace: "frontend"` | Exactly that namespaced endpoint |
| `namespace: null` | Exactly the all-namespace collection endpoint; only list/watch |
| `names: null` with get | Every valid named object request |
| `names: null` with list/watch | Empty effective authorization name **and** every supported valid name |
| `names: ["settings"]` | Exactly that effective authorization name |

An all-namespace scope is not a wildcard over namespaced endpoints. Namespace
and name strings retain the DNS/length bounds below. Empty name arrays, empty
name literals, wildcard names, missing verbs and unknown fields are rejected.
This version cannot express an empty-effective-name-only requirement.

For a modern collection request, a nonempty effective name can come from
`fieldSelector=metadata.name=settings`; a legacy named watch path can also
supply it. Without a usable exact-name restriction, authorization sees the empty
name. It does **not** check each returned object against `resourceNames`.
Consequently `resourceNames: ["settings"]` does not grant an unrestricted list,
while `resourceNames: [""]` grants the empty-name case but cannot satisfy
`must_allow` with `names: null`. A literal `resourceNames: ["*"]` remains a
literal star and matches no supported object name. These rules follow the
[pinned RBAC matching helpers](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/evaluation_helpers.go)
and [request interpretation](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/request/requestinfo.go).

A clause forbidding only a name-selected list/watch request is a requirement
about that request class, not confidentiality of the named object's contents:
an unnamed collection request may still return that object. To forbid all
direct Secret read grants in a scope, cover `get`, `list` and `watch` with
`names: null`, as the demo does.

All-namespace collection requests require a ClusterRoleBinding grant. A
RoleBinding to a ClusterRole still applies only in the RoleBinding's namespace;
adding a `metadata.namespace` field selector to an all-namespace URL does not
change its authorization namespace.

Safety clauses should explicitly cover the relevant read verbs: removing a
Secret `get` grant can still leave `list` or `watch` grants that expose contents.
For a schema-2 repair, preservation quantifies over **all three verbs**, every
supported namespace/name and the all-namespace collection endpoint for each
frozen identity, regardless of which verbs appear in its access clauses.
Change scope includes the verb, so approval to change `get` does not permit
changing `watch`.

```sh
dune exec soundcheck -- profile kubernetes-rbac --contract-version 2 --format json
```

The existing CLI, frozen MCP and approved-base Action select the model from the
trusted contract. Evidence bundles bind that selected profile. Raw URLs and
selector expressions are not new verifier inputs; reports describe effective
authorization attributes. The model does not assert successful API execution,
returned objects or watch events. In particular, an empty witness name means
no effective exact-name restriction, not necessarily no selectors in an HTTP
request. Preparation still checks the shared snapshot format; its original
receipt `target_profile` is not the profile selected for a later verification.

## Named write-access contracts (schema 3)

The [runnable named-write repair demo](../bench/kubernetes-rbac/workflows/write-access/README.md)
includes an incomplete repair, required manager writes and an unrelated
Secret-rotation regression caught only by repair comparison.

Schema 3 retains the schema-2 fields and adds `update`, `patch` and `delete` to
the allowed verbs. It selects `kubernetes-rbac-v1.34-read-write-v1`. Existing
schema-1/2 contracts and profiles keep their meaning; selecting schema 3 is a
separate requirement change, not an automatic upgrade.

Each write requires a nonempty DNS-valid namespace and object name. In a write
clause or change scope, `names: null` selects every supported named request;
`names: ["settings"]` selects exactly that name. `namespace: null` is invalid
for these verbs. It still selects the all-namespace endpoint for list/watch.
Schema 3 has no name-complement selector: requiring `settings` while
forbidding `names: null` for the same subject/verb/resource/namespace is
inconsistent, rather than a way to express "settings only".

An app can be required to read its ConfigMaps while being forbidden to update,
patch or delete them. A separate identity can retain a required named write.
Each forbidden operation needs its own clause: removing `update` does not remove
`patch` or `delete`. Preservation covers **all six supported verbs**, including
verbs absent from the access clauses. An approved update change cannot silently
remove another identity's patch permission or the app's collection reads.

The [pinned request parser](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/request/requestinfo.go)
maps ordinary named PUT/PATCH/DELETE requests to update/patch/delete. Their
authorization name comes from the URL path, not a selector or body. RBAC matches
`resourceNames` literally: `[]` is unrestricted, whereas `[""]` and `["*"]`
grant no supported named write. Top-level create and collection deletion are
outside this profile; adding a name selector does not turn collection DELETE
into a supported named delete.

The proof concerns the **initial request's RBAC grant**, not successful mutation,
changed fields or object contents. Request bodies, object existence,
preconditions, admission and extra operation-specific authorization remain
outside it. For example, server-side-apply PATCH can additionally require
[create authorization](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/handlers/patch.go),
and malformed-object deletion can additionally require
[unsafe-delete authorization](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/handlers/delete.go).
Preserving authorization decisions does not preserve stored object contents.

```sh
dune exec soundcheck -- profile kubernetes-rbac --contract-version 3 --format json
```

## Namespace and name selectors (schema 4)

Schema 4 selects `kubernetes-rbac-v1.34-scoped-read-write-v1`. It retains the
schema-3 authorization model and six verbs, and adds the following selectors
to **both clauses and `change_scope`**. Existing literal/null selectors keep
their meaning; schemas 1–3 reject the new syntax and retain their profiles.

| Field and selector | Request class |
| --- | --- |
| `"namespace": {"include": ["team-a", "team-b"]}` | Every namespaced request in either listed namespace |
| `"namespace": {"exclude": ["team-a", "team-b"]}` | Every valid nonempty namespace except those listed, including namespaces absent from the snapshot |
| `"namespace": {"exclude": []}` | Every valid nonempty namespace |
| `"namespace": null` | Only the all-namespace list/watch endpoint, as in schemas 2–3 |
| `"names": {"empty": true}` | Only an empty effective authorization name; list/watch only |
| `"names": {"exclude": ["settings"], "include_empty": false}` | Every valid nonempty name except `settings` |
| `"names": {"exclude": ["settings"], "include_empty": true}` | That complement plus the empty effective name; list/watch only |

For example, a `must_allow` clause can require Secret `get` on `settings`,
while a `must_not_grant` clause uses the name complement to forbid other named
Secret reads. A separate `must_not_grant` clause with `names: {"empty": true}`
can prohibit unrestricted list/watch authorization while allowing a selected
named collection request. These are authorization attributes, not guarantees
about returned objects. An HTTP selector such as `metadata.name!=settings`
is **not** the contract's name complement: it generally has no usable exact
authorization name and therefore belongs to the empty-name request class.

Namespace exclusions never include the all-namespace collection endpoint.
Replacing a ClusterRoleBinding with RoleBindings may remove both access in
other namespaces **and** all-namespace list/watch access. Approve the latter
with separate `namespace: null` change scopes when intended. Otherwise repair
comparison rejects that additional change even if the candidate's access
clauses pass. It also preserves access inside the excluded namespace set and
for other frozen identities, across all six verbs.

Selectors combine by intersection: namespaces `["a", "b"]` and names
`["x", "y"]` select all four combinations. `must_allow` requires every such
request, not one matching pair. Overlapping allow/forbid selectors remain an
inconsistent requirement.

Namespace includes must be nonempty. Exclusion arrays may be empty. All literals
must meet the existing DNS bounds; duplicates, mixed selector forms and unknown
fields are rejected. `include_empty` is mandatory for a name complement and
must be false for `get`, `update`, `patch` and `delete`. Empty string literals
are not permitted inside selector arrays. Set values are sorted for the frozen
identity, but equivalent alternative selector spellings need not have identical
canonical bytes. Version changes remain explicit requirement changes.

```sh
dune exec soundcheck -- profile kubernetes-rbac --contract-version 4 --format json
```

CLI, frozen MCP, evidence bundles, the approved-base Action and the submitted
repair evaluator use the contract-selected profile. Input preparation and the
supported resource/rule inventory are unchanged. Synthetic acceptance tests
replay concrete counterexamples through the pinned Kubernetes authorizer;
finite reference checks do not independently prove universal selector coverage.

## Supported profiles

`kubernetes-rbac-v1.34-get-v1` references Kubernetes v1.34.0 and supports:

- One strict JSON Kubernetes `v1/List` of RBAC v1 Roles, ClusterRoles,
  RoleBindings and ClusterRoleBindings. JSON is also valid YAML; general YAML
  syntax and multiple documents are not accepted.
- Explicit object names/namespaces and validated labels/annotations. Direct
  verification rejects other metadata; [explicit preparation](#prepare-a-json-export)
  can remove only the supported bookkeeping fields before verification.
- Exact User, Group and ServiceAccount subjects. An omitted ServiceAccount
  namespace defaults to its RoleBinding's namespace; ClusterRoleBindings
  require it explicitly. User/Group and roleRef API groups must be explicit.
- Additive grants, local and cluster role references, namespace-scoped bindings,
  cluster-wide bindings, literal resourceNames and supported wildcards.
- Named `get` requests for core ConfigMaps/Secrets. Namespaces are DNS1123 labels
  of 1..63 bytes; object names are DNS1123 subdomains of 1..253 bytes.

`kubernetes-rbac-v1.34-read-v1` uses the same snapshot/identity boundary, adding
the schema-2 list/watch request classes described above. Get still requires a
nonempty namespace and name. List/watch additionally permit empty effective
namespace and/or name. Other verbs, resources, API groups, subresources and
nonempty names outside the DNS bounds are outside the request domain.

`kubernetes-rbac-v1.34-read-write-v1` retains the read domain and adds named
update/patch/delete for those same resources. The snapshot and identity boundary
is unchanged. Other write verbs, resources, API groups and subresources remain
outside the request domain.

All supplied objects are checked, including unbound roles and unrelated
bindings. Malformed input, unknown fields, duplicate identities, missing
references, aggregation rules and nonResourceURLs return `unknown`. Escaped
NULs remain distinct; duplicate JSON keys, invalid Unicode and trailing data
are rejected. Unsupported forms are never silently discarded.

**Completeness is an external assumption.** Resolving every supplied role
reference does not establish that all applicable bindings were included. The
input describes complete desired policy state: applying a partial manifest
does not delete omitted live bindings. Deployment reconciliation must establish
the state that was verified.

**No grant is not final denial.** The decision is RBAC `Allow` versus
`NoOpinion`. Other authorizers, authentication, impersonation, admission, object
existence, aggregation/reconciliation controllers, mutation effects and escalation
checks are outside these models. Schema-1 restrictions on `get` do not rule out
Secret exposure through `list` or `watch`. Schema 2 can cover those direct read
grants, but pod creation and other indirect exposure paths remain outside it.

Preservation ranges over all supported valid namespace/name strings for the
frozen identities, not just namespaces present in the input. Schema 2 includes
the all-namespace collection endpoint; schema 3 also includes named writes.
All exclude identities, verbs, resources and control planes outside their
selected profile.

## Output and integrations

Both RBAC commands emit report schema 10. Violations include `object_request`,
`identity_groups` and `granting_rules`; legacy HTTP fields are unused placeholders.
Preservation uses a `must_preserve` clause with before/after RBAC decisions in
its description. Only `proved` exits `0`; violation/unknown/vacuous/inconsistent
exit `3`/`4`/`5`/`6`. I/O and usage failures exit `1` and `2`.

Use `--format human`, `json` or `github`. GitHub annotations identify the exact
typed object request, groups and granting rules; a preservation failure names
the before/after decision change. An annotation retains the same exit code as
the JSON result. Non-proof results and I/O failures are error annotations;
only a proof is a notice.

RBAC exposes CLI, library, frozen MCP and reusable Action workflows. The web UI
remains Kong-specific.

## Frozen MCP workflow

Start the server with an independently reviewed contract. An optional baseline
enables repair-preservation checks:

```sh
eval "$(opam env)"
dune exec soundcheck -- mcp --connector kubernetes-rbac \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json \
  --baseline bench/kubernetes-rbac/fixtures/01-unsafe.json
```

The contract and baseline files are read at startup and retained for the entire
session. Editing or deleting those files later does not replace the loaded
requirements or baseline. A baseline must be supported by the snapshot reader;
it may violate the contract because it represents the configuration to repair.
Restart the server after independently approving different startup inputs.

Both tools accept exactly `{"config": "<candidate snapshot JSON>"}`:

- `verify` checks the candidate's frozen access contract.
- `compare` checks that contract and preservation outside the approved change
  scope against the startup baseline. It is advertised only when a baseline was
  supplied. Tool discovery includes its SHA-256 identity.

Tool arguments cannot override the contract, identities, groups, change scope,
baseline, solver or evidence destination. Each tool returns the ordinary report
schema 10 as text and structured content. `violated` and `unknown` are verifier
outcomes, not transport errors. Invalid tool arguments are JSON-RPC errors.
The server accepts candidate bytes directly; it does not read candidate paths,
run an agent, modify files or contact a Kubernetes cluster.

The stdio adapter uses the existing `2024-11-05` MCP handshake: initialize, then
`notifications/initialized`, followed by tool requests. It accepts strict UTF-8
JSON objects, one per line, with string or decimal-integer request IDs and a
16 MiB encoded-message limit. Duplicate keys and YAML syntax are rejected;
escaped candidate bytes are preserved. Oversized frames are discarded through
the next newline so a following valid message remains usable. Normal output
contains protocol messages only. See the pinned [MCP lifecycle](https://modelcontextprotocol.io/specification/2024-11-05/basic/lifecycle)
and [stdio transport](https://modelcontextprotocol.io/specification/2024-11-05/basic/transports).

Keep the server executable, startup arguments, contract and baseline under
operator control. Freezing tool arguments is not a sandbox for an agent that
can replace or restart the verifier. `verify` alone establishes no preservation
result; repair acceptance requires `compare` or the equivalent CLI check.

## GitHub Action

Select RBAC explicitly in the trusted caller workflow:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: ph0smet/soundcheck@<reviewed-full-commit-sha>
    with:
      connector: kubernetes-rbac
      config: rbac-snapshot.json
      contract: contracts/rbac-access.json
```

`config` is the candidate's complete desired snapshot, in the strict JSON
format above. `contract` is a fixed repository-relative path resolved from the
immutable PR base commit or protected-default-branch push commit. A candidate's
edited contract cannot replace that approved blob. The selector defaults to
`kong`; unknown or empty selectors fail before verification.

The default `mode: verify` calls `rbac verify --format github`. It checks required
and forbidden grants without claiming preservation outside the change scope.

For repair acceptance on pull requests, select `mode: repair` in a trusted job:

```yaml
on: [pull_request]
permissions:
  contents: read
jobs:
  rbac-repair:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: ph0smet/soundcheck@<reviewed-full-commit-sha>
        with:
          connector: kubernetes-rbac
          mode: repair
          config: rbac-snapshot.json
          contract: contracts/rbac-access.json
```

Repair mode calls `rbac compare` with two approved inputs from the **same
immutable PR base commit**: the contract at `contract` and the baseline at
`config`. Only the candidate comes from the checkout's `config` file. Both
approved inputs must be regular Git blobs, and their commit/path/blob identities
are logged. Candidate edits cannot replace the baseline, widen the approved
change scope or select an alternative baseline revision.

The base snapshot may violate the contract because it is the policy being
repaired. The candidate must satisfy the contract and preserve all modeled
decisions outside its approved change scope. The operator-regression example
passes `verify` but fails `repair`.

The fixed config path must already exist in the PR base. A missing, non-regular,
malformed or unsupported baseline fails the gate; it never falls back to
verification. Repair mode requires `kubernetes-rbac` and a `pull_request` event.
It rejects pushes: the push's after commit cannot also serve as a meaningful
before snapshot. Protected-default-branch pushes can still use explicit/default
`verify` mode. New contract or baseline selection requires independent review.

Use a fresh trusted Ubuntu job and a reviewed full Action commit SHA. Protect
the workflow, mode, connector choice and both fixed paths, and approve requirements
separately. Required checks, branch protection and fresh-base reruns remain
repository responsibilities. See the [Action trust boundary](../README.md#github-action)
for supported events, runner requirements and dependency assumptions.

## Verification evidence

Add `--evidence-dir NEW_DIRECTORY` to `rbac verify` to retain an audit bundle:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/fixtures/03-valid-repair.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json \
  --format json --evidence-dir /tmp/soundcheck-rbac-verify-evidence
```

The destination must not exist; its parent must exist. Evidence schema 2 contains
the normalized frozen contract (including identities, groups, completeness and
change scope), complete assurance profile, report, exact input digest and byte
count, verifier/solver provenance, and every planned SMT obligation. The raw
snapshot is not copied. Executed SAT models retain exact named identities and
object coordinates and have passed obligation validation. Obligations skipped
after a decisive result remain present as `not_executed`.

Unsupported snapshots produce an `unknown` report and an explicitly unavailable
plan. Invalid contracts and input I/O errors produce no bundle. Requesting
evidence preserves normal report output and verdict exit codes on success;
an evidence write error exits `1` without printing a successful report.
The private directory and files are created exclusively. `manifest.json` is
published last; a failed write may leave an incomplete directory without it.

Queries permit formula replay, not independent checking of an UNSAT certificate,
the parser or the target model. A saved query's trailing `get-value` can produce
a model-unavailable error after `unsat` during direct batch Z3 replay; Soundcheck's
solver executes the observation only after SAT. Retained formulas, contracts,
reports and models can contain sensitive identifiers even though raw snapshots
are omitted. Review bundles before sharing. The web UI does not accept RBAC
bundles.

## Repair-comparison evidence

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/fixtures/01-unsafe.json \
  bench/kubernetes-rbac/fixtures/03-valid-repair.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json \
  --format json --evidence-dir /tmp/soundcheck-rbac-compare-evidence
```

Comparison uses evidence schema **3**, with `operation: "repair_comparison"`.
Single-snapshot verification, including Kong, continues to use schema **2**.
Both commands still emit report schema 10. Comparison bundles bind the exact
baseline and candidate bytes separately as `inputs.before` and `inputs.after`
(SHA-256 and byte count); neither raw snapshot is copied. They retain the same
frozen contract, complete profile, provenance and hashed payloads as verification.

`candidate-report.json` records the candidate's access-contract result;
`report.json` records the final comparison result. All candidate queries and the
`preservation-outside-change-scope` query are planned before solving. The latter
has phase `preservation`, and searches for any changed RBAC decision outside the
approved change scope for the frozen identities within the supported profile.

- A proved candidate followed by UNSAT preservation produces a proved comparison.
- A candidate contract failure keeps its verdict; the preservation query remains
  present as `not_executed`, with no solver result or model. Its existence is not
  evidence that preservation was checked.
- A preservation counterexample or solver failure leaves the successful candidate
  report intact and records `violated` or `unknown` in the final report.
- An unsupported baseline or candidate prevents the comparison plan. The manifest
  has `obligation_plan.status: "unavailable"`, a reason, no queries and a null
  `candidate_report`; the candidate contract was not executed. Both byte digests
  are still recorded. Invalid contracts and unreadable inputs produce no bundle.

The same exclusive-write, manifest-last, exit-code and sensitivity rules apply.
Schema-2 consumers must reject comparison bundles unless explicitly updated to
understand both stages. No Kong comparison or web UI evidence support is implied.

## Submitted-repair evaluation

The experimental [RBAC repair evaluator](../bench/repair/RBAC.md) evaluates an
ordered set of candidate files against an evaluator-owned suite:

```sh
eval "$(opam env)"
dune exec bench/repair/rbac_main.exe -- \
  bench/repair/rbac-examples/suite.yaml \
  bench/repair/rbac-examples/submissions.yaml
```

Contracts, identity contexts, approved change scopes and exact baseline bytes
are frozen before submission metadata is read. Each attempt invokes the same
contract-plus-preservation comparison once. The summary binds input digests and
records both stages, including an unavailable candidate stage when an unsupported
snapshot prevents comparison planning. Unknowns and input/tool failures receive
no acceptance credit, and missing tasks remain in the schedule.

The seven included candidates are hand-authored synthetic controls: four fail
the contract, one breaks an unrelated operator's permission, one is unsupported,
and one is a valid repair. They validate evaluator behavior, not AI performance.
The command emits a minimized experimental summary without raw configurations,
witnesses, formulas or diagnostics. No agent or cluster is contacted.

## Validation

Ordinary `dune test` runs parser, preparation, core, contract, preservation, CLI,
MCP, Action gate and submitted-repair regressions without Go or network access. The [reference harness](../bench/kubernetes-rbac/conformance/README.md)
compares concrete and production SMT decisions with Kubernetes' actual pinned
authorizer, on original input bytes, and replays CLI witnesses. Its separate
[preparation corpus](../bench/kubernetes-rbac/preparation/README.md) compares
original and prepared typed policy inventories and decisions, including
deliberately corrupted outputs. Finite agreement is implementation evidence,
not proof of parser/encoder correctness or a live-cluster guarantee.
