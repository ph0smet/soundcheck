# Kubernetes RBAC

Soundcheck checks paired access requirements and repair preservation within
bounded static RBAC profiles. Contract schema 1 checks named `get`; schema 2
adds `list` and `watch`; schema 3 adds named `update`, `patch` and `delete` for
core ConfigMaps and Secrets. Schema 4 adds namespace sets/complements and
precise effective-name selectors over that same request domain.
Schema 5 explicitly expands the resource catalogue to include Pods, Services,
Endpoints, EndpointSlices, Deployments and Nodes, with API-group-aware access
and preservation. Schema 6 adds `create` and `deletecollection` over that
catalogue, with empty authorization names and explicit namespace scope.
Schema 7 adds a fixed catalogue of Pod log/exec, ServiceAccount token and
selected status/scale subresource operations, each with its own allowed verbs.
Older contracts keep their original domains.
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

Without `--input-format`, input remains one strict JSON `apiVersion: v1`,
`kind: List`. Use the [explicit manifest mode](#prepare-rendered-manifests)
below for YAML streams, typed Lists or individual objects.
The 16 MiB input limit and all policy checks still apply, including
[aggregate consistency](#already-resolved-aggregated-clusterroles), invalid mixed resource/URL rules, duplicate identities and unresolved
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

## Prepare rendered manifests

Use `--input-format yaml` for a UTF-8 YAML stream, or `--input-format json`
for a single strict JSON object or List. Feed already-rendered Helm/Kustomize
output saved to a file; Soundcheck does not render templates or contact a cluster.

```sh
dune exec soundcheck -- rbac prepare \
  bench/kubernetes-rbac/preparation/manifests/rendered.yaml \
  --input-format yaml --namespace frontend --rbac-only \
  --receipt /tmp/rendered-rbac-receipt.json > /tmp/rendered-rbac.json
dune exec soundcheck -- rbac verify /tmp/rendered-rbac.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
```

This synthetic bundle contains five RBAC objects plus a ServiceAccount and
ConfigMap. Preparation succeeds; verification still detects its unwanted Secret
grant and exits `3`. The namespace context and contract are explicit inputs;
neither is inferred from the accompanying ServiceAccount.

- Individual RBAC objects, generic `v1/List` containers and RBAC v1 `RoleList`,
  `RoleBindingList`, `ClusterRoleList`, `ClusterRoleBindingList` are accepted.
  Supported Lists may nest. Typed Lists infer item `kind` and `apiVersion` only
  when **both** are absent or empty strings; partial, null or conflicting type
  metadata is rejected. Generic Lists require explicit child types.
- `--namespace NAME` fills only absent/empty Role/RoleBinding metadata namespaces.
  Explicit namespaces stay intact. This is a defaulting context, **not** a
  confinement boundary or proof of deployment context. Choose the context intended
  for deployment. Cluster-scoped objects and subject namespaces are not rewritten;
  a ServiceAccount subject still inherits its RoleBinding's effective namespace
  under existing RBAC semantics. ClusterRoleBinding ServiceAccounts need an
  explicit namespace. User/Group and roleRef API groups still must be explicit.
- Mixed bundles require `--rbac-only`. Every RBAC object is retained, including
  unbound roles and unrelated bindings. Excluded objects are identified by source
  location, API version and kind in the receipt. Their syntax and scalar fidelity
  are checked, **not** their Kubernetes schemas or workload security. Unsupported
  RBAC kinds/versions, unknown List wrappers and other objects with top-level
  `items` cannot be silently excluded. Kubernetes's unstructured reader treats
  `items` as a List even without a `List` kind suffix.
- Pagination is checked on every accepted List. Duplicate identities, unresolved
  references, unsupported rules and the metadata restrictions above still fail.
  No selected RBAC objects is an error. A successful selection does not establish
  that the bundle contains the complete relevant cluster inventory.

YAML uses a deliberately bounded subset matching Kubernetes's YAML 1.1 scalar
resolution. Quote intended strings such as `"on"`, `"no"` and `"123"`. Canonical
decimal int64 values retain exact precision, including integers above 2^53;
timestamps, resource quantities and dotted version strings remain text. Floats,
noncanonical numeric spellings, out-of-range integers, tags, anchors, aliases,
merge keys, non-string mapping keys, duplicate keys and NUL escapes are rejected
throughout the source, including excluded documents. Use strict JSON input for
numeric syntax outside this YAML subset; do not change a numeric field to a
string merely to pass preparation. YAML is limited to 16 MiB, 128 nesting levels,
4,096 documents and 250,000 nodes. Only genuinely empty/comment-only documents
are skipped and accounted for; explicit `null` documents are rejected.

Manifest mode emits a **schema-2 preparation receipt** when `--receipt` is supplied.
It retains the schema-1 identity and assurance fields and adds input format,
document count, selection mode, namespace context, source-to-snapshot object
locations, List wrappers, excluded objects, empty documents and every defaulted
field/value. Removed metadata paths refer to the original `documents[i]` and
nested `.items[j]` locations. No policy values or removed metadata values are
copied into the receipt. The same exclusive-file/private-permission rules apply.
Keep the source, receipt and normalized snapshot together for review.

The entire input must parse and the resulting inventory must pass the unchanged
strict snapshot reader before a receipt or stdout snapshot is published. The
legacy preparation command and its schema-1 receipts are unchanged. Verification,
comparison, MCP and CI still consume normalized JSON snapshots; these preparation
options do not change frozen contracts or the authorization model.

## Assemble an explicit inventory

An application manifest can reference roles supplied elsewhere, such as a
cluster's bootstrap policy. `rbac inventory` combines explicitly selected local
sources into one strict snapshot. It does not fetch resources or fill missing
roles automatically. The [synthetic example](../bench/kubernetes-rbac/inventory/README.md)
supplies application bindings and an upstream-generated two-role Kubernetes
v1.34.0 reference excerpt:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac inventory \
  bench/kubernetes-rbac/inventory/plan.json \
  --receipt inventory-receipt.json > inventory.json
dune exec soundcheck -- rbac inspect inventory.json \
  --contract bench/kubernetes-rbac/inventory/contract.json
dune exec soundcheck -- rbac verify inventory.json \
  --contract bench/kubernetes-rbac/inventory/contract.json --format json
```

The strict JSON plan has `schema_version: 1`, `kind: "kubernetes-rbac-inventory"`
and an ordered `sources` array. Each source requires:

- `id`: a unique lowercase DNS label, at most 63 bytes.
- `path`: a local regular file; relative paths use the plan's directory.
- `sha256`: the exact source bytes' SHA-256, as 64 lowercase hexadecimal digits.
- `format`: `json` or `yaml`, with the same bounded syntax as manifest preparation.
- `source_type`: `supplied` or `bootstrap-reference`.

Optional `namespace` and `rbac_only` apply the same explicit defaults/selection
as manifest preparation. `source_version` is an optional caller-declared label;
it is required for `bootstrap-reference`. Unknown fields and duplicate IDs
reject. Plans contain 1–64 sources, at most 16 MiB combined source bytes; the
existing parser, object and final snapshot limits still apply. Plan and source
files must be regular files; symbolic-link inputs reject.

Every source is read once, hashed and normalized from those same bytes. Partial
fragments may have unresolved role references only during assembly. The union
retains **every selected RBAC object**, including unrelated supplemental bindings
and unbound roles. Duplicate object identities reject even when their contents
are identical. Every role reference must resolve in the union, with all missing
references reported by source location, binding and exact role identity. Ordinary
preparation and verification still reject incomplete references.

An optional **schema-1 inventory receipt**, kind `rbac-inventory-assembly`, binds
the exact plan, ordered source identities/settings, per-source transformations,
object origins and final snapshot. This is a distinct protocol from preparation
receipts. Source-local retained objects use `object_index`; final objects use
`snapshot_index` plus `source_id`, `source_path` and object identity. The receipt
records caller-declared versions and `assumed_bootstrap_sources`; verification,
authenticity and completeness flags are false. It uses the existing private,
exclusive receipt creation rules. Receipt-write failure emits no stdout snapshot.
Exit `0` means assembly succeeded, `2` invalid/unsupported input or usage, and `1`
I/O failure. Neither inventory assembly nor inspection invokes the solver,
kubectl, Helm or Kustomize.

Pins detect different bytes; they do not authenticate a source. Review and
protect the plan and source selection independently: successful reference
resolution cannot discover omitted grants. A versioned upstream bootstrap
excerpt is an **assumption about policy**, not a cluster export. Real clusters
can retain extra permissions or customize/disable default-role reconciliation.
Use actual authorized inventory when available; do not replace an exported role
with a same-name default to make assembly pass. The example is not the complete
bootstrap policy, which includes semantics still outside this profile.

## Review frozen identities

`rbac inspect SNAPSHOT.json --contract CONTRACT.json` reads the same strict
snapshot and frozen contract as verification and emits a JSON review report.
It shows each exact username and sorted group list, with matching binding/role
identities, matching subjects and the role's rule count. These are
`subject_matching_bindings`: an empty role or rules outside the modeled request
domain can match a subject without authorizing a modeled request.

The report binds raw snapshot/contract bytes and the canonical frozen contract.
It does not infer groups from a ServiceAccount name or from bindings, authenticate
users, inspect tokens, contact a cluster, evaluate authorization, or prove access.
`snapshot_completeness_asserted_by_contract` records the existing contract
assertion, while `completeness_established` remains false. User/group input must
come from independently trusted identity context; review it before freezing the
contract. Changing that context requires a separately reviewed contract, not an
inspection override. Success exits `0`; invalid input exits `2`, I/O failure `1`.
Reports contain usernames, groups, policy names and contract contents; handle
them with the same care as those input artifacts.

## Frozen contract

For a requirements-first walkthrough, use the [schema-4 authoring example](../bench/kubernetes-rbac/workflows/authoring/README.md).
It separates the workload's ServiceAccount namespace from target namespaces,
supplies trusted identity groups explicitly, and pairs required ConfigMap reads
with forbidden grants and an independently approved repair scope.

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

### Check the contract before choosing a candidate

```sh
dune exec soundcheck -- rbac check-contract \
  bench/kubernetes-rbac/workflows/authoring/contract.json
```

This read-only command uses the same strict contract reader as verification and
prints a human-readable review of schemas 1–8: the selected profile, exact declared
identities and groups, ordered clause meanings, approved changes, and separate
SHA-256 hashes for the raw artifact and canonical frozen contract. Artifact counts
are reported after normalization; they measure size, not human authoring effort.
It takes only a contract file, has no overrides or JSON report format, and invokes
neither a solver nor Kubernetes. It does not rewrite or generate requirements.

**Exit 0 means structurally parsed, not verified.** An inconsistent contract can
parse successfully. Inhabitation, consistency, access and repair
preservation remain unchecked; use `rbac verify` and `rbac compare` for those
solver-backed obligations. Keep those verification commands as CI gates.
Invalid input/usage exits `2`, and I/O failure exits `1`. The input must be a
regular file, at most 16 MiB. Review output includes identity names and groups.

The descriptions make the following choices explicit:

| Authoring choice | Meaning |
| --- | --- |
| `namespace: null` | Only the all-namespace list/watch endpoint, not every namespaced request |
| Namespace `exclude` in schema 4 | Valid nonempty namespaces outside the set; the global collection endpoint is separate |
| `names: null` | All names in that verb's supported domain, including the empty effective name for list/watch |
| `names: {"empty": true}` | Only the empty effective list/watch authorization name; schema 4 |
| `change_scope` | Requests allowed to change during a repair; candidate access requirements still apply there |

Diagnostic errors identify the relevant field or selector member. Correct the
artifact against independently reviewed intent; do not broaden a requirement,
drop a group, substitute another verb, or flip `snapshot_complete` merely to make
it parse. Missing role references name all affected bindings and targets; obtain
the omitted roles from reviewed sources, using explicit inventory assembly when
needed. Resolving references does not establish completeness. Unsupported
aggregation-controller semantics must not be erased from input to obtain a proof.

## Read-access contracts (schema 2)

The [runnable read-access repair demo](../bench/kubernetes-rbac/workflows/read-access/README.md)
pairs a frozen schema-2 contract with unsafe, partial-repair, valid-repair,
deny-all and operator-regression snapshots.

Schema 2 keeps the same `kind`, frozen identity context, paired clause kinds and
approved `change_scope`. Every clause and change-scope entry also requires a
singular `verb`: `get`, `list` or `watch`. The contract selects the
`kubernetes-rbac-v1.34-read-v3` profile. Existing schema-1 artifacts, canonical
identities and get-only preservation semantics keep their meaning;
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
request. Preparation still checks the shared snapshot format; its receipt
`target_profile` identifies snapshot support, not the contract-selected profile
of a later verification.

## Named write-access contracts (schema 3)

The [runnable named-write repair demo](../bench/kubernetes-rbac/workflows/write-access/README.md)
includes an incomplete repair, required manager writes and an unrelated
Secret-rotation regression caught only by repair comparison.

Schema 3 retains the schema-2 fields and adds `update`, `patch` and `delete` to
the allowed verbs. It selects `kubernetes-rbac-v1.34-read-write-v3`. Existing
schema-1/2 contracts keep their meaning; selecting schema 3 is a
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

Schema 4 selects `kubernetes-rbac-v1.34-scoped-read-write-v3`. It retains the
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

## Resource and API-group contracts (schema 5)

Schema 5 selects `kubernetes-rbac-v1.34-resource-read-write-v1`. It keeps the six
verbs and scope selectors from schema 4, but requires an explicit `api_group`
alongside the raw plural `resource` in **every clause and change scope**, including
`api_group: ""` for core resources. Its fixed catalogue is:

| `api_group` | `resource` | Scope | Counterexample `resource_kind` |
| --- | --- | --- | --- |
| `""` | `configmaps` | Namespaced | `configmaps` |
| `""` | `secrets` | Namespaced | `secrets` |
| `""` | `pods` | Namespaced | `pods` |
| `""` | `services` | Namespaced | `services` |
| `""` | `endpoints` | Namespaced | `endpoints` |
| `apps` | `deployments` | Namespaced | `deployments.apps` |
| `discovery.k8s.io` | `endpointslices` | Namespaced | `endpointslices.discovery.k8s.io` |
| `""` | `nodes` | Cluster | `nodes` |

For example, these two clauses require a deployment patch grant while forbidding
direct Node reads for the same independently declared identity:

```json
[
  {
    "name": "deploy-web", "kind": "must_allow", "subject": "deployer",
    "verb": "patch", "api_group": "apps", "resource": "deployments",
    "namespace": "apps", "names": ["web"]
  },
  {
    "name": "no-node-read", "kind": "must_not_grant", "subject": "deployer",
    "verb": "get", "api_group": "", "resource": "nodes",
    "namespace": null, "names": null
  }
]
```

These are clauses, not a complete contract. Supply the existing trusted
`context`, paired clauses, and separately reviewed `change_scope` in a
`schema_version: 5`, `kind: "kubernetes-rbac-access"` artifact. No identity,
requirement or approved change is inferred from candidate grants.

For namespaced resources, `namespace: null` still means only the all-namespace
list/watch endpoint. Named get/update/patch/delete require a nonempty namespace.
For Nodes, `namespace: null` is required for **every** supported verb and means
cluster scope; namespace strings and include/exclude selectors are rejected.
A RoleBinding cannot grant these Node requests, even when it references a
ClusterRole containing Node rules. ClusterRoleBindings can supply the grant.

Nonempty effective authorization names remain restricted to DNS1123 subdomains
of at most 253 characters, and nonempty namespaces to DNS1123 labels of at most
63 characters. Named operations require nonempty names; list/watch also admit
the empty effective name with the existing selector meanings. This is a bounded
authorization-request domain, **not object-body name validation** or complete
HTTP request coverage. It does not establish that an object or API route exists,
or that a subsequent mutation would accept the name or body.

Group and resource must match separately. `apps` is not `extensions`; a core
rule for `deployments` does not grant an `apps` Deployment request. Whole `*`
wildcards in policy rules match within this fixed catalogue; wildcard contracts,
qualified contract aliases such as `deployments.apps`, and subresource request
scopes are rejected. Policy rules for other resources or subresources remain
retained input; they cannot grant a request in this base-resource domain unless
the same rule also matches its supported group/resource pair. The qualified
notation in the table is the lossless **output**
discriminator, not another input spelling.

Repair preservation covers all eight catalogue entries for every frozen
identity, including entries absent from the clauses. An approved change to
Deployment access does not permit changing Node access. Upgrading from schema 4
to 5 therefore requires independent review of intent and preservation scope;
it is not a mechanical version-number edit. Existing schemas 1–4 retain their
original canonical identities, profile IDs and smaller preservation domains.

```sh
dune exec soundcheck -- profile kubernetes-rbac --contract-version 5
dune exec soundcheck -- profile kubernetes-rbac --contract-version 5 --format json
```

Profile JSON schema 3 exposes each `resource_domains` entry's group, resource,
scope and discriminator. Report schema 10 and evidence shapes remain unchanged.
The [synthetic resource corpus](../bench/kubernetes-rbac/resources/README.md)
compares literal expectations, concrete/SMT decisions and pinned Kubernetes
authorization, including replay of grouped and cluster-scoped witnesses.

Namespaces need separate modeling: named Namespace paths carry their name in
the authorization namespace attribute, unlike Nodes. They remain excluded,
alongside custom resources, subresources and indirect privilege escalation.
Create/deletecollection require the separate schema-6 opt-in below.
Deployment/Pod grants do not establish anything about
workload behavior, secret exposure through execution, admission or mutation
effects. See the [scope and target-source record](plans/2026-11-rbac-resource-domains.md).

## Collection-write contracts (schema 6)

Schema 6 adds initial RBAC authorization for `create` and `deletecollection`
over the same eight-resource catalogue. For example, require a workload to
create Pods in `frontend`, while forbidding bulk Pod deletion there. A repair
that removes both permissions fails the required-creation clause.

```json
{
  "schema_version": 6,
  "kind": "kubernetes-rbac-access",
  "context": {
    "schema_version": 1,
    "snapshot_complete": true,
    "identities": [{"username": "app", "groups": []}]
  },
  "clauses": [
    {"name": "required-creation", "kind": "must_allow", "subject": "app",
     "verb": "create", "api_group": "", "resource": "pods",
     "namespace": "frontend", "names": {"empty": true}},
    {"name": "forbidden-bulk-deletion", "kind": "must_not_grant", "subject": "app",
     "verb": "deletecollection", "api_group": "", "resource": "pods",
     "namespace": "frontend", "names": {"empty": true}}
  ],
  "change_scope": [
    {"subject": "app", "verb": "deletecollection", "api_group": "",
     "resource": "pods", "namespace": "frontend", "names": {"empty": true}}
  ]
}
```

These two verbs use an **empty effective authorization name**. `names: null`
and `names: {"empty": true}` both select that singleton; name lists and
complements are rejected. A create request's body `metadata.name` or
`generateName` does not constrain its initial RBAC permission. Likewise,
`fieldSelector=metadata.name=example` on collection DELETE does not become an
authorization name. This differs from the supported list/watch name-selector
behavior. Soundcheck does not interpret the body or model which objects a
deletion filter selects.

Namespaced collection writes require a nonempty namespace, or a reviewed
namespace include/exclude selector. `namespace: null` is rejected for those
resources; it does not mean “write across every namespace.” Nodes still require
`namespace: null` for cluster scope and can receive grants only through
ClusterRoleBindings. Named POST paths, subresources and non-resource URL
authorization remain outside this profile.

Policy `resourceNames` are literal: an omitted or empty list is unrestricted;
`["example"]` and `["*"]` do not match the new empty-name requests, while
**`[""]` does**. Such an empty-string grant does not restrict created/deleted
objects by name. Named `delete` and `deletecollection` are distinct verbs;
granting one does not grant the other unless another rule or wildcard does.
The [pinned-source scope record](plans/2026-11-rbac-collection-writes.md)
links the Kubernetes parser, matcher and authorization boundary behind these rules.

The profile is `kubernetes-rbac-v1.34-collection-write-v1`. Its JSON remains
profile schema 3, declaring contract version 6 and all eight verbs. Report
schema 10 and evidence shapes are unchanged. Use:

```sh
dune exec soundcheck -- profile kubernetes-rbac --contract-version 6
dune exec soundcheck -- profile kubernetes-rbac --contract-version 6 --format json
```

Preservation covers all eight verbs and all eight resources for **every frozen
identity**, including dimensions absent from clauses. Adding or removing a
creation/bulk-deletion grant outside `change_scope` fails repair verification.
Schema 5 intentionally retains its six-verb preservation domain; an upgrade
requires independent review of the broader requirements and approved changes.
Schemas 1–5 keep their canonical bytes, domains and profile IDs.

All interfaces use the same frozen contract: CLI/library verification and
comparison, contract review, evidence, config-only MCP, trusted-base CI repair
gates and submitted-repair evaluation. A proof concerns initial RBAC grants,
not mutation success, body contents, admission, extra authorization checks,
controller/workload effects or the number/identity of deleted objects.

The [synthetic collection-write corpus](../bench/kubernetes-rbac/collection-writes/README.md)
compares literal expectations, native Kubernetes, concrete lowering and SMT,
including body/selector controls and replay of contract/preservation witnesses.

## Subresource contracts (schema 7)

Schema 7 can require Pod log access while forbidding exec grants, or restrict
Deployment scaling to named deployments. It retains every schema-6 base
operation and adds exactly these subresource operations:

| API group | Resource/subresource | Initial RBAC verbs |
| --- | --- | --- |
| core (`""`) | `pods/log` | `get` |
| core | `pods/exec` | `get`, `create` |
| core | `serviceaccounts/token` | `create` |
| core | `pods/status`, `services/status`, `nodes/status` | `get`, `update`, `patch` |
| `apps` | `deployments/status`, `deployments/scale` | `get`, `update`, `patch` |

Every added operation uses the **nonempty parent object name**. For example,
POST to `/api/v1/namespaces/frontend/pods/worker/exec` has verb `create`, resource
`pods`, subresource `exec` and name `worker`. This differs from base Pod creation,
whose initial authorization name is empty. The URL supplies the parent name;
body fields and query selectors do not replace it. Log `follow=true` remains
`get`, and exec uses `get`/`create`, not an RBAC verb named `connect`.

Every clause and change scope now requires a separate `subresource` string;
use `""` for base resources. This example keeps log access to `worker` and
forbids both initial exec verbs in `frontend`:

```json
{
  "schema_version": 7,
  "kind": "kubernetes-rbac-access",
  "context": {
    "schema_version": 1,
    "snapshot_complete": true,
    "identities": [{"username": "app", "groups": []}]
  },
  "clauses": [
    {"name": "required-log", "kind": "must_allow", "subject": "app",
     "verb": "get", "api_group": "", "resource": "pods", "subresource": "log",
     "namespace": "frontend", "names": ["worker"]},
    {"name": "forbidden-exec-get", "kind": "must_not_grant", "subject": "app",
     "verb": "get", "api_group": "", "resource": "pods", "subresource": "exec",
     "namespace": "frontend", "names": null},
    {"name": "forbidden-exec-create", "kind": "must_not_grant", "subject": "app",
     "verb": "create", "api_group": "", "resource": "pods", "subresource": "exec",
     "namespace": "frontend", "names": null}
  ],
  "change_scope": [
    {"subject": "app", "verb": "get", "api_group": "", "resource": "pods",
     "subresource": "exec", "namespace": "frontend", "names": null},
    {"subject": "app", "verb": "create", "api_group": "", "resource": "pods",
     "subresource": "exec", "namespace": "frontend", "names": null}
  ]
}
```

For these named subresources, `names: null` means all supported nonempty parent
names. Name sets and complements with `include_empty: false` work as before;
empty-only scopes and `include_empty: true` reject. Namespaced subresources
require a nonempty namespace or an include/exclude selector. Nodes/status
requires `namespace: null` and can receive grants only through cluster-wide
bindings. Existing DNS name/namespace bounds apply. Base collection-write
names remain empty even in schema 7; there is no global rule that all `create`
requests have empty names.

Kubernetes resource matching is precise:

- `pods` grants base Pod operations, not log or exec operations.
- `pods/exec`, `*/exec` and whole `*` can match Pod exec; `pods/*` and `*/*`
  are **not** general subresource wildcards.
- `resourceNames: ["worker"]` can restrict exec/token creation to that parent.
  Omitted/empty arrays are unrestricted; `[""]` and `["*"]` do not grant any
  supported named subresource operation by themselves.
- Deployment scale uses API group `apps`; token requests use the core group.
  Their response objects' API groups do not change the request authorization.

The [pinned-source scope record](plans/2026-11-rbac-subresources.md) explains the
request parser, matcher, installed routes and version boundaries. Unsupported
combinations such as `pods/scale`, `list pods/log`, or base ServiceAccount
operations reject. A native RBAC wildcard can allow a fabricated resource name;
that does not establish a real API endpoint or expand Soundcheck's catalogue.

The profile is `kubernetes-rbac-v1.34-subresources-v1`. Profile JSON schema 4
lists `operations` for each resource entry, including `verb`, `name_domain`
and `namespace_domain`. Domains are `named`, `empty` or `empty-or-named`.
Consumers must use these per-entry combinations, not multiply all verbs by
all resources. Report schema 10 and evidence shapes remain unchanged:

```sh
dune exec soundcheck -- profile kubernetes-rbac --contract-version 7
dune exec soundcheck -- profile kubernetes-rbac --contract-version 7 --format json
```

Repair preservation covers **all supported base and subresource operations for
every frozen identity**, including operations absent from clauses. Removing a
log grant or changing an unrelated scaling grant fails unless the exact change
is approved. Base and subresource change scopes are distinct. Schemas 1–6 keep
their canonical identities, profiles and original preservation domains; a
schema upgrade requires independent review of the expanded scope.

The guarantee is initial Kubernetes v1.34.0 RBAC `Allow | NoOpinion`, not exec
success, token issuance, response contents, admission or final authorization.
GET on status endpoints can return the full underlying object, not just status
fields. Newer Kubernetes versions can require additional `create` permission
for WebSocket GET exec, and token issuance can involve separate NodeRestriction
audience authorization. These checks and operational effects are outside this
profile. CLI/library, review, evidence, frozen MCP, trusted-base CI and
submitted-repair evaluation all use the same selected contract and catalogue.

The [synthetic subresource corpus](../bench/kubernetes-rbac/subresources/README.md)
compares frozen expectations with native Kubernetes, concrete lowering and SMT,
including URL/body controls and contract/preservation witness replay.

## Server-side apply contracts (schema 8)

An identity may be allowed to patch an existing Deployment without being allowed
to recreate it if missing. Schema 8 checks these two conditional server-side
apply (SSA) branches independently:

| `operation` | RBAC prerequisites at the same caller and target |
| --- | --- |
| `apply-existing` | Named `patch` |
| `apply-missing` | Named `patch` **and** named `create` |

These labels describe the branch taken by storage, not live object existence
discovered by Soundcheck. A proof establishes the RBAC prerequisites for that
branch, assuming the complete static snapshot and trusted identities. It does
not establish that an apply request will succeed.

The scope is the eight existing base resources: core ConfigMaps, Secrets, Pods,
Services, Endpoints and Nodes, apps Deployments, and discovery.k8s.io EndpointSlices.
SSA requires `subresource: ""` and a nonempty target name. Namespaced resources
require nonempty namespace scopes; Nodes require `namespace: null`.
Existing name/namespace sets and complements work within those domains.
`names: null` selects every supported nonempty target name; empty-name selectors
and complements with `include_empty: true` reject for SSA.

For example, this complete contract requires applying updates to `web` while
forbidding its recreation in `frontend`:

```json
{
  "schema_version": 8,
  "kind": "kubernetes-rbac-access",
  "context": {
    "schema_version": 1,
    "snapshot_complete": true,
    "identities": [{"username": "deployer", "groups": []}]
  },
  "clauses": [
    {
      "name": "update-existing-web", "kind": "must_allow",
      "subject": "deployer", "operation": "apply-existing",
      "api_group": "apps", "resource": "deployments", "subresource": "",
      "namespace": "frontend", "names": ["web"]
    },
    {
      "name": "do-not-recreate-web", "kind": "must_not_grant",
      "subject": "deployer", "operation": "apply-missing",
      "api_group": "apps", "resource": "deployments", "subresource": "",
      "namespace": "frontend", "names": ["web"]
    }
  ],
  "change_scope": [
    {
      "subject": "deployer", "operation": "apply-missing",
      "api_group": "apps", "resource": "deployments", "subresource": "",
      "namespace": "frontend", "names": ["web"]
    }
  ]
}
```

The additional SSA `create` authorization uses the **named URL target**.
A policy rule granting `create` with `resourceNames: ["web"]` can satisfy it,
although that rule cannot grant ordinary collection creation, whose initial
authorization name is empty. Patch and create may come from different bindings
or roles, but must both match the same frozen identity and target coordinates.
There is no added caller `get` or `update` prerequisite.

`must_allow` on `apply-missing` requires both checks to grant. `must_not_grant`
requires at least one to lack a grant; it does not forbid patch and create
individually. In the example, removing a local, named create grant can stop
recreation while retaining patch access. Removing a broader grant may change
other permissions and fail preservation.

Schema 8 uses `operation` **instead of** `verb` in every clause and change scope,
including retained operations such as `"get"`, `"patch"` and `"create"`.
Mixed fields and arbitrary operation IDs reject. All previous base/subresource
request classes remain in its domain, for 99 resource/operation combinations.
Schemas 1–7 keep their syntax, domains, profiles and canonical identities;
changing the contract version requires separate review of intent.

Preservation covers every supported operation for every frozen identity,
including dimensions absent from clauses. Ordinary `patch` and `apply-existing`
have the same authorization predicate but are separate approved-change classes.
Allowing a patch permission change does not automatically allow an apply-existing
change. Preservation compares **aggregate operation decisions**, not intermediate
grants: if patch remains absent, a named-create change does not by itself change
the `apply-missing` result.

```sh
dune exec soundcheck -- profile kubernetes-rbac --contract-version 8
dune exec soundcheck -- profile kubernetes-rbac --contract-version 8 --format json
```

Profile `kubernetes-rbac-v1.34-apply-v1` uses profile JSON schema 5. Its per-resource
operations name the native `checks`, hypothetical `object_state` (null for
initial operations), and name/namespace domains. Concrete evaluation inputs
also require `operation` instead of `verb` for schema 8. Report schema 10 and
evidence formats stay unchanged. Counterexample `action` is the operation ID;
successful SSA `granting_rules` identify source rules with `patch:`/`create:`
prefixes. A partial compound grant has `granting_rules: []`; human/GitHub output
explains the missing prerequisites. These explanations are conditional
evaluations, not execution traces: an ungranted initial patch prevents the
handler from reaching additional create authorization.

The [pinned-source scope record](plans/2026-11-rbac-apply-authorization.md) describes
the actual Kubernetes v1.34 handler/store checks and independent conformance
requirements. CLI, library, frozen MCP, trusted-base CI, evidence and submitted
repair evaluation share the same contract. Candidate configuration cannot choose
a different operation branch, change scope or contract version.

The model excludes body validation, field ownership conflicts, admission, other
authorizers, live existence, races, mutation success and resulting workload
effects. SSA on subresources, PUT create-on-update, unsafe deletion and other
operation-specific checks remain separately scoped. The retained native request
operations still describe initial RBAC authorization only.

The [synthetic apply corpus](../bench/kubernetes-rbac/apply/README.md) compares
conditional authorization, frozen repair decisions and counterexample replays
with pinned Kubernetes. It is separate from the external public-config pilot.

## Supported profiles

The profile IDs for schemas 1–4 end in `-v3`. This revision accepts already-resolved,
acyclic aggregated ClusterRoles alongside the resource/URL rule coexistence
introduced in `-v2`. Contract schemas 1–4, canonical contract identities and
quantified request domains are unchanged. Older profile IDs describe earlier
input boundaries; report/evidence/receipt schemas
retain their existing shapes and now identify the revised profile.

`kubernetes-rbac-v1.34-get-v3` references Kubernetes v1.34.0 and supports:

- One strict JSON Kubernetes `v1/List` of RBAC v1 Roles, ClusterRoles,
  RoleBindings and ClusterRoleBindings. Direct verification does not accept general
  YAML syntax or multiple documents; [explicit preparation](#prepare-rendered-manifests)
  can normalize supported manifests first.
- Explicit object names/namespaces and validated labels/annotations. Direct
  verification rejects other metadata; [explicit preparation](#prepare-a-json-export)
  can remove only the supported bookkeeping fields before verification.
- Exact User, Group and ServiceAccount subjects. An omitted ServiceAccount
  namespace defaults to its RoleBinding's namespace; ClusterRoleBindings
  require it explicitly. User/Group and roleRef API groups must be explicit.
- Additive grants, local and cluster role references, namespace-scoped bindings,
  cluster-wide bindings, literal resourceNames and supported wildcards.
- Separate non-resource URL rules in ClusterRoles, retained as policy content
  with no grants in the quantified resource-request domain.
- Already-resolved acyclic aggregated ClusterRoles, checked against their full
  selected policy and the explicit complete-inventory assumption described below.
- Named `get` requests for core ConfigMaps/Secrets. Namespaces are DNS1123 labels
  of 1..63 bytes; object names are DNS1123 subdomains of 1..253 bytes.

`kubernetes-rbac-v1.34-read-v3` uses the same snapshot/identity boundary, adding
the schema-2 list/watch request classes described above. Get still requires a
nonempty namespace and name. List/watch additionally permit empty effective
namespace and/or name. Other verbs, resources, API groups, subresources and
nonempty names outside the DNS bounds are outside the request domain.

`kubernetes-rbac-v1.34-read-write-v3` retains the read domain and adds named
update/patch/delete for those same resources. The snapshot and identity boundary
is unchanged. Other write verbs, resources, API groups and subresources remain
outside the request domain.

`kubernetes-rbac-v1.34-resource-read-write-v1` uses that same snapshot/identity
boundary, including aggregate consistency and URL-rule coexistence, with the
schema-5 resource catalogue and request domains described above. Its `-v1`
suffix identifies the first revision of this broader resource profile.

`kubernetes-rbac-v1.34-collection-write-v1` retains that snapshot, identity and
resource boundary, adding the schema-6 empty-name create/deletecollection
request classes described above. Existing profiles do not gain these verbs.

`kubernetes-rbac-v1.34-subresources-v1` retains the schema-6 base domain and adds
the eight subresource entries above. Its operation catalogue is explicit in
profile JSON schema 4. Existing profiles do not gain subresource obligations.

`kubernetes-rbac-v1.34-apply-v1` retains every schema-7 operation and adds the
conditional SSA branches for the eight base resources. Profile JSON schema 5
enumerates the prerequisite checks and hypothetical object states. Earlier
profiles remain initial-RBAC-only and do not gain compound obligations.

All supplied objects are checked, including unbound roles and unrelated
bindings. Malformed input, unknown fields, duplicate identities, missing
references, unsupported aggregate states and invalid URL/resource mixtures return `unknown`. Escaped
NULs remain distinct; duplicate JSON keys, invalid Unicode and trailing data
are rejected. Unsupported forms are never silently discarded.

### Non-resource rules in resource verification

A ClusterRole can contain separate rules for URLs such as `/version` and for
resources such as ConfigMaps. Soundcheck retains both. A URL-only rule cannot
satisfy a required ConfigMap read or introduce a Secret grant in this model,
even with `verbs: ["*"]` and `nonResourceURLs: ["*"]`. Resource wildcards in a
separate resource rule remain active.

The rule distinction follows Kubernetes v1.34 validation:

- A **nonempty** `nonResourceURLs` list is valid only on a ClusterRole and
  requires a nonempty `verbs` list. Its `apiGroups`, `resources` and
  `resourceNames` lists must each be absent, null or empty. A list containing
  `""` is nonempty and cannot be mixed into a URL rule.
- An absent, null or empty `nonResourceURLs` list is a **resource rule**. It
  still requires nonempty API-group/resource/verb lists. It must never be
  discarded merely because the URL field exists.
- All arrays and elements are type-checked. The pinned API does not validate
  URL-string syntax; strings are preserved literally without interpreting their
  wildcard placement or asserting that they describe reachable endpoints.
- A RoleBinding may reference a ClusterRole containing both kinds of rules.
  Its resource grants remain restricted to the binding's namespace. A Role
  itself cannot contain a nonempty URL rule, including when unbound.

Rule positions are preserved: if a URL rule precedes a resource grant, evidence
still names that resource grant's original `/rules/1` index. Preparation,
inventory receipts and snapshot hashes retain the complete URL policy.
Inspection counts every source rule; subject matches are not access decisions.

**URL authorization and preservation remain outside the model.** A URL-only
change may pass resource repair-preservation while changing `/version` access.
The changed snapshot still has a different hash. Use a separate review for that
URL change; this feature adds coexistence, not URL contracts or URL equivalence.
The request adapter continues to reject `resourceRequest: false`.

### Already-resolved aggregated ClusterRoles

Soundcheck accepts an aggregate only when its **stored rules already agree with
the rules selected from the complete ClusterRole inventory**. Kubernetes uses
stored rules for authorization and a separate controller fills them from selected
roles. An aggregate with `rules: []` can therefore gain permissions after
reconciliation. Soundcheck rejects this stale state when matching roles contribute
rules; it does not treat it as a safety proof or fill in the rules for you.

The check follows the pinned
[aggregation controller](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/controller/clusterroleaggregation/clusterroleaggregation_controller.go)
and [selector validation](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/validation/validation.go):

- `matchLabels` and `matchExpressions` support `In`, `NotIn`, `Exists` and
  `DoesNotExist`. Requirements inside one selector are ANDed; multiple selectors
  are ORed. An empty selector matches every role. `NotIn` also matches a missing
  label. Keys, values, operators and their value counts are validated.
- A role never selects itself. Other cycles between aggregates are rejected,
  including unbound cycles: controller ordering can affect which grants survive.
- Nested acyclic aggregates are supported. Expected rules come recursively from
  nonaggregate leaves, never from an aggregate's existing rules. Every aggregate
  must agree, even when no binding currently references it.
- Equality covers the **entire policy**: all verbs, API groups, resources, names
  and non-resource URLs. List order and duplicates do not affect this comparison;
  differently structured but equivalent rules are not merged. Missing and stale
  additional grants both cause rejection. Original rules and evidence indices
  are retained.
- A missing/null `aggregationRule` is ordinary policy. A nonnull rule needs at
  least one selector. An aggregate whose selectors contribute no rules is valid
  only with an empty stored rule set.
- When aggregates are present, the limit is 512 ClusterRoles, 1,024 selector units
  (one per selector, label pair, expression and expression value), and 100,000
  child-rule contributions across aggregate dependencies. Exceeding a limit
  rejects the snapshot without truncating it.

Preparation preserves labels, aggregate fields and rules. Multiple source files
may supply contributors through `rbac inventory`; consistency is checked after
assembly. This feature does not establish live controller convergence, safe
intermediate rollout states, future label/object changes or successful apply.
Verification and repair comparison still quantify only their selected resource
domain; aggregate consistency is not a URL-authorization or URL-preservation claim.

**Completeness is an external assumption.** Supply all applicable bindings and
the complete ClusterRole inventory with labels, including unbound roles that
selectors can match. Resolving every supplied role reference does not establish
that inventory completeness. The
input describes complete desired policy state: applying a partial manifest
does not delete omitted live bindings. Deployment reconciliation must establish
the state that was verified.

**No grant is not final denial.** The decision is RBAC `Allow` versus
`NoOpinion`; for schema-8 SSA, `Allow` requires every modeled prerequisite and
`NoOpinion` means at least one lacks a grant. Other authorizers, authentication, impersonation, admission, object
existence, live aggregation/reconciliation controllers, mutation effects and escalation
checks are outside these models. Schema-1 restrictions on `get` do not rule out
Secret exposure through `list` or `watch`. Schema 2 can cover those direct read
grants, but pod creation and other indirect exposure paths remain outside it.

Preservation ranges over all supported valid namespace/name strings for the
frozen identities, not just namespaces present in the input. Schema 2 includes
the all-namespace collection endpoint; schema 3 also includes named writes.
Schema 5 includes every entry in its fixed resource catalogue, including Nodes.
Schema 6 adds base collection writes; schema 7 adds every listed subresource
operation; schema 8 also adds both conditional SSA branches over every base
resource, including operations absent from the clauses.
All exclude identities, verbs, resources and control planes outside their
selected profile.

## Output and integrations

Both RBAC commands emit report schema 10. Violations include `object_request`,
`identity_groups` and `granting_rules`; legacy HTTP fields are unused placeholders.
The selected profile defines `resource_kind`: schemas 5 and 6 use qualified
discriminators for noncore resources. Schema 7 also identifies subresources,
for example `pods/exec`, `serviceaccounts/token` and `deployments/scale.apps`.
Decode by exact lookup in the profile catalogue, rather than splitting arbitrary
strings or assuming every request belongs to the core API group. For subresource
operations, `object_request.name` is the parent authorization name.
For SSA, `action` is `apply-existing` or `apply-missing`, and the object name
is the common target for its prerequisite checks. These are operation IDs,
not literal Kubernetes RBAC verbs.
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
