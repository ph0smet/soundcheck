# Explicit RBAC inventory and identity review

The approved inventory/identity roadmap slice addresses public-pilot inputs with
omitted bootstrap roles and identity context requiring independent review. Scope
is offline assembly and inspection; authorization profiles, frozen contract
schemas and verification/MCP/CI semantics are unchanged. Public benchmark inputs
and results stay external. No live cluster or owner-reviewed deployment is implied.

## Boundaries

`rbac inventory PLAN.json` composes 1–64 explicitly ordered, SHA-256-pinned local
JSON/YAML sources. Each source uses existing bounded manifest normalization, with
its own explicit namespace context and RBAC selection. Source descriptors are
strict and all are validated before reads. Hashing and normalization consume the
same bytes; combined source bytes are limited to 16 MiB. Paths are relative to
the plan directory, unless absolute. There is no rendering, discovery or fetch.

An opaque preparation fragment validates supported object semantics and local
duplicates without constructing a verification snapshot. Only reference closure
is deferred. All objects survive union, including supplemental bindings and
unbound roles. Reject duplicate identities across sources; resolve every reference
only after union; require the existing strict snapshot reader before publication.
Missing-reference diagnostics enumerate source locations and exact targets.
The ordinary preparation and verifier readers retain strict closure requirements.

The distinct schema-1 `rbac-inventory-assembly` receipt binds exact plan bytes,
ordered source hashes/settings/declarations, source-local transformation history,
all object origins and final output bytes. A fragment has no standalone snapshot
receipt. Versions and `bootstrap-reference` labels are caller declarations, not
authentication or evidence of installed state. All verification/authenticity/
completeness flags remain false; receipts use exclusive private creation.

`rbac inspect SNAPSHOT --contract CONTRACT` shows exact frozen identities/groups
and subject matches, reusing the target connector's subject matcher. It binds raw
input identities and canonical contract. It never derives intent or group
membership from policy, and matching bindings need not grant a modeled request.
Completeness is distinguished as an assertion versus an established fact. Importing
identity observations or contacting a cluster is outside this bounded feature.

## Bootstrap reference

Generate only `Role/kube-system/extension-apiserver-authentication-reader` and
`ClusterRole/system:auth-delegator` from the existing pinned Kubernetes v1.34.0
module. Use native typed objects/serializer, preserve every rule and metadata,
and generate no bindings. The synthetic application provides its own bindings.
The fixture is explicitly selected by a plan; it is never an implicit fallback.
Its provenance records the version, commit, module sum, artifact hash and selection.

Primary target sources:
[namespace policy](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/namespace_policy.go),
[cluster policy](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go),
[default reconciliation](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/rest/storage_rbac.go),
[subject matching](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go).
Reconciliation can retain extra permissions and default objects can be customized;
the fixture establishes source provenance, not live-state equality or completeness.
Full bootstrap policy includes unsupported semantics and is not silently projected.

## Acceptance

Regressions must cover pins, exact reads, all-source accounting, namespace-aware
closure, duplicate rejection, supplemental grants, full missing-reference reports,
exact identity groups, empty/out-of-domain subject matches, private exclusive
receipts and no external tool invocation. Legacy preparation receipts/closure
and all prior verification regressions must remain valid.

Native conformance regenerates the excerpt and decodes original sources through
Kubernetes before composing the native union. Compare original/prepared typed
policy inventories and native/concrete/production-SMT decisions; replay any
violated-contract witness. Independently audit source transformations and origins,
and reject fabricated receipts. Include supplemental group grants, exact empty
groups, missing bootstrap, duplicate roles and changed byte pins. These are
bounded synthetic checks, not universal implementation proofs or deployment results.
