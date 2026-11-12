# Initial RBAC authorization for collection writes

Following PR #73, Sourav approved this bounded scope on 2026-11-12: opt-in
contract schema 6 adds `create` and `deletecollection` over the existing eight
resource/group pairs. Schemas 1–5 keep their canonical identities, request and
preservation domains, and assurance profiles. No new shared-core coordinates or
report/evidence shapes are needed.

## Frozen meaning

Schema 6 retains schema 5's explicit `api_group`/`resource` fields, fixed resource
catalogue, trusted identities and existing six verbs. The two new verbs have
strictly **empty effective authorization names**. For them:

- `names: null` and `names: {"empty": true}` both select that singleton.
  Name lists and complements are rejected with an authoring diagnostic; they
  cannot express restrictions on created/deleted object names or contents.
- Namespaced resources require a nonempty namespace. Existing namespace
  include/exclude selectors apply, including namespaces absent from the snapshot.
  There is no all-namespace collection-write scope.
- Nodes require `namespace: null`, yielding an empty authorization namespace.
  RoleBindings cannot grant these cluster-scoped requests.

This is initial RBAC `Allow | NoOpinion`, not final authorization, mutation
success, admission, route/object existence, body validity, selected/deleted
objects, controller/workload effects, or indirect privilege escalation. Raw HTTP
and body/selector parsing remain outside the verifier; the native reference
harness exercises that boundary independently.

Preservation quantifies all eight verbs over all eight resources for every
frozen identity, including dimensions absent from clauses. Approved changes
match exact identity/verb/group/resource/namespace/name scopes. A new grant
outside that scope must fail even if all candidate clauses pass. An older
contract must not silently acquire collection-write preservation obligations.

The new assurance ID is `kubernetes-rbac-v1.34-collection-write-v1`. It uses
profile JSON schema 3, with `contract_schema_version: 6`, eight verbs and the
same explicit resource catalogue. CLI/library, contract review, evidence, frozen
MCP, trusted-base CI repair gates and submitted-repair evaluation share the
connector's semantics. Candidate-controlled contract/profile downgrades fail.

## Target semantics

Pinned Kubernetes v1.34.0
[RequestInfo](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go#L176)
maps collection POST to `create` and unnamed DELETE to `deletecollection`.
Names come from URL path segments. The exact `metadata.name` selector is
promoted into an authorization name only inside the GET/list/watch branch.
Therefore the same selector on collection DELETE leaves the name empty.

The [authorization filter](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go#L101)
copies these attributes. The later
[create handler](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go#L94)
decodes the body and derives the object name; that name must never replace the
initial authorization name. Named POST paths are outside the selected domain,
even though the generic request parser can extract named `create` attributes.

The [API installer](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/installer.go#L569)
places namespaced collection writes under a namespace. Only list/watch also get
all-namespace routes. Do not reuse the list/watch name/namespace-domain helper
to classify these writes.

[ResourceNameMatches](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/evaluation_helpers.go#L80)
uses literal equality. An omitted/empty `resourceNames` list is unrestricted;
`["x"]` or `["*"]` does not match an empty name. **`[""]` does match**, and
[policy validation](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/validation/validation.go#L103)
does not prohibit it. Preserve the original policy content and exact matcher;
do not treat every nonempty list as excluding collection writes. API groups,
resources and verbs retain their exact-or-whole-wildcard semantics.

## Acceptance

Freeze synthetic inputs and independently justified expected results before
execution. Compare literal expectations with pinned native Kubernetes, concrete
lowering and SMT decisions. Exercise every resource/new-verb pair; namespace,
identity and group isolation; exact/wildcard verbs/resources; all resourceNames
cases above; additive grants and consistent aggregates.

Native HTTP controls must distinguish filtered list/watch from filtered
deletecollection, show create body names/generateName do not affect initial
attributes, and distinguish named DELETE. Named POST, all-namespace namespaced
writes, subresources and non-resource URLs remain exclusion controls. Selector
parse errors do not turn an initial RBAC grant into an execution guarantee.

Contract/repair cases pair required creation with forbidden collection deletion;
a repair that preserves reads but removes required creation fails. Paired v5/v6
cases demonstrate the expanded preservation domain, including an unmentioned
identity/resource. Replay contract and preservation counterexamples natively,
checking the frozen domain, violated clause and change scope. Bind evidence to
input/source/tool hashes, reject missing/mismatched results, and preserve old
canonical/profile goldens. Full regressions and existing native suites must
pass; every eventual commit must independently pass clean-worktree checks.

Public benchmark artifacts remain external and unchanged. Owner-reviewed
deployment inputs, live-agent evaluation, Namespaces/CRDs, subresources and
extra operation-specific authorization are separately scoped work.
