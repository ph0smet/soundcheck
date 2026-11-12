# Initial RBAC authorization for subresources

Following PR #74, Sourav approved this bounded schema-7 scope on 2026-11-12:
retain schema 6's base-resource domain and add the eight entries below. Schemas
1–6 retain their canonical identities, request/preservation domains and profiles.
No shared-core coordinate or report/evidence shape changes are required.

## Frozen operation catalogue

| API group | Resource/subresource | Initial RBAC verbs | Namespace |
| --- | --- | --- | --- |
| core (`""`) | `pods/log` | `get` | Nonempty |
| core | `pods/exec` | `get`, `create` | Nonempty |
| core | `serviceaccounts/token` | `create` | Nonempty |
| core | `pods/status` | `get`, `update`, `patch` | Nonempty |
| core | `services/status` | `get`, `update`, `patch` | Nonempty |
| core | `nodes/status` | `get`, `update`, `patch` | Empty |
| `apps` | `deployments/status` | `get`, `update`, `patch` | Nonempty |
| `apps` | `deployments/scale` | `get`, `update`, `patch` | Nonempty |

All 19 new operation combinations require the **nonempty parent authorization
name**. Names remain bounded to DNS1123 subdomains of at most 253 characters;
nonempty namespaces remain DNS1123 labels of at most 63 characters. The
operation catalogue is not a Cartesian product of all verbs and resources.
Base ServiceAccounts, other subresources, Namespaces and CRDs remain excluded.

Schema 7 requires explicit `api_group`, `resource` and `subresource` strings in
every clause and approved-change scope. Use `subresource: ""` for base resources;
combined resource aliases and wildcards are not contract selectors. For a named
subresource, `names: null` selects every supported parent name; name sets and
complements with `include_empty: false` are permitted. Empty-only selectors and
complements including empty names reject. Existing namespace selectors apply;
Nodes/status requires `namespace: null` and cannot receive RoleBinding grants.

Preservation quantifies all supported operations over all 16 entries for every
frozen identity, including dimensions absent from clauses. Approved changes
exclude only their exact identity/verb/group/resource/subresource/namespace/name
scope. A base-resource change scope does not authorize a subresource change.

The new assurance ID is `kubernetes-rbac-v1.34-subresources-v1`. Profile JSON
schema 4 declares each entry's operations and name/namespace domains (`named`,
`empty`, `empty-or-named`). Existing profile JSON remains unchanged. The finite
connector registry maps core entries to `resource[/subresource]`, and noncore
entries to `resource[/subresource].group`; decode by exact lookup, never by
splitting arbitrary strings. This retains the generic core's object-kind
coordinate and report schema 10. CLI/library, contract review, evidence, frozen
MCP, trusted-base CI and submitted-repair evaluation share these semantics.

## Independent target evidence

Pinned Kubernetes v1.34.0's
[request parser](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go#L177)
maps GET/POST/PUT/PATCH to get/create/update/patch, extracting the parent name
and subresource from the URL. Named requests do not acquire a replacement name
from body metadata or query selectors. In particular, exec/token POST is named,
unlike base collection create. The
[authorization filter](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go#L114)
copies these attributes into the authorizer request.

The [RBAC matcher](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/evaluation_helpers.go#L52)
supports exact combined resources, whole `*`, and `*/` followed by an exact
subresource. `pods/*` and `*/*` are not general subresource globs. Base `pods`
does not match `pods/log`. Resource names use literal equality: absent/empty
arrays are unrestricted; `["worker"]` restricts the parent; `[""]` and `["*"]`
do not match any supported named subresource request. Group/verb checks remain
separate from resource matching.

[Log](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/core/pod/rest/log.go#L81)
`follow=true` remains initial `get`.
[Exec](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/core/pod/rest/subresources.go#L199)
supports GET and POST; its admission operation CONNECT is not an RBAC verb.
[Token creation](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/core/serviceaccount/storage/token.go#L72)
uses a named creator and the core authorization group, regardless of the
response's `authentication.k8s.io` kind.
[Deployment scale](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/apps/deployment/storage/storage.go#L280)
uses the `apps` request group despite returning an `autoscaling/v1` Scale.
Checked-in [core OpenAPI](https://github.com/kubernetes/kubernetes/blob/v1.34.0/api/openapi-spec/v3/api__v1_openapi.json)
and [apps OpenAPI](https://github.com/kubernetes/kubernetes/blob/v1.34.0/api/openapi-spec/v3/apis__apps__v1_openapi.json)
independently enumerate GET/PATCH/PUT for the five selected status/scale routes.

Native RBAC Allow does not establish route existence. Upstream
[tests](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac_test.go#L235)
even allow fabricated `pods/scale` under `*/scale`. Such requests must reject
at the Soundcheck catalogue boundary, not become meaningful denied proofs.

## Guarantee and exclusions

The claim remains initial RBAC **Allow | NoOpinion**, not final API authorization,
admission, object/route existence, execution, token issuance, body validity,
response contents, changed fields or controller/workload effects. Status GET
can return the full underlying object; it is not a status-only projection.
The verifier consumes authorization attributes, not HTTP requests or bodies.

Extra authorization is separately scoped. Kubernetes 1.35 introduced the
default-on [WebSocket create-permission gate](https://v1-35.docs.kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/)
for some GET exec connections. Pinned 1.34's
[NodeRestriction](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/admission/noderestriction/admission.go#L623)
can additionally authorize ServiceAccount token audiences. Neither is implied
by an initial RBAC grant, and bound-object checks must not be invented as
general caller `get` prerequisites.

## Acceptance

Freeze synthetic inputs and source-derived expectations before production
comparison. Check every supported operation against native Kubernetes,
concrete lowering and SMT; test exact/wildcard/name/group/binding combinations,
additive grants and consistent aggregates. Native URL/body controls must expose
the exact initial attributes and distinguish named subresource creation from
base collection creation. Reject empty parents, wrong namespace forms,
unsupported verbs and fabricated catalogue entries, including native-Allow
controls. Preserve pre-change schema-1–6 profile and canonical goldens.

Pair required and forbidden grants; check deny-all, partial repairs, and
unmentioned identity/operation regressions. Replay both contract and preservation
witnesses natively, checking their frozen domain and scope. Exercise CLI, MCP,
evidence, trusted-base gates and submitted-repair evaluation without permitting
candidate-controlled schema/profile substitution. Bind reference evidence to
input, source, module and executable hashes; reject incomplete/mismatched data.
Full regressions and previous native suites must pass. Each eventual commit
must independently pass clean-worktree checks.

Keep public benchmark artifacts external and unchanged. Owner-reviewed
deployment and live-agent evaluations remain separate work requiring inputs.
