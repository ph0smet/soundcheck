# Fixed resource catalogue for RBAC contract schema 5

Following PR #72, Sourav approved this bounded scope on 2026-11-12: add Pods,
Services, Endpoints, EndpointSlices, Deployments and Nodes through an explicit
contract-version opt-in. Preserve schemas 1–4 exactly. Namespaces, custom
resources, new verbs and subresources remain separate work.

## Frozen meaning

Schema 5 requires `api_group` and the raw plural `resource` in every clause and
approved-change scope. It retains schema-4 namespace/name selectors and the six
verbs `get`, `list`, `watch`, `update`, `patch`, `delete`. Its complete catalogue:

| API group | Resources | Request scope |
| --- | --- | --- |
| `""` | configmaps, secrets, pods, services, endpoints | Namespaced |
| `apps` | deployments | Namespaced |
| `discovery.k8s.io` | endpointslices | Namespaced |
| `""` | nodes | Cluster |

For namespaced resources, named operations require a nonempty namespace;
list/watch also admit empty namespace for the all-namespace endpoint. Nodes
require `namespace: null` for every verb; their authorization namespace is empty.
All named operations require a nonempty effective authorization name.
List/watch also admit empty names, with the existing explicit selector semantics.

The request-name subset remains DNS1123 subdomains of at most 253 characters;
nonempty namespaces remain DNS1123 labels of at most 63. These are explicit
authorization-domain restrictions, not object-body validators or complete HTTP
request coverage. A supported request can still address a nonexistent object,
an unavailable route, or a name rejected during later API execution.

Preservation quantifies **all eight resources** for every frozen identity,
including resources absent from clauses. An approved change matches its exact
group/resource pair. A later catalogue expansion requires another opt-in; it
must not change schema 5's frozen meaning. Schemas 1–4 retain their old canonical
bytes, profiles and ConfigMap/Secret request/preservation domains.

## Lowering and target evidence

The shared IR already admits a connector-defined resource-kind discriminator.
Map the fixed catalogue injectively: bare core plural, `deployments.apps`, or
`endpointslices.discovery.k8s.io`, following Kubernetes'
[`GroupResource.String`](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apimachinery/pkg/runtime/schema/group_version.go).
Use exact registry lookup, not arbitrary string splitting. Raw contract and
evaluation fields reject qualified aliases. The shared core and report/evidence
shapes stay unchanged; schema-5 profile JSON uses schema 3 to expose the catalogue.

Lower each rule by matching raw API group and raw resource separately, before
selecting its discriminator. Kubernetes' pinned
[rule matching](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/evaluation_helpers.go)
uses exact membership or whole `*` wildcards. ResourceNames are literal;
subresource-only rules cannot grant these base-resource requests. The
[resolver](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go)
consults RoleBindings only for a nonempty authorization namespace. Therefore
those bindings cannot grant supported Nodes or all-namespace collections.

Namespaces are deliberately excluded: the pinned
[request parser](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go)
sets authorization namespace to the Namespace object's name for named paths,
while collection paths retain empty namespace. Treating them like Nodes would
miss grants. No live cluster contact is needed for the native reference checks.

## Acceptance

Freeze synthetic inputs and expected decisions before execution. Compare native
Kubernetes v1.34.0 authorization, concrete lowering and SMT decisions. Cover
exact/wildcard/wrong API groups; resource-name restrictions; namespaced bindings
to local/cluster roles; Node and collection boundaries; and all supported verbs.
Exercise native URL extraction independently of manually supplied attributes.
Replay grouped-resource and Node contract/preservation counterexamples through
the native authorizer, checking identity, domain, clause and approved changes.

Regressions must establish stable old canonical contracts and domains; v4 must
ignore a Pod/Node-only change that v5 detects outside `change_scope`, including
an identity/resource absent from clauses. Exercise CLI, profile review, evidence,
frozen MCP and trusted-base CI gates. Unknown contract schemas, unsupported
contract/evaluation pairs or aliases, invalid Node namespace scopes, new verbs
and subresource request scopes fail closed. Out-of-domain policy rules are
retained and cannot grant a request unless their raw dimensions also match it.

These checks support initial RBAC authorization fidelity, not universal
implementation correctness, final API denial, mutation success, controller or
workload effects, escalation safety, or deployment completeness. Public benchmark
inputs/results remain external; owner-reviewed pilot inputs remain pending.
