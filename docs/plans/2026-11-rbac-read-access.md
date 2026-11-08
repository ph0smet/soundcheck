# Kubernetes RBAC read authorization

Sourav approved this batch after PR #64: get/list/watch for core ConfigMaps and
Secrets, including all-namespace collections, name restrictions, repair
preservation and independent Kubernetes conformance. Ship coherent commits on
`feat/rbac-read-access`; Sourav opens and merges the PR.

## Frozen requirements and request boundary

Contract schema 1 keeps its canonical form, named-get domain and assurance
profile. Schema 2 uses the same contract kind and identity context, with a
required singular `verb` (`get`, `list`, `watch`) in each clause/change scope.
Its profile is `kubernetes-rbac-v1.34-read-v1`.

For schema 2, a namespace string selects that exact namespaced endpoint. Null
selects exactly the all-namespace collection endpoint, not all namespaced
endpoints. Get requires a nonempty namespace and object name. List/watch also
permit empty effective authorization namespace/name. Nonempty namespaces and
names retain the existing DNS/length bounds.

`names: null` selects every supported effective authorization name: named get,
or both empty and DNS-valid names for list/watch. A nonempty name list selects
literal effective names. Empty-name-only requirements are not expressible in
this version. Empty strings, wildcard names, missing verbs and unsupported
request selectors in contracts fail closed.

The modeled name is an authorization attribute, not a returned object. The
pinned API server can extract it from an exact `metadata.name` selector or a
legacy named watch path. Empty means no effective exact-name restriction, not
necessarily an HTTP request without selectors. Raw HTTP parsing is not a new
Soundcheck input surface. Concrete out-of-profile attributes are rejected.

The [pinned authorizer](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac.go)
uses literal resource-name matching. An absent/empty `resourceNames` list is
unrestricted; `[""]` matches empty effective Name; `["*"]` is literal and
matches no supported DNS name. [Binding resolution](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go)
does not consult RoleBindings for the all-namespace endpoint. A namespace field
selector does not change that endpoint's authorization namespace.

The shared request representation, solver, report schema 10 and evidence schemas
2/3 already carry verb/name/namespace. Profile and frozen-contract identity
select their meaning; old contracts are never silently widened. Preprocessing
continues using the unchanged snapshot parser and receipt format.

## Delivery and acceptance

1. Versioned contracts, read domain/lowering, preservation, accurate reports and
   profile/evidence selection, with focused regressions and bounded documentation.
2. Independent read conformance: upstream RequestInfoFactory and authorization
   attributes from raw URLs, production RBAC decisions, concrete/SMT comparison
   and witness replay; retain the original named-get/preparation suites.
3. Adapter acceptance and runnable examples for CLI/evidence, frozen MCP and the
   approved-base Action, including preservation across verb and endpoint scope.

Each commit receives clean-worktree build/regression checks. Reference tests
include empty/literal/wildcard names, exact versus nonexact selectors, malformed
ListOptions, legacy watch paths, namespace-filtered all-namespace URLs, group
and cluster grants, get-only repairs leaving list/watch access, deny-all repairs
and unrelated operator regressions. Every supported witness has a canonical
ordinary URL for upstream replay. Original expectations are not weakened.

This proves static RBAC Allow/NoOpinion relative to the frozen context and
complete snapshot. It does not prove API execution, object existence, response
contents, watch stream behavior, admission, other authorizers, aggregation,
mutation, impersonation or indirect Secret exposure. No live cluster is used.
