# Read-access reference corpus

These synthetic snapshots test contract schema v2 and the
`kubernetes-rbac-v1.34-read-v3` profile. They are not deployment samples or an AI
repair evaluation. Run them with the existing explicit command:

```sh
bash bench/kubernetes-rbac/conformance/run.sh
```

The read-access results are saved separately under
`_build/rbac-conformance/read-access/`. The original named-get and preparation
suites keep their own inputs and counters. No cluster or kubeconfig is used.

`cases.json` fixes each original snapshot's SHA-256, frozen contract, support
boundary, ordered failing clause, and optional repair expectation. The matrices
cover three fixed identities, ConfigMaps and Secrets, all three read verbs,
named and unnamed collection attributes, and namespace/all-namespace endpoints.
Each supported decision must agree between the production connector evaluator,
the production SMT encoding executed by Z3, and Kubernetes v1.34.0's RBAC
authorizer. The public read-access workflow is also checked, including actual
CLI counterexample replay.

The fixtures distinguish a get-only repair that leaves list/watch access,
required collection access, empty and literal-star `resourceNames`, exact
selected names, namespace RoleBindings versus ClusterRoleBindings, all-namespace
requirements, unrelated operator regressions, and the aggregation boundary.
An empty `resourceNames` array is unrestricted; a single empty string is a
literal match for an empty effective authorization Name. A literal `"*"` in
`resourceNames` is not a wildcard and is outside the valid object-name domain.

The named-exclusions case deliberately proves only that selected request class
is ungranted while an unnamed collection request remains allowed. A selected
name prohibition is not object confidentiality: an unfiltered collection may
still return that object. Use `names: null` to forbid the full list/watch request
class, as the main and public workflow contracts do.

`url-cases.json` independently fixes expected API-server request attributes for
raw request targets. The oracle executes the pinned
[RequestInfoFactory](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/request/requestinfo.go),
copies its fields into `AttributesRecord` as the pinned
[authorization adapter](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/filters/authorization.go)
does, and runs the production RBAC authorizer. That small value projection is
explicit in the harness; it does not call the full HTTP authorization filter.
Every projected field is checked. The separate original oracle mode still
accepts explicit attributes, so URL witnesses are replayed through both paths.

Exact `metadata.name` selectors can provide an effective Name for collection
list/watch authorization. Nonexact selectors do not. `metadata.namespace` does
not change the endpoint's authorization namespace. Legacy watch paths and
malformed list options have their own pinned extraction behavior. A selected
list/watch witness is replayed using a collection URL and exact name selector;
a named GET with `watch=true` remains a get authorization request.

The URL tests observe authorization attributes, not a successful HTTP operation.
They do not establish API route existence, object existence, storage selector
validity, admission behavior, returned object sets, or a composed authorizer's
final decision. Out-of-domain attributes are recorded and must produce model
`unknown`; they are never coerced into supported requests. Completeness and
authentication identities remain external assumptions. `NoOpinion` means no
RBAC grant, not final API-server denial.
