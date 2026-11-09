# Named-write reference corpus

These synthetic fixtures check contract schema v3 and profile
`kubernetes-rbac-v1.34-read-write-v1`. The supported domain retains get/list/watch
and adds named `update`, `patch`, and `delete` for core ConfigMaps and Secrets.
Every write request needs a valid nonempty namespace and object name, with no
subresource. This is offline authorization evidence, not deployment experience
or an AI evaluation.

Run the existing explicit harness:

```sh
bash bench/kubernetes-rbac/conformance/run.sh
```

Write results are separate at `_build/rbac-conformance/write-access/`. Existing
original, preparation, and read-access suites retain their inputs and counts.
The runner also requires each new write request to remain outside v1/v2
contracts; old contracts never silently acquire a larger preservation domain.
Each old version first accepts a named-get control with the same frozen identity,
groups, namespace, resource, and name, so write rejection cannot be explained
by a context mismatch.
Nothing downloads or runs a cluster as part of the normal `dune test` suite.

`cases.json` freezes exact fixture hashes and expected support, ordered contract
failures, and repair preservation. Cases include incomplete repairs, required
update/patch/delete access, named and wildcard grants, a surviving group grant
through a ClusterRoleBinding, literal empty/star `resourceNames`, a read
regression outside approved writes, and an unrelated operator write regression.
Subresource-only and create/deletecollection-only grants can coexist with a
proof over the bounded profile; that proof says nothing about those excluded
request classes. The aggregation fixture must remain unknown.

The upstream reference receives each original snapshot's exact bytes. Supported
matrix and URL-derived requests must agree across Kubernetes v1.34.0's production
RBAC authorizer, the connector's concrete evaluator, and its production SMT
encoding evaluated by Z3. Actual CLI contract and preservation witnesses are
replayed through both explicit attributes and raw URL parsing. Named write
witnesses use PUT, PATCH, or DELETE on the named resource path. Corruption tests
reject changed verbs, names, namespaces, profiles, frozen requirements, and
incomplete or mistyped reference responses.

The pinned
[RequestInfoFactory](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/request/requestinfo.go)
maps PUT to update, PATCH to patch, and a named DELETE to delete. Collection
DELETE becomes `deletecollection`; an exact name selector does not make it a
named delete. Query options do not replace a named write's path-derived name or
namespace. The existing oracle copies parsed fields into `AttributesRecord`
using the documented value projection; it does not reimplement this parsing or
the RBAC grant logic. No Go module or oracle protocol change is needed.

These are **initial request authorization attributes**, not a guarantee that an
operation succeeds or has acceptable effects. Bodies, patch content types,
object state, admission, and storage are outside the model. Server-side apply
may require an additional [create authorization](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/handlers/patch.go)
for an absent object. Special unsafe deletion can require an additional
[`unsafe-delete-ignore-read-errors` authorization](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/endpoints/handlers/delete.go).
URL cases with force/dry-run/special-deletion options observe
only the initial attribute mapping and do not claim those extra checks pass.
Snapshot completeness and authenticated identities remain external assumptions;
RBAC `NoOpinion` is not a final API-server denial.
