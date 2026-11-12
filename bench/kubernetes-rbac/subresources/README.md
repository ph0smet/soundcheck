# Subresources: synthetic Kubernetes RBAC conformance

This campaign checks opt-in contract schema 7 against the production Kubernetes
v1.34.0 RBAC authorizer. It retains schema 6's eight base resource/group pairs
and adds eight explicit subresource entries with 19 installed operations:

| Request API group | Resource/subresource | Initial RBAC verbs |
| --- | --- | --- |
| core (`""`) | `pods/log` | `get` |
| core | `pods/exec` | `get`, `create` |
| core | `serviceaccounts/token` | `create` |
| core | `pods/status`, `services/status`, `nodes/status` | `get`, `update`, `patch` |
| `apps` | `deployments/status`, `deployments/scale` | `get`, `update`, `patch` |

Every new operation uses a **nonempty parent name from the URL**, including
POST exec and TokenRequest. This differs from top-level collection create,
whose authorization name remains empty. Only Node/status is cluster-scoped.
TokenRequest and Scale response API groups do not replace the request group.

The catalogue is derived from pinned route installation and storage handlers;
it is not inferred from which arbitrary authorization attributes a wildcard
rule accepts. For example, the native RBAC authorizer can allow a fabricated
`pods/scale` request under `*`. Soundcheck must still reject it as outside the
approved operation catalogue. The suite exercises this distinction directly.

The [runner](../conformance/run_subresources.py) freezes literal policy
experiments and expected outcomes before consulting the production model.
[inputs.json](inputs.json) binds all 210 generated artifacts, including original
policy bytes, request tuples, HTTP methods and bodies, paired contracts,
baselines, the catalogue, and expected grants/verdicts. Missing, changed or extra
input pins fail the run. [source-pins.json](source-pins.json) also binds 18 actual
upstream source files under the downloaded Kubernetes and apiserver modules.
Module metadata, module pins, harness sources, and executable hashes are recorded
before execution and checked again before completion.

The frozen campaign contains:

- 460 requests across 30 literal policy cases: 13,800 native/concrete/SMT
  comparisons. Controls include base/subresource separation, exact and wildcard
  groups, exact resource names, `*/subresource`, nonmatching `parent/*` and `*/*`,
  per-operation verbs, named versus empty create, RoleBinding scope, full frozen
  identities/groups, additive grants and already-resolved aggregates.
- 39 paired-contract and repair cases, requiring 22,800 finite native checks.
  Every installed operation has a named-parent functionality/safety contract.
  Namespace/name selectors, lost functionality, Node/status scope, and narrow
  exec repair are covered. Matched schema-6/schema-7 cases show the added
  preservation domain, including permissions belonging to an identity absent
  from the clauses. Further controls distinguish approved base create from
  exec create, GET exec from POST exec, and different parent names. Base
  collection-write preservation remains covered in schema 7.
- 96 raw URL/body cases under five policies: 480 native attribute/decision
  checks, with supported tuples also replayed through concrete and SMT paths.
  Bodies include mismatching names/namespaces and malformed text. Named GET
  queries cannot replace the parent or turn log following into RBAC `watch`.
- 102 schema-7 rejections and all 140 new matrix requests rejected under the
  unchanged schema 6. Unsupported operations do not become `NoOpinion`.
- Five clause-counterexample and eight preservation-counterexample replays.
  Consumers check exact operation coordinates, frozen identity/groups, parent
  name, clause membership, approved-change boundaries and actual native
  Allow/NoOpinion differences. No solver-selected witness value is pinned.

These are synthetic initial-authorization experiments. No cluster is contacted,
no API operation is executed, and this is not a deployment benchmark. The model
does not prove successful exec, returned log/status contents, token issuance,
request-body validity, changed fields, admission, controller behavior, or
resulting privileges. Kubernetes 1.35's default-enabled
`AuthorizePodWebsocketUpgradeCreatePermission` adds a create check to WebSocket
exec; that extra check is absent from pinned 1.34.0. TokenRequests can also face
NodeRestriction binding/audience checks after initial authorization. Finite
agreement is not universal proof of the parser, encoder or target model.

Source boundaries are independently documented in pinned
[request parsing](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go),
[attribute projection](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/filters/authorization.go),
[route installation](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/installer.go),
[RBAC rule matching](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac.go),
[resource/name matching](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/evaluation_helpers.go),
[Pod connect handlers](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/core/pod/rest/subresources.go),
[TokenRequest handling](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/core/serviceaccount/storage/token.go),
and [Deployment status/scale handling](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/apps/deployment/storage/storage.go).

Run the integrated suite from the repository root:

```sh
bash bench/kubernetes-rbac/conformance/run.sh
```

For reference-only validation before a production implementation is available:

```sh
python3 bench/kubernetes-rbac/conformance/run_subresources.py \
  --native-only \
  --reference _build/rbac-conformance/reference-oracle \
  --module-metadata _build/rbac-conformance/kubernetes-module.json \
  --output _build/rbac-conformance/subresources-native/results.json
```

A native-only receipt explicitly records its mode and zero production rejection
and witness-replay counts. It is not complete production conformance evidence.
Normal results appear at `_build/rbac-conformance/subresources/results.json`;
`before-execution.json` records the frozen inputs, sources and tools before any
analyzer executes. Failed runs preserve diagnostics and never mark completion.

The standalone [contract.json](contract.json) requires access to logs for Pod
`settings` in `team-a`, forbids POST exec there, and approves changes only to that
exec decision. After inputs are materialized, replay its narrow repair with:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac compare \
  _build/rbac-conformance/subresources/artifacts/contracts/minimal-exec-repair/baseline.json \
  _build/rbac-conformance/subresources/artifacts/contracts/minimal-exec-repair/snapshot.json \
  --contract bench/kubernetes-rbac/subresources/contract.json \
  --format json
```

Expected result: `proved`, relative to the initial RBAC model and assumptions.
Required log permission remains; POST exec loses its grant; every modeled
decision outside the approved change scope is preserved.
