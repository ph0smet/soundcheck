# Fixed resource domains: synthetic Kubernetes RBAC conformance

This corpus checks contract schema 5 against Kubernetes v1.34.0. It is synthetic
acceptance evidence, not an operator-reviewed deployment or a comparison with a
linter. No Kubernetes cluster is contacted.

The fixed catalogue is core ConfigMaps, Secrets, Pods, Services, Endpoints and
Nodes; `apps` Deployments; and `discovery.k8s.io` EndpointSlices. It covers initial
RBAC authorization for `get`, `list`, `watch`, and named `update`, `patch`, `delete`,
with no subresource. Nodes use an empty authorization namespace. Namespaced
collection endpoints can also use an empty namespace, with different meaning.
Nonempty effective authorization names use the explicitly bounded DNS1123
subset; these tests do not validate object bodies or prove that an API operation
will execute successfully.

The [campaign](../conformance/run_resources.py) declares expectations before
running any analyzer. [inputs.json](inputs.json) pins all 87 generated input
artifacts, including expected decisions, contracts and comparison outcomes.
Generation is deterministic, and the runner refuses missing, extra or changed
pins. Original synthetic policy bytes go directly to the native authorizer.
The standalone [contract.json](contract.json) deliberately mentions only
ConfigMaps and Secrets: schema 5 still preserves decisions across all eight
resources, including resources absent from those clauses.

The campaign contains:

- 14 policy matrices, each with 260 concrete requests: 3,640 literal/native/
  concrete-connector/production-SMT comparisons. Cases cover exact and wildcard
  API groups/resources, wrong group/resource pairs, literal lookalike wildcards,
  Role and ClusterRole binding scope, literal `resourceNames`, empty collection
  names, and a second identity.
- 15 contract and repair cases. They exercise Deployment repairs, required-access
  loss, Node authorization, all-namespace collections, API-group mistakes, and
  preservation regressions on Nodes and EndpointSlices absent from the clauses.
  Matched schema-4/schema-5 cases show that old contracts retain their original
  ConfigMap/Secret preservation domain while schema 5 detects Pod/Node changes.
- 83 native URL extraction cases, including all six verbs, named and unfiltered
  collections, exact-name selectors, grouped APIs, all-namespace requests and
  Nodes. Five controls remain outside the model: Namespace requests, a Pod
  subresource, create and deletecollection. In particular, named Namespace paths
  have a different authorization namespace from Nodes and cannot be modeled by
  simply treating both as empty-namespace resources.
- 20 explicit model-domain rejections, including the five URL controls. No
  unsupported request may receive a supported decision.
- Native replay of each contract and preservation witness, including exact
  decoding of `deployments.apps` and `endpointslices.discovery.k8s.io` back to
  their API group/resource pairs. Replays check the frozen identity, request
  domain, clause or approved-change boundary, and actual native decision.

The native URL boundary and RBAC implementation come from the pinned upstream
modules, rather than a second parser or authorizer written for this campaign:
[`RequestInfo`](https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/endpoints/request/requestinfo.go),
[`RuleAllows`](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac.go),
[rule matching](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/evaluation_helpers.go),
and [binding resolution](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go).

Run the complete pinned conformance suite from the repository root:

```sh
bash bench/kubernetes-rbac/conformance/run.sh
```

Its resource results are written to
`_build/rbac-conformance/resources/results.json`, with inputs, subprocess output,
SMT matrices and witness replays under the sibling `artifacts/` directory. A
failed run retains its diagnostics and does not report completion. Inputs,
campaign source and tool binaries are checked for mutation during execution.
Finite agreement does not prove encoder correctness for every possible input.

After the suite materializes the synthetic inputs, the Deployment repair can be
replayed through the CLI:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac compare \
  _build/rbac-conformance/resources/artifacts/contracts/deployment-minimal-repair/baseline.json \
  _build/rbac-conformance/resources/artifacts/contracts/deployment-minimal-repair/snapshot.json \
  --contract _build/rbac-conformance/resources/artifacts/contracts/deployment-minimal-repair/contract.json \
  --format json
```

The expected result is `proved`, relative to the frozen domain and assumptions.
The candidate keeps required Deployment reads and removes the forbidden patch
grant outside `team-a`, preserving every other modeled decision. Variants that
also remove the operator's Node or EndpointSlice access must fail preservation.
