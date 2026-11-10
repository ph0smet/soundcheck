# Explicit inventory example

This synthetic extension API server example demonstrates combining two application
bindings with two explicit bootstrap role assumptions. It is not a deployment
evaluation or a complete Kubernetes bootstrap catalog.

From the repository root:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac inventory bench/kubernetes-rbac/inventory/plan.json \
  --receipt inventory-receipt.json > inventory.json
dune exec soundcheck -- rbac inspect inventory.json \
  --contract bench/kubernetes-rbac/inventory/contract.json
dune exec soundcheck -- rbac verify inventory.json \
  --contract bench/kubernetes-rbac/inventory/contract.json --format json
```

Choose a new receipt filename on each run. Inventory and inspection exit zero for
successful offline processing; only the final verification command reports a proof.
The contract expects `proved`, relative to its explicit complete-inventory and
identity assumptions. It requires reading/watching the named authentication
ConfigMap, forbids ConfigMap updates and Secret reads, and excludes an unrelated
user's Secret access. The effective watch authorization name is explicit; this
does not claim an unrestricted collection watch.

`application.yaml` deliberately has two unresolved role references by itself.
`plan.json` supplies `bootstrap-v1.34.0.json` by exact hash. Removing that source
reports both missing references. There is no automatic role insertion. The
`system:auth-delegator` rules are retained, but TokenReview and SubjectAccessReview
authorization is outside the current ConfigMaps/Secrets verification domain.
Inspection therefore reports its subject match without calling it a modeled grant.

The bootstrap file is generated from the pinned upstream Kubernetes module by
the conformance oracle's `--bootstrap-reference` mode:

```sh
# After building the pinned oracle as described in ../conformance/README.md:
_build/rbac-conformance/reference-oracle --bootstrap-reference > /tmp/bootstrap-reference.json
cmp /tmp/bootstrap-reference.json bench/kubernetes-rbac/inventory/bootstrap-v1.34.0.json
```

The generator selects `NamespaceRoles()["kube-system"]`'s
`extension-apiserver-authentication-reader` Role and `ClusterRoles()`'s
`system:auth-delegator` ClusterRole, retaining all native rules/metadata and
generating **no bindings**. `bootstrap-provenance.json` binds version, upstream
commit/module checksum, artifact checksum and exact selection. Kubernetes code
and derived policy are Apache-2.0; see the conformance oracle's
[license](../conformance/oracle/KUBERNETES-LICENSE).

The conformance suite regenerates the exact excerpt, independently decodes each
original source through Kubernetes, compares typed policy inventories and
reference/connector/SMT decisions, and checks a supplemental group grant plus
explicitly empty groups. A bootstrap default may differ from installed policy;
review source selection and use authorized actual exports for a real deployment.
