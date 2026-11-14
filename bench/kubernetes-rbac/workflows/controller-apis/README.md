# Preserve controller access while removing webhook modification

This synthetic schema-10 example removes a controller's permission to patch
webhook configurations while preserving its required API access and an unrelated
reviewer's permissions. The requirements are independently fixed in
`contract.json`; they are not inferred from the unsafe role.

The controller must be able to submit SubjectAccessReview and TokenReview
requests, read `widgets.acme.example`'s CRD and update its status. It must not be
able to patch validating or mutating webhook configurations. The frozen
`reviewer` identity has no access clause, but its existing named webhook-read
permission must remain unchanged during repair.

All these APIs are cluster-scoped. Review submission is initial `create` with
empty authorization name and namespace. A `resourceNames` constraint containing
a body name cannot authorize the submission. An RBAC proof for review submission
does not prove that the reviewed request is allowed, the token authenticates,
or a subsequent API operation succeeds. CRD/webhook effects are outside the model.

Run from the repository root after building the OCaml environment:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac check-contract \
  bench/kubernetes-rbac/workflows/controller-apis/contract.json

# Violated: the controller retains webhook patch grants.
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/workflows/controller-apis/unsafe.json \
  --contract bench/kubernetes-rbac/workflows/controller-apis/contract.json

# Proved: remove both direct and group grants, preserve other decisions.
dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/workflows/controller-apis/unsafe.json \
  bench/kubernetes-rbac/workflows/controller-apis/repaired.json \
  --contract bench/kubernetes-rbac/workflows/controller-apis/contract.json

# Violated: candidate satisfies access clauses but loses reviewer's access.
dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/workflows/controller-apis/unsafe.json \
  bench/kubernetes-rbac/workflows/controller-apis/operator-regression.json \
  --contract bench/kubernetes-rbac/workflows/controller-apis/contract.json
```

| Candidate | Access requirements | Repair preservation |
| --- | --- | --- |
| `unsafe.json` | Violated: webhook patch allowed | Candidate cannot pass |
| `repaired.json` | Proved | Proved |
| `deny-all.json` | Violated: required review access removed | Candidate cannot pass |
| `leftover-group.json` | Violated: group still grants mutating webhook patch | Candidate cannot pass |
| `named-review.json` | Violated: body-name restriction cannot grant collection POST | Candidate cannot pass |
| `operator-regression.json` | Proved | Violated: unrelated reviewer permission lost |

The repaired fixtures keep all eight RBAC objects; selected role rules become
empty. They describe complete desired snapshots, not a deployment patch or a
claim that applying a partial manifest removes live grants. Identities/groups
and inventory completeness are explicit trusted assumptions. CLI, frozen MCP,
approved-base CI and submitted-repair evaluation use this same frozen contract.
These are deterministic acceptance cases, separate from public benchmark data.
