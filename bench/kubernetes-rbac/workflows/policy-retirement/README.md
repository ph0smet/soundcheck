# Retire and migrate RBAC policies

This synthetic workflow replaces a Role and binding, then removes the obsolete
objects while retaining the application's ConfigMap access throughout the
transition. The complete snapshots, trusted identities, frozen plan and access
requirements are hand-authored; this is adapter acceptance evidence,
not a deployment pilot or live-agent result.

From the repository root:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac check-contract \
  bench/kubernetes-rbac/workflows/policy-retirement/contract.json
dune exec soundcheck -- rbac sequence \
  bench/kubernetes-rbac/workflows/policy-retirement/before.json \
  bench/kubernetes-rbac/workflows/policy-retirement/repaired.json \
  --contract bench/kubernetes-rbac/workflows/policy-retirement/contract.json \
  --format json
```

The schema-2 plan freezes four distinct targets in this order:

1. Create Role `team-a/replacement-reader`.
2. Create RoleBinding `team-a/replacement-app`.
3. Delete RoleBinding `team-a/old-app`.
4. Delete Role `team-a/old-reader`.

The application must have ConfigMap access and no Secret grant at the end.
`invariants: ["configmaps-required"]` additionally requires ConfigMap access in
the original inventory and every resulting state. ConfigMaps and Secrets are
inside the approved change scope, so the invariant adds a requirement beyond
preservation outside that scope. Other modeled permissions must still be
preserved for every trusted identity after each step.

The deployer can create Roles/bindings, delete the exact retired names, and
already has the ConfigMap permissions in the replacement. It has no Secret
permission and no `bind`/`escalate` grant. This permits the replacement through
native policy coverage and deletion through named `delete`, without requiring
the deployer to possess the Secret grant it removes.

With `contract.json` and `before.json`:

| Candidate | Expected result | Why |
| --- | --- | --- |
| `repaired.json` | `valid_sequence` | Required access remains available and the obsolete grant disappears |
| `authorization-failed.json` | `authorization_failed` | The replacement attempts a Secret grant the deployer cannot confer |
| `contract-failed.json` | `contract_failed` | The authorized replacement loses required ConfigMap access |
| `out-of-scope-regression.json` | `out_of_scope_regression` | The replacement adds unapproved Pod access |
| `before.json` | `unknown` | The candidate does not contain the required replacement objects |

## Distinguish endpoint success from transition requirements

`handoff-contract.json` freezes updates to `primary-reader` followed by
`secondary-reader`. Use `handoff-before.json` as the baseline:

| Candidate | Expected result | Meaning |
| --- | --- | --- |
| `handoff-repaired.json` | `valid_sequence` | Primary keeps ConfigMap access while both Secret grants are removed |
| `handoff-invariant-failed.json` | `invariant_failed` at state 1 | Final access is valid, but ConfigMap access is absent between the two updates |

Both candidates meet final access and preservation; only the second violates
the selected invariant. This is one fixed task with both successful and failed
repairs, not two different specifications chosen after seeing results.

Additional frozen controls use `repaired.json`:

- `gap-contract.json` with `before.json` removes the old binding before creating
  its replacement. It fails the invariant at state 1.
- `unguarded-gap-contract.json` selects no invariants. That same transition
  passes because the temporary loss lies inside the approved change scope.
- `contract.json` with `initial-before.json` fails the invariant at state 0;
  the original policy lacks the selected required ConfigMap grant.
- `role-first-contract.json` is unsupported because its first deletion leaves
  the old binding with an unresolved role reference.
- `revoked-actor-contract.json` with `before.json` and
  `revoked-actor-after.json` deletes the deployer's own binding first. The next
  operation fails authorization from its immediately preceding state.

## Retire one object

`delete-contract.json` deletes only `old-app` from `delete-before.json` to
`delete-after.json`. The replacement Role and binding already exist, so required
access is retained. `delete-role-contract.json` then removes the now-unreferenced
`old-reader` from `delete-after.json` to `repaired.json`.

```sh
dune exec soundcheck -- rbac change \
  bench/kubernetes-rbac/workflows/policy-retirement/delete-before.json \
  bench/kubernetes-rbac/workflows/policy-retirement/delete-after.json \
  --contract bench/kubernetes-rbac/workflows/policy-retirement/delete-contract.json \
  --format json
```

`delete-unauthorized-contract.json` freezes the application as actor; the same
candidate fails because that identity lacks the named deletion grant.

## Use the same frozen gate in MCP and CI

```sh
dune exec soundcheck -- mcp --connector kubernetes-rbac \
  --contract bench/kubernetes-rbac/workflows/policy-retirement/contract.json \
  --baseline bench/kubernetes-rbac/workflows/policy-retirement/before.json
```

The MCP `sequence` tool accepts only candidate `config`. The trusted Action uses
`connector: kubernetes-rbac` and `mode: sequence`, loading the entire contract
and baseline from the approved PR base. A candidate cannot drop invariants,
change actor/order, broaden scope or replace the baseline. `mode: change` also
supports the single deletion contract. See the [contract and trust boundary](../../../../docs/rbac-policy-sequences.md).

`--evidence-dir NEW_DIRECTORY` writes private snapshots, exact hashes, reports,
queries and checked outcomes. These support replay and audit; they are not
independently checked proof certificates.

The model is conditional on each prior operation completing and becoming visible.
Deletion means full removal using ordinary default DELETE options. No actual
cluster write, pending-deletion handling, concurrent transition, controller
reconciliation, rollback or atomic deployment is established.
