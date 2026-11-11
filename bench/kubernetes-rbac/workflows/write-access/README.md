# Repair named write grants without breaking readers or operators

This synthetic example uses contract schema 3 and the
`kubernetes-rbac-v1.34-read-write-v2` profile. It checks named `update`, `patch`
and `delete` authorization for core ConfigMaps and Secrets alongside the existing
read domain. It uses a complete desired RBAC snapshot and four frozen identities.

The application must retain `get` access to `frontend/settings`, while receiving
no named update, patch or delete grant for ConfigMaps in `frontend` or Secrets
in `payments`. A separate `config-manager` must retain all three named write
grants for `frontend/settings`. This requirement does not establish that the
manager can write *only* that object; no complement-of-names selector is implied.

The approved change scope contains only the application's six forbidden write
classes. Repair comparison also protects the application's list/watch access,
the secret rotator's named grants and the operator's collection reads, including
all-namespace reads, outside that scope.

From the repository root:

```sh
eval "$(opam env)"
dune exec soundcheck -- profile kubernetes-rbac --contract-version 3 --format json
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/workflows/write-access/partial-write-fix.json \
  --contract bench/kubernetes-rbac/workflows/write-access/contract.json --format json
# violated: removing update still leaves an application patch grant

dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/workflows/write-access/unsafe.json \
  bench/kubernetes-rbac/workflows/write-access/repaired.json \
  --contract bench/kubernetes-rbac/workflows/write-access/contract.json --format json
# proved: the contract holds and other modeled decisions are preserved
```

| Snapshot | Contract result | Comparison against `unsafe.json` |
| --- | --- | --- |
| `unsafe.json` | Violated: application ConfigMap update remains granted | Contract fails |
| `partial-write-fix.json` | Violated: application ConfigMap patch remains granted | Contract fails |
| `repaired.json` | Proved | Proved |
| `deny-all.json` | Violated: application ConfigMap read is lost | Contract fails |
| `operator-regression.json` | Proved | Violated: the secret rotator loses named Secret update |

`verify` alone accepts the operator regression because the explicit contract
still holds. `compare` checks the unchanged baseline and rejects the lost grant.
Every non-proof exits nonzero. These are deterministic synthetic controls, not
production deployment or AI-agent results.

The same contract can be loaded at MCP startup with `--connector kubernetes-rbac`
and `--baseline unsafe.json` (use the paths above). For the GitHub Action, select
`connector: kubernetes-rbac` and PR-only `mode: repair`; both contract and baseline
come from the approved base commit, at the trusted fixed paths. See the
[connector guide](../../../../docs/kubernetes-rbac.md) for the complete workflows.

Only static RBAC `Allow`/`NoOpinion` is modeled. Named writes require a valid
namespace and object name; collection create and deletecollection are outside
the profile. A granted patch or delete does not prove that the API operation
succeeds or what it changes: apply can need an additional create authorization,
and special deletion paths can need additional permissions. Authentication,
admission, request bodies, preconditions, object existence, persistence and
indirect Secret exposure remain outside the claim. The manager's delete grant
does not promise that a later application read finds an existing object.

The files describe full replacement snapshots. Removing a binding here means
it is absent from the assumed desired state; applying a partial manifest does
not delete an omitted live binding. Schema-1 and schema-2 contracts keep their
existing domains and must be independently reviewed before upgrading.
