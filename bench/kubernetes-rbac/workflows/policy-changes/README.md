# A frozen, authorized Role repair

These synthetic snapshots exercise `rbac change` with the same independently
reviewed operation and access requirements. Run from the repository root:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac change \
  bench/kubernetes-rbac/workflows/policy-changes/before.json \
  bench/kubernetes-rbac/workflows/policy-changes/repaired.json \
  --contract bench/kubernetes-rbac/workflows/policy-changes/contract.json
```

`deployer` can update `team-a/app-reader` and holds the permissions retained in
the repair. The app must keep ConfigMap access and lose Secret access; existing
Pod access must be preserved outside the approved scope.

| Candidate | Expected result |
| --- | --- |
| `repaired.json` | `valid_change`, exit 0 |
| `authorization-failed.json` | `authorization_failed`, exit 3; new permission is not covered |
| `contract-failed.json` | `contract_failed`, exit 3; required ConfigMap grant removed |
| `out-of-scope-regression.json` | `out_of_scope_regression`, exit 3; Pod grant removed |
| `before.json` | `unknown`, exit 4; no-op operation is unsupported |

The outer operation contract is schema 1; its nested access contract is schema
10, which includes Pods in the preservation domain. Authorization checks full
policy rules, including permissions outside that nested domain. This is not a
live deployment or public-config benchmark. See the
[usage and trust boundary](../../../../docs/rbac-policy-changes.md).
