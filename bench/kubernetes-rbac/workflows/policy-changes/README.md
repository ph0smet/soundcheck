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

## Evaluate submitted attempts

The same directory includes an evaluator-owned suite with the Role repair above
and a self-edit task. Its actor already has `update` on its own Role through a
trusted group. Adding `escalate` and unowned Deployment deletion rights fails;
removing only Secret access succeeds. All authority comes from `self-before.json`.

```sh
eval "$(opam env)"
dune exec bench/repair/rbac_main.exe -- \
  bench/kubernetes-rbac/workflows/policy-changes/suite.yaml \
  bench/kubernetes-rbac/workflows/policy-changes/submissions.yaml
```

Expected: two tasks, seven synthetic attempts, two `valid_change`, two
`authorization_failed`, one `contract_failed`, one `out_of_scope_regression`,
one `unknown`, zero errors; aggregate exit 0. No-op policy changes are unknown,
even though an access-only comparison can evaluate an unchanged snapshot.
See the [evaluator format and freeze boundary](../../../repair/RBAC.md#policy-change-repair-evaluation).
