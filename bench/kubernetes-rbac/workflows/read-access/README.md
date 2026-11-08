# Preserve useful reads while repairing Secret access

These synthetic snapshots demonstrate the schema-2 RBAC read profile, pinned
to Kubernetes v1.34.0. The contract is independent of the candidate policy.
It requires the frontend ServiceAccount to get its `settings` ConfigMap and
watch ConfigMaps in `frontend`, while receiving no Secret get/list/watch grant
in `payments` and no all-namespace Secret list/watch grant.

Only the frontend's Secret read decisions in `payments` may change. Every other
modeled decision must be preserved, including the operator's cluster-wide
ConfigMap list/watch grants and the frontend's existing ConfigMap list access.

Run from the repository root after installing the normal development toolchain:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/workflows/read-access/unsafe.json \
  --contract bench/kubernetes-rbac/workflows/read-access/contract.json
# exit 3: unwanted Secret get grant

dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/workflows/read-access/get-only-repair.json \
  --contract bench/kubernetes-rbac/workflows/read-access/contract.json
# exit 3: removing get still leaves list/watch grants

dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/workflows/read-access/unsafe.json \
  bench/kubernetes-rbac/workflows/read-access/repaired.json \
  --contract bench/kubernetes-rbac/workflows/read-access/contract.json
# exit 0: access requirements hold and other modeled decisions are preserved
```

Replace `repaired.json` in the comparison with either negative control:

| Candidate | Expected result |
| --- | --- |
| `operator-regression.json` | Access contract holds, but lost operator list/watch access violates preservation |
| `deny-all.json` | Lost frontend ConfigMap access violates the functionality clause |

Add `--format json` or `--format github` for machine-readable output or GitHub
annotations. Add `--evidence-dir NEW_DIRECTORY` to retain input digests and byte
counts, the frozen contract, selected profile and SMT queries from a comparison.

The frozen agent workflow uses the same files:

```sh
dune exec soundcheck -- mcp --connector kubernetes-rbac \
  --contract bench/kubernetes-rbac/workflows/read-access/contract.json \
  --baseline bench/kubernetes-rbac/workflows/read-access/unsafe.json
```

The agent supplies only candidate JSON to `verify` or `compare`. It cannot
change the startup contract or baseline through tool arguments. In a required
CI workflow, the Action selects schema 2 from the approved base-commit
contract; `mode: repair` additionally loads the baseline from that same base
commit at the fixed candidate path. Both files must already exist in the
approved base; see the [Action guidance](../../../../docs/kubernetes-rbac.md#github-action).

All cases concern RBAC authorization of a complete static snapshot and fixed
trusted identities. `NoOpinion` is not a final API-server denial. No claim is
made about live deployment state, returned objects, watch events, or indirect
Secret exposure through workloads. These are deterministic verifier examples,
not production configurations or autonomous-agent evaluation results.
