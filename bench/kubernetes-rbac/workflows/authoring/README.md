# Author a narrow ConfigMap-read contract

This synthetic example starts with access requirements, then checks candidate
RBAC snapshots against them. The contract uses schema 4 and the
`kubernetes-rbac-v1.34-scoped-read-write-v3` profile. It is not a public deployment
evaluation, an observed authentication context, or a measured authoring study.

## Write the requirement before inspecting grants

A configuration-reader workload needs `get` access to the `settings` ConfigMap
in both `team-a` and `team-b`. It must receive no other ConfigMap `get` grants.
A repair may remove those unwanted grants, while preserving every other modeled
decision for the workload and a separate operator.

The following requirement table defines `contract.json` independently of the
candidate snapshots. Each row selects `verb: "get"`, `resource: "configmaps"`
and subject `system:serviceaccount:platform:config-reader`.

| Clause | Requirement | Namespace selector | Name selector |
| --- | --- | --- | --- |
| `settings-required` | `must_allow` | `{"include":["team-a","team-b"]}` | `["settings"]` |
| `other-names-forbidden` | `must_not_grant` | `{"include":["team-a","team-b"]}` | `{"exclude":["settings"],"include_empty":false}` |
| `other-namespaces-forbidden` | `must_not_grant` | `{"exclude":["team-a","team-b"]}` | `null` |

The first clause requires access in **both** listed namespaces. The second
covers every other valid name in those namespaces. The third covers every valid
nonempty namespace outside the list, including namespaces absent from a supplied
snapshot. `must_not_grant` means RBAC must supply no grant; it is not a final
API-server denial.

The two forbidden request classes are also the exact `change_scope`. This does
not relax the clauses: the candidate must still satisfy all three. It only
permits decisions in those two classes to differ from the baseline. An empty
change scope would reject the intended removal of existing unwanted grants.

## Review the caller independently

Suppose the workload's reviewed Deployment contains these fields. This is an
excerpt for manual explanation, not a complete deployable manifest or an input
to this example's verifier commands:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: config-reader
  namespace: platform
spec:
  template:
    spec:
      serviceAccountName: config-reader
```

For requests authenticated as that ServiceAccount, the username is
`system:serviceaccount:platform:config-reader`. The caller's `platform`
namespace differs from the target namespaces `team-a` and `team-b`. The repaired
RoleBindings therefore live in the target namespaces and name a ServiceAccount
subject whose explicit namespace is `platform`.

The frozen identities in this example are deliberately supplied assumptions:

| Username | Exact trusted groups |
| --- | --- |
| `system:serviceaccount:platform:config-reader` | `system:authenticated`, `system:serviceaccounts`, `system:serviceaccounts:platform` |
| `operator` | `operators`, `system:authenticated` |

Kubernetes's pinned [ServiceAccount identity helpers](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/authentication/serviceaccount/util.go)
define the username and ServiceAccount groups; its
[authenticated-group wrapper](https://github.com/kubernetes/apiserver/blob/v0.34.0/pkg/authentication/group/authenticated_group_adder.go)
adds `system:authenticated` under its authentication conditions. Soundcheck does
not execute that authentication chain, infer groups from the username, or prove
that the workload uses those credentials. Review actual caller attributes and
inventory completeness independently before using a contract for a deployment.
Do not remove a group from the contract to hide an unwanted group grant.

## Review, then verify

Run from the repository root with the normal development toolchain:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac check-contract \
  bench/kubernetes-rbac/workflows/authoring/contract.json

dune exec soundcheck -- rbac inspect \
  bench/kubernetes-rbac/workflows/authoring/unsafe.json \
  --contract bench/kubernetes-rbac/workflows/authoring/contract.json

dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/workflows/authoring/unsafe.json \
  --contract bench/kubernetes-rbac/workflows/authoring/contract.json --format json
# exit 3: other-names-forbidden is violated

dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/workflows/authoring/unsafe.json \
  bench/kubernetes-rbac/workflows/authoring/repaired.json \
  --contract bench/kubernetes-rbac/workflows/authoring/contract.json --format json
# exit 0: the requirements hold and other modeled decisions are preserved
```

`check-contract` parses the existing contract format and displays its review
summary, identities, clauses, approved changes and input/canonical hashes. It
does not read a policy, invoke Z3 or prove that the requirements are consistent
or satisfied. `inspect` shows subject-matching bindings for the frozen identities;
those matches are not authorization verdicts. Only verification and comparison
produce solver-backed results within the stated profile.

The baseline gives the workload cluster-wide ConfigMap `get` through a
ClusterRoleBinding. The repair restricts the ClusterRole to `settings` and
replaces that binding with RoleBindings in `team-a` and `team-b`. The operator's
`operators` group separately retains `get` on `ops/configmaps/status`.

| Snapshot | `verify` | `compare` against `unsafe.json` |
| --- | --- | --- |
| `unsafe.json` | Violated: `other-names-forbidden` | Contract fails before preservation |
| `repaired.json` | Proved | Proved |
| `deny-all.json` | Violated: `settings-required` | Contract fails before preservation |
| `operator-regression.json` | Proved | Violated: operator loses `get ops/configmaps/status` |
| `leftover-group.json` | Violated: `other-names-forbidden` | Contract fails before preservation |

The deny-all control removes both workload bindings while retaining the
operator's access. The operator-regression control removes only the operator's
RoleBinding from the repaired snapshot. The leftover-group control adds a broad
grant to `system:serviceaccounts:platform`; the frozen workload identity matches
that group even though its direct ServiceAccount bindings are narrow. Keep the
same contract and baseline for every candidate. Solver-selected witness names
can vary; assess the request class and granting rule rather than a golden name.

## What the author supplied

This fixed contract contains **2 identities, 5 group memberships, 3 clauses and
2 approved-change scopes**. The selectors explicitly name two target namespaces
and one permitted object name. These reproducible artifact counts describe the
review inputs; they are not measurements of human effort or evidence that real
contract authoring takes a particular amount of time.

For an owner-reviewed pilot, record the initial requirement approval, time spent
drafting and reviewing, diagnostic iterations, requirement changes needing new
approval, and the final raw/canonical hashes. Actual human authoring measurements
remain pending; this walkthrough supplies no timing or usability-study result.

The three access clauses constrain only ConfigMap `get`. They do not independently
forbid Secret access or other verbs. Repair comparison additionally preserves
every decision outside the two approved classes across both frozen identities
and the whole modeled six-verb ConfigMaps/Secrets domain, including absence of
grants. It does not quantify unlisted identities or guarantee full application
functionality. Add independently approved requirements for other access needs;
do not infer them from whichever grants happen to be present.

These files are complete desired snapshots for this synthetic example. Applying
a partial manifest does not delete an omitted live binding. Snapshot completeness,
trusted identity attributes and deployment reconciliation remain assumptions.
