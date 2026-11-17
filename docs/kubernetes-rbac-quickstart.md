# Try Kubernetes RBAC verification

This walkthrough shows what counts as a repair: remove unwanted access, keep
required access, and preserve other modeled permissions. It uses checked-in
synthetic snapshots and one fixed contract. It does not contact a cluster.

Install and build using the [source quickstart](getting-started.md#1-install-the-toolchain),
then run these commands from the repository root. Commands showing a violation
intentionally exit nonzero; run them individually and retain their exit codes.

## Review the requirement

The example requires `frontend-sa` to read ConfigMaps in `frontend`, while
receiving no named Secret `get` grant in `payments`. A separate operator's
permissions must survive the repair. The contract fixes the trusted usernames,
groups, complete-inventory assumption and allowed change scope.

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac check-contract \
  bench/kubernetes-rbac/contracts/frontend-access.json
```

This reviews structure and intent; exit `0` here is not a proof. This small
example uses the original named-`get` profile. It does not rule out Secret
access through `list`, `watch` or indirect workload effects. Select a broader
[supported contract](kubernetes-rbac.md#supported-profiles) when the requirement
needs it; never infer the requirement from the permissions already present.

## Find unwanted access

```sh
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/fixtures/01-unsafe.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
# Expected: violated, exit 3.
```

The checked counterexample identifies the caller, requested object and granting
binding/role/rule. Solver-selected object names may differ between runs.

## Reject a repair that removes required access

```sh
dune exec soundcheck -- rbac verify \
  bench/kubernetes-rbac/fixtures/02-delete-workload-grants.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
# Expected: violated, exit 3. Required ConfigMap access was removed.
```

Keep the same contract. Removing every grant cannot satisfy a requirement that
also demands useful access.

## Check a complete repair

```sh
dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/fixtures/01-unsafe.json \
  bench/kubernetes-rbac/fixtures/03-valid-repair.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
# Expected: proved, exit 0.
```

`compare` checks the candidate's access requirements and preservation against
the original snapshot. `verify` alone does not establish preservation.

The following candidate meets the workload's clauses but breaks the operator's
access; comparison catches that regression:

```sh
dune exec soundcheck -- rbac compare \
  bench/kubernetes-rbac/fixtures/01-unsafe.json \
  bench/kubernetes-rbac/fixtures/16-operator-regression.json \
  --contract bench/kubernetes-rbac/contracts/frontend-access.json --format json
# Expected: violated, exit 3, in a must_preserve obligation.
```

To retain queries, results and provenance, add `--evidence-dir NEW_DIRECTORY`
to a verification or comparison command. The destination must not exist and
its parent must exist. Evidence supports replay and audit; it is not an
independently checked proof certificate. Review it before sharing.

## Review an ordered migration

A valid final snapshot can hide a temporary loss of required access. The
[retirement and migration demo](../bench/kubernetes-rbac/workflows/policy-retirement/README.md)
uses a frozen actor, operation order and selected requirements that must hold
from the original state onward. Its two-update handoff compares a valid repair
with a final-valid candidate that loses ConfigMap access at state 1.

Only `valid_sequence` passes that gate. Each operation uses authority from its
preceding state; preservation compares every resulting state with the original
outside the approved scope. The model assumes prior writes completed and became
visible. It does not apply changes or guarantee an atomic deployment.

## Use the local workspace

Follow the [web startup instructions](../frontend/README.md#running), then open
`/rbac`. Choose access verification, repair comparison, single change or ordered
sequence, and load a labeled synthetic example or supply reviewed inputs.

Review the intent, lock the contract and the original snapshot when required,
then run candidates.
Inspect the witness or state results, assurance boundary and evidence download.
The local lock supports review; trusted CI must independently rerun its gate
with the approved contract and baseline.

For a manual browser review before recording a demo:

- Try all four modes and inspect a successful and failed result.
- Change a candidate and confirm the previous result becomes stale; change the
  contract or original snapshot and confirm a new review is required.
- Cancel a run and confirm a late response cannot replace a newer result.
- Inspect the selected profile and download evidence for the displayed run.
- Check keyboard navigation and a narrow viewport, including long identities,
  counterexamples and the sequence state view.

These are review steps, not a record that browser acceptance has been completed.

## Bring an owner-reviewed policy

Use the [RBAC pilot guide](evaluation/kubernetes-rbac-pilot.md) to assemble an
authorized complete inventory, trusted identities and independently approved
requirements. [Preparation and inventory](kubernetes-rbac.md#prepare-a-json-export)
can normalize supported inputs and resolve references; they cannot establish
completeness or the caller's actual authentication context.

All results concern the selected versioned RBAC model. `NoOpinion` means no RBAC
grant, not final API-server denial. Authentication, other authorizers, admission,
indirect workload effects and live reconciliation need separate reasoning.
