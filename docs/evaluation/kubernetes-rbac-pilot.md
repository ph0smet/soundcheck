# Owner-reviewed Kubernetes RBAC pilot

Use a small authorized set of local policy snapshots to evaluate whether
Soundcheck's results help a policy owner. The [synthetic walkthrough](../kubernetes-rbac-quickstart.md)
is ready to run; completing it does not complete a deployment pilot. This guide
adds no cluster collector, deployment executor or new contract format.

Copy the [review worksheet](kubernetes-rbac-review-worksheet.md) into a private
evaluation directory. Keep deployment inputs, approvals, identities and detailed
results outside the repository. The separate [Kong pilot protocol](pilot-protocol.md)
and runner retain their existing scope.

## Establish the inputs

Record the owner's processing authorization and intended use of results,
retention and sharing decisions, and how the sample was selected. Collect:

- A complete original inventory of applicable Roles, ClusterRoles, RoleBindings
  and ClusterRoleBindings, with source/version and byte-digest records. Include
  unbound ClusterRoles and labels needed by aggregate selectors. Missing references
  and unsupported objects remain recorded; do not filter them away to pass.
- Independently trusted usernames and exact groups. A ServiceAccount name or
  workload reference alone does not prove which credentials or groups are used.
- Owner-approved required and forbidden access, identities whose other modeled
  permissions must be preserved, and the exact allowed change scope.
- The chosen access profile, any separately reviewed custom API catalogue, and
  requirements or environment behavior outside that profile.

Use [preparation](../kubernetes-rbac.md#prepare-rendered-manifests) and
[inventory assembly](../kubernetes-rbac.md#assemble-an-explicit-inventory) where
needed. Retain original bytes, prepared snapshots and receipts. Successful
preparation or reference resolution does not establish completeness. Record any
sanitization that changes policy semantics. Explicit bootstrap supplements must
match the reviewed inventory; selecting a pack does not prove it is installed.

## Freeze intent before candidates

Author the contract from the owner's requirements, separately from proposed
repairs. Record the raw and canonical contract identities, reviewer and approval
reference. Preserve the original snapshot identity and chosen verifier/solver
versions. Do not weaken clauses, remove a trusted group or broaden scope to make
a candidate pass. A legitimately revised requirement starts a separately reviewed
task with its own results.

For an access contract, these commands review structure, subject matches and
coverage. The file names below refer to locally supplied pilot inputs:

```sh
eval "$(opam env)"
dune exec soundcheck -- rbac check-contract approved-access.json
dune exec soundcheck -- rbac inspect original.json --contract approved-access.json
dune exec soundcheck -- rbac coverage original.json --contract approved-access.json
```

`check-contract` prints a human review; `inspect` and `coverage` already emit
JSON. These commands do not prove access. Inspect/coverage take an access
contract, not an outer policy-change or sequence contract.

For a single policy change or ordered migration, separately freeze the actor,
operation targets/order and nested access contract. For a schema-2 ordered
sequence, select requirements that must hold from the original state through
every step. A final repair goal that the original already violates cannot also
be a valid initial-state invariant.
Use the [change](../rbac-policy-changes.md) or
[sequence](../rbac-policy-sequences.md) guide for their distinct gates and limits.

## Run and retain every outcome

Run the baseline and candidates through the appropriate existing CLI or frozen
MCP interface. For example, with reviewed access inputs:

```sh
dune exec soundcheck -- rbac verify original.json \
  --contract approved-access.json --format json
dune exec soundcheck -- rbac compare original.json candidate.json \
  --contract approved-access.json --format json
```

Capture each report, stderr and exit code. A baseline violation can be expected;
do not discard it through shell error suppression or an early-exit batch.
Record every selected input and submitted candidate, including unsupported
semantics, timeouts, invalid inputs and unattempted cases. Distinguish contract
failure from preservation or operation-authorization failure.

Use `--evidence-dir NEW_DIRECTORY` where permitted; the parent must exist and
the destination must not. Retain exact input hashes, contract identity, engine,
solver and assurance profile alongside the evidence. Some bundles contain full
private snapshots; even hashes, queries and witnesses may reveal identifiers.
Replayable formulas are not independent UNSAT certificates.

All execution here is offline and advisory. Any cluster access, target replay,
deployment or external-agent campaign needs its own authorized scope. A valid
sequence assumes successful visible prior writes and does not establish rollout
atomicity, admission success or runtime workload security.

## Review usefulness independently

Have the owner adjudicate each result against the original requirement and
independent target evidence. Record intended exceptions, confirmed requirement
violations, possible modeling defects, unsupported semantics and unresolved
cases separately. A modeled violation is not automatically a deployed
vulnerability. RBAC `NoOpinion` is not the API server's final denial.

Measure time spent assembling inventory, establishing identities, writing and
reviewing requirements, interpreting results and reviewing repairs. Solver time
does not measure those costs. Record useful diagnostics and requirements that
could not be expressed. Compare with the owner's existing process only when
there is evidence for what it would have found.

A completed pilot retains the selected sample, approved intent, all scheduled
outcomes, assumptions, independent adjudications and authoring/review effort.
State sample size and selection bias; keep unknowns and failures in accounting.
Do not infer general accuracy, vulnerability counts or autonomous repair success
from synthetic fixtures, conformance tests or submitted-candidate evaluation.
Review the exact proposed summary separately before publishing private results.
