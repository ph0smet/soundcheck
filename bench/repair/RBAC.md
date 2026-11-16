# Experimental submitted RBAC repairs

Evaluate candidate static RBAC snapshots against an evaluator-owned baseline
and frozen access, policy-change or ordered-sequence contract. Access tasks call
`Verify.compare_with_trace` once per candidate: required access must still hold, forbidden RBAC grants must be
absent, and every modeled decision outside the approved change scope must be
preserved. They use the same comparison as `soundcheck rbac compare`.
Policy-change tasks call `Policy_change.run` once, first checking the frozen
actor's authority to make the edit from the original snapshot, then running
that same access/preservation comparison. They use the `soundcheck rbac change`
gate without reimplementing its authorization or solver logic.
Ordered-sequence tasks call `Policy_sequence.run` once: every frozen operation
must be authorized from its preceding state, final access must hold, and modeled
permissions outside the approved change scope must be preserved after every step.
Version-2 change/sequence contracts add explicit policy deletion. Version-2
sequences also freeze selected access clauses that must hold in the original
inventory and every resulting state.

```sh
eval "$(opam env)"
dune exec bench/repair/rbac_main.exe -- \
  bench/repair/rbac-examples/suite.yaml \
  bench/repair/rbac-examples/submissions.yaml
```

The seven candidates are **hand-authored synthetic controls** copied byte for
byte from the [RBAC reference corpus](../kubernetes-rbac/fixtures/). They do not
measure AI repair performance, deployment accuracy or task difficulty. This
evaluator does not run an agent, generate a candidate, execute submitted commands,
contact a cluster or apply a manifest.

| Candidate | Candidate contract | Repair outcome |
| --- | --- | --- |
| Unchanged unsafe snapshot | violated | contract_failed |
| Remove the workload's grants, also losing required ConfigMap access | violated | contract_failed |
| Leave an applicable ClusterRoleBinding grant | violated | contract_failed |
| Grant through a fixed service-account group | violated | contract_failed |
| Fix the workload but remove an operator's unrelated grant | proved | out_of_scope_regression |
| Incomplete snapshot with a missing role reference | unavailable | unknown |
| Remove only the unwanted grant | proved | valid_repair |

The last supplied candidate is the first accepted repair. An aggregate exit 0
means every scheduled task has at least one valid submitted repair and no
input/tool errors; it does not mean every attempt passed.

## Fixed evaluation inputs

The suite and submission metadata use the existing strict
[repair benchmark formats](README.md#keep-tasks-outside-the-repairers-control).
The separate `rbac_main.exe` command selects the connector; candidates cannot
select it or supply a contract, baseline, identity context, change scope, solver,
comparison mode or claimed outcome. For policy-change tasks they also cannot
replace the actor, operation, target or nested requirements. Sequence tasks also
freeze the entire ordered step list and, in version 2, the selected invariant
clause names; candidates supply only the final snapshot.
Each suite `config` is the original baseline.
Paths are relative to their own metadata directory, with traversal and symlink
components rejected by the existing regular-file reader.

Before reading the submission metadata, the evaluator reads every distinct
baseline and contract path once and freezes those bytes and parsed contracts.
Each attempt is read once and compared with that original baseline. It never
uses an earlier candidate as the next baseline or reloads a contract after a
candidate arrives. Empty submissions produce explicit missing-task failures;
unknown task IDs and duplicate attempt IDs within a task invalidate metadata.
No task or attempt disappears because evaluation failed.

Keep the suite, baseline, contracts and evaluator under the operator's control,
separate from candidate files. Inputs must remain stable while read. These local
file checks are not a race-resistant sandbox or a contract-approval mechanism.

## Policy-change repair evaluation

Use the same command and metadata formats with an independently reviewed
[`kubernetes-rbac-policy-change` contract](../../docs/rbac-policy-changes.md):

```sh
eval "$(opam env)"
dune exec bench/repair/rbac_main.exe -- \
  bench/kubernetes-rbac/workflows/policy-changes/suite.yaml \
  bench/kubernetes-rbac/workflows/policy-changes/submissions.yaml
```

The two supplied tasks contain **seven hand-authored synthetic controls**:

| Task / candidate | Expected `repair_result` |
| --- | --- |
| App reader: unchanged target | `unknown` (no-op update is unsupported) |
| App reader: add an unowned Deployment deletion permission | `authorization_failed` |
| App reader: remove required ConfigMap access | `contract_failed` |
| App reader: remove unrelated Pod access | `out_of_scope_regression` |
| App reader: remove only Secret access | `valid_change` |
| Actor's own role: add `escalate` and an unowned deletion permission | `authorization_failed` |
| Actor's own role: remove only Secret access | `valid_change` |

The self-edit actor already holds `update` on its own Role through a frozen
group membership. Newly added `escalate` cannot authorize that edit: every
attempt uses the original permissions, even after an earlier successful attempt.
The first valid attempts are 5 and 2 respectively. The aggregate exits 0 because
both tasks have an accepted change and there are no input/tool errors. All seven
attempts remain in the accounting; this is not an observed agent trajectory.

The entire outer contract is frozen before submissions are read. Its canonical
hash binds actor, groups, operation, target, access requirements and change scope.
The returned gate result must match that identity and the exact before/after
input hashes; an incoherent result is `report_mismatch`. Nested comparison
reports and traces undergo the same checks as an access-only task. No stage is
rerun to produce the summary.

Authorization failure or an unsupported edit leaves `contract_result`,
`contract_assurance` and `comparison_assurance` null because the nested verifier
did not run. `authorization_result` is `allowed`, `not_authorized`, or null when
authorization was unavailable. Once authorized, unsupported nested inputs or a
solver failure still yield `unknown`; successful authorization alone earns no
acceptance. `change_assurance` is the outer gate's `within_profile` or
`unsupported_or_inconclusive` status; nested assurance retains its own meaning.

Version-1 contracts retain the single-object create/update-existing boundary.
Version 2 also supports `delete-existing` under the documented ordinary-deletion
model: the exact target must exist before the edit and be absent afterward.
Native policy coverage is deterministic analysis; nested verification uses SMT.
Neither stage establishes successful API mutation, admission or runtime effects.
This extension does not run agents, contact a cluster, or rerun public benchmark v2.

## Ordered-sequence repair evaluation

Use the same evaluator and candidate-only metadata with a frozen
[`kubernetes-rbac-policy-sequence` contract](../../docs/rbac-policy-sequences.md):

```sh
eval "$(opam env)"
dune exec bench/repair/rbac_main.exe -- \
  bench/kubernetes-rbac/workflows/policy-sequences/suite.yaml \
  bench/kubernetes-rbac/workflows/policy-sequences/submissions.yaml
```

The two tasks contain **eight hand-authored synthetic attempts**. The first
freezes two Role updates that remove duplicate Secret grants. Its candidates
include an unsupported no-op, unmet edit authorization, lost required access,
permanent and temporary out-of-scope Pod access loss, and a valid sequence at
attempt 6. Attempt 7 fails authorization and remains counted after that success.
The second task freezes the reverse order; the formerly disruptive candidate
then preserves the workflow throughout and passes at attempt 1. The campaign
exits zero because both tasks have a valid submission and no input/tool errors.
This illustrates independently approved ordering; candidates cannot select it.

The complete outer contract's raw and canonical hashes bind the actor, trusted
groups, ordered operations and targets, final requirements and approved change
scope. Every attempt starts from the same original baseline. The gate derives
intermediate states; the evaluator cannot substitute candidate-controlled
checkpoints or reuse an earlier attempt as a baseline.

The evaluator checks the returned outer identity and exact input digests, then
validates the single run's state chain, stage order, reports and recorded
executions. Final comparison reports undergo the existing access-task checks;
executed intermediate reports must retain the expected access identity and
profile. Neither authorization nor the solver is rerun to produce a summary.

`sequence_phase` and `sequence_step` identify the stopping phase and its one-based
operation index. Version-2 invariants can fail at state 0, the original inventory.
These fields do not identify the first defect in deployment order:
the gate validates the whole plan, checks all authorizations, checks final access
and preservation, then checks intermediate preservation in order. Final access
requirements apply at the endpoint. Intermediate states may still violate those
requirements inside the approved scope while a staged repair is in progress.
Out-of-scope permissions must be preserved at every post-step state.

`final_comparison_result` uses the nested comparison's outcomes (`valid_repair`,
`contract_failed`, `out_of_scope_regression`, or `unknown`). A final `valid_repair`
can accompany an outer `out_of_scope_regression` when an intermediate state fails.
`intermediate_preservation_result` is `proved`, `violated`, or `unknown` after
execution, `not_required` for a successful one-step sequence, and null when
that stage did not execute. `sequence_assurance` is the outer `within_profile`
or `unsupported_or_inconclusive` assessment. `change_assurance` stays null for
sequence tasks; final nested assurance fields retain their existing meanings.

Only `valid_sequence` accepts a sequence attempt. All authorization failures,
unknowns, negative controls and input/tool failures remain in the denominator,
including attempts after success. The conditional model assumes each earlier
write succeeds and becomes visible before the next check; it does not establish
atomic deployment, controller convergence, rollback or successful API mutation.

## Retirement and transition-invariant evaluation

Version-2 policy contracts use the same evaluator and candidate-only metadata:

```sh
eval "$(opam env)"
dune exec bench/repair/rbac_main.exe -- \
  bench/kubernetes-rbac/workflows/policy-retirement/suite.yaml \
  bench/kubernetes-rbac/workflows/policy-retirement/submissions.yaml
```

The supplied campaign has **three synthetic tasks and eleven hand-authored
attempts**. These exercise the gate and accounting; they are not agent results.

| Task | Controls and first accepted attempt |
| --- | --- |
| Retire obsolete policies | Missing replacement, unowned grant, lost required access, unrelated Pod grant, then valid replacement/retirement at attempt 5; another authorization failure follows. |
| Preserve access during a handoff | A final-valid candidate temporarily loses required ConfigMap access; a valid handoff passes at attempt 2; another temporary-loss attempt remains counted. |
| Delete an obsolete binding | Leaving the target present is unsupported; removing it passes at attempt 2. |

The campaign exits zero because each task has a valid candidate and no input/tool
errors. Negative attempts remain in the counts, including both failures after
success. Individual invariant failures remain non-proofs even when the final
access/preservation comparison proved.

`invariants` selects existing final-access clause names. The actor, identities,
groups, domain, scope, selection and ordered operations all remain frozen outside
candidate control. The evaluator binds the complete outer identity and exact
input bytes, validates each recorded state/query/report chain, and checks that
invariant reports identify the outer sequence and expected nested access profile.
It does not rerun any stage to produce the summary.

For version 2, the gate checks the complete structural plan, all preceding-state
authorizations, final access/preservation, the selected invariants at states
0 through N, and then intermediate preservation. `state_invariants_result` is
the last executed invariant result, or `not_required` when no clauses were
selected and the sequence reached that stage. `state_invariants_checked` counts
executed state checks, including a failing check. `invariant_failure_state` is
populated only when the gate stops in `state_invariants`; 0 denotes the original
inventory and a positive value denotes the state after that operation. Skipped
stages, version-1 sequences and non-sequence tasks have null invariant fields.

The distinct `invariant_failed` outcome records a violated, vacuous or
inconsistent invariant stage. Solver failures remain `unknown`. Neither can
accept an attempt. The strict snapshot/reference boundary still applies to every
state; deletion assumes that the object is fully removed and the result visible
before the next operation. This does not prove live deletion, controller
reconciliation, successful API mutation or atomic migration.

## Interpretation and boundaries

The frozen contract selects the profile. Schema 1 retains
`kubernetes-rbac-v1.34-get-v3` and named `get`; schema 2 selects
`kubernetes-rbac-v1.34-read-v3` and `get/list/watch`, including namespaced and
all-namespace collection authorization. Schema 3 selects
`kubernetes-rbac-v1.34-read-write-v3`, adding named `update`, `patch` and `delete`.
Schema 4 selects `kubernetes-rbac-v1.34-scoped-read-write-v3`, retaining those
verbs and adding namespace/name selectors to access clauses and approved changes.
These four versions quantify core ConfigMaps and Secrets. Schema 5 selects
`kubernetes-rbac-v1.34-resource-read-write-v1`, with explicit API-group/resource
scopes over its [fixed eight-resource catalogue](../../docs/kubernetes-rbac.md#resource-and-api-group-contracts-schema-5).
Schema 6 selects `kubernetes-rbac-v1.34-collection-write-v1`, adding empty-name
`create`/`deletecollection` to that catalogue and its preservation domain.
Namespaced collection writes require nonempty namespaces; Nodes remain
cluster-scoped. Body names and deletion filters cannot narrow these permissions.
All use complete static desired RBAC snapshots in strict JSON and fixed trusted
usernames/groups. Preservation covers that profile's fixed domain outside the
contract's `change_scope`. Both returned stages must match the frozen contract
and its profile; candidate output cannot downgrade the expected profile.
The original `rbac-examples` access-only controls remain schema 1; the new
policy-change examples nest schema 10.

An omitted binding is assumed absent from the complete desired snapshot. Applying
a partial manifest does not remove an existing live binding. Authentication,
admission, object existence, aggregation controllers and escalation paths remain
outside these profiles. Schema 2 and 3 model effective authorization attributes,
not raw selector parsing, response contents or watch events. Schema 3 does not
model operation success, request bodies or effects; apply can need additional
create authorization, and special deletion paths can require other permissions.
`NoOpinion` means RBAC
supplied no grant, not a final API-server denial. See the
[connector guide](../../docs/kubernetes-rbac.md).

For access-only tasks, or once a policy-change task reaches the nested
comparison, both snapshots must be supported before it can plan its work. If
either is unsupported, the candidate stage is unavailable: `contract_result`
and `contract_assurance` are null, while `repair_result` is `unknown` and
`comparison_assurance` is `unsupported`. This does not claim the candidate's
contract was checked independently.

When planning succeeds, the candidate is checked once. A non-proof prevents
preservation execution. A proved candidate can still have a preservation
regression or an unknown comparison. Solver failures, timeouts and invalid
witnesses stay `unknown`, never accepted; the evaluator does not classify them
by matching diagnostic strings. Input read failures, evaluator exceptions and
incoherent returned results have explicit fixed failure codes.

## Minimized summary

The distinct experimental format is `kind: submitted_rbac_repair_evaluation`.
Suites containing only schema-1 access or invalid/unreadable contracts retain format 1,
including existing fatal summaries. Any successfully frozen newer contract
(access schema 2–10) selects format 2:
each task includes its trusted `profile` (null for an invalid/unreadable contract),
and the top-level `profile` is the sole known profile or null for mixed profiles.
Without a newer policy contract or sequence task, any successfully frozen
version-1 policy-change contract selects **format 3**, including
mixed access/change suites and failed submission metadata. Formats 1 and 2 retain
their existing fields and meanings. Format 3 adds:

- Per-task `contract_kind` and `access_profile`; `profile` identifies the outer
  gate for change tasks, while `access_profile` identifies their nested verifier.
- Per-attempt `authorization_result` and `change_assurance` (null for access tasks).
- Distinct `valid_change` and `authorization_failed` outcome counts.
- `comparison: frozen_policy_change_and_scope_preservation`; each task's frozen
  contract kind determines the actual gate. Access tasks still require no edit authority.

For format 3, `tasks_with_valid_repair` and `first_valid_attempt` count either a
`valid_repair` for an access task or a `valid_change` for a policy-change task.
The top-level profile is null when outer/access task profiles differ. A failed
contract has null kind/profile fields; the raw digest is retained when readable.
The existing Kong format and report/evidence schemas are unchanged.

Without a newer policy contract, any successfully frozen version-1
ordered-sequence contract selects **format 4**, including
mixed access/change/sequence suites and failed submission metadata. Existing
task sets keep formats 1–3 unchanged. Format 4 adds:

- `valid_sequence` to the outcome counts; it also counts as an accepted attempt
  for `tasks_with_valid_repair` and `first_valid_attempt`.
- Per-attempt `sequence_assurance`, `sequence_phase`, `sequence_step`,
  `final_comparison_result`, and `intermediate_preservation_result`. These are
  null for access/single-change tasks and for attempts with input/tool failures.
- `comparison: frozen_ordered_policy_sequence_and_scope_preservation`;
  each task's frozen kind still determines its gate and required stages.

Any successfully frozen **version-2 policy-change or sequence contract** selects
**format 5**, including mixed suites and failed submission metadata. Existing
task sets retain formats 1–4 unchanged. Format 5 adds:

- Per-task `contract_version`, identifying that task's frozen outer contract
  (or its access schema for access-only tasks); invalid contracts have null.
- Per-attempt `state_invariants_result`, `state_invariants_checked`, and
  `invariant_failure_state`, with the execution meanings described above.
- A distinct `invariant_failed` outcome count.
- `comparison: frozen_policy_retirement_and_state_invariants`; the frozen kind
  and version still select each task's actual gate. The top-level profile is
  null when tasks use different access/outer profiles.

The [named-write workflow](../kubernetes-rbac/workflows/write-access/README.md)
provides schema-3 controls for partial fixes, required manager writes and a
secret-rotator regression; its fixed contract can be used in an operator-owned
suite with the same candidate-only submission format.
Its fields include:

- Every scheduled task, provenance, ordered attempts and first valid ordinal.
- `baseline_sha256` and `candidate_sha256` for exact input bytes.
- `contract_sha256` for exact raw contract bytes, and `frozen_contract_sha256`
  for normalized identity, clauses and approved changes. Both bind the fixed
  identity context; formatting differences affect only the raw hash.
- Per-attempt `contract_result`, `repair_result`, candidate and comparison
  assurance, input/tool failure category and elapsed reading/evaluation time.
- Complete task and attempt counts, including missing tasks, unknowns and errors.

Access-task repair outcomes are `valid_repair`, `contract_failed`,
`out_of_scope_regression` and `unknown`. Policy-change tasks replace `valid_repair`
with `valid_change` and can also return `authorization_failed`.
Ordered-sequence tasks use `valid_sequence` and the same non-success outcome
names, with the explicit phase fields distinguishing final and intermediate
preservation failures. Version-2 sequences can additionally return
`invariant_failed`; a final proof alone cannot accept such an attempt.
A failure has no repair outcome and is
counted separately. Invalid or unreadable submissions retain the frozen schedule
with `submitted_attempts: null`; invalid suites have `scheduled_tasks: null`.

No raw configuration, canonical contract, path, report, witness, diagnostic or
formula is emitted. IDs, digests, counts and timings can still be sensitive:
this is data minimization, not anonymization. Nothing is written or uploaded
automatically. Use the normal CLI/MCP interfaces separately for authorized
detailed feedback; this evaluator supplies acceptance accounting.

| Exit | Meaning |
| --- | --- |
| 0 | Every task has a valid submitted repair, change or sequence; no input/tool errors. |
| 1 | Input/tool error, missing submission, or an empty suite. |
| 2 | Invalid invocation. |
| 3 | Evaluation completed, but at least one task has no valid repair. |

A task can have both a valid candidate and an error; the error still prevents
exit 0. Submitted-attempt order comes from metadata, not an observed agent history.
For an external-agent study, preregister task selection, generation budgets and
stopping rules, keep missing attempts in the denominator, and record generation
time/cost and independent target validation separately.

## Focused checks

```sh
eval "$(opam env)"
dune runtest bench/repair --force -j 1
```

The RBAC tests cover frozen read-once inputs, strict metadata and tampering,
single comparison dispatch, stage classification, privacy and error accounting.
Process checks evaluate the seven controls with Z3, compare their exact bytes
with the reference corpus, and test unsupported baselines, missing attempts,
invalid contracts, solver protocol failure and non-regular input rejection.
Policy-change checks exercise both synthetic tasks, original-input authority,
outer identity/input substitutions, skipped stages, mixed schedules, later
errors after success, frozen hashes and solver failures after authorization.
Sequence checks cover frozen ordering, final versus intermediate failures,
temporary permission gains/losses, one-step and mixed-task summaries, exact input
and outer-identity substitutions, all attempts after success, and skipped or
unknown solver stages.
Retirement checks additionally cover mixed deletion sequences, initial-state and
intermediate invariant failures, frozen clause selection, unknown invariant
solvers, mixed contract versions, exact format-5 accounting and unchanged
format-4 output for legacy sequences.
The same command also runs the existing Kong evaluator regressions.
