# Experimental submitted RBAC repairs

Evaluate candidate static RBAC snapshots against an evaluator-owned baseline
and access contract. The evaluator calls `Verify.compare_with_trace` once per
candidate: required access must still hold, forbidden RBAC grants must be
absent, and every modeled decision outside the approved change scope must be
preserved. It uses the same comparison as `soundcheck rbac compare`.

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
comparison mode or claimed outcome. Each suite `config` is the original baseline.
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

## Interpretation and boundaries

The exact profile is `kubernetes-rbac-v1.34-get-v1`: one complete static desired
RBAC snapshot in strict JSON, fixed trusted usernames/groups, and named `get`
requests for core ConfigMaps and Secrets. `NoOpinion` means RBAC supplied no
grant; it is not a final API-server denial. Preservation covers the same fixed
identity and named-get domain outside the contract's `change_scope`.

An omitted binding is assumed absent from the complete desired snapshot. Applying
a partial manifest does not remove an existing live binding. Authentication,
admission, object existence, aggregation controllers, list/watch and escalation
paths remain outside this profile. See the [connector guide](../../docs/kubernetes-rbac.md).

Both snapshots must be supported before the comparison can plan its work. If
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

The distinct experimental format is `kind: submitted_rbac_repair_evaluation`,
`experimental_format_version: 1`; the existing Kong format is unchanged.
Its fields include:

- Every scheduled task, provenance, ordered attempts and first valid ordinal.
- `baseline_sha256` and `candidate_sha256` for exact input bytes.
- `contract_sha256` for exact raw contract bytes, and `frozen_contract_sha256`
  for normalized identity, clauses and approved changes. Both bind the fixed
  identity context; formatting differences affect only the raw hash.
- Per-attempt `contract_result`, `repair_result`, candidate and comparison
  assurance, input/tool failure category and elapsed reading/evaluation time.
- Complete task and attempt counts, including missing tasks, unknowns and errors.

The repair outcomes are `valid_repair`, `contract_failed`,
`out_of_scope_regression` and `unknown`. A failure has no repair outcome and is
counted separately. Invalid or unreadable submissions retain the frozen schedule
with `submitted_attempts: null`; invalid suites have `scheduled_tasks: null`.

No raw configuration, canonical contract, path, report, witness, diagnostic or
formula is emitted. IDs, digests, counts and timings can still be sensitive:
this is data minimization, not anonymization. Nothing is written or uploaded
automatically. Use the normal CLI/MCP interfaces separately for authorized
detailed feedback; this evaluator supplies acceptance accounting.

| Exit | Meaning |
| --- | --- |
| 0 | Every task has a valid submitted repair; no input/tool errors. |
| 1 | Input/tool error, missing submission, or an empty suite. |
| 2 | Invalid invocation. |
| 3 | Evaluation completed, but at least one task has no valid repair. |

A task can have both a valid candidate and an error; the error still prevents
exit 0. The sequence order is supplied metadata, not an observed agent history.
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
The same command also runs the existing Kong evaluator regressions.
