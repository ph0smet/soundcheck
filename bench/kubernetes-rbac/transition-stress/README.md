# Bounded RBAC transition stress

This deterministic synthetic harness exercises the existing schema-2 sequence
gate. It varies inventory, identity, clause and operation counts and checks exact
expected results. It is separate from pinned Kubernetes semantic conformance,
the frozen external public benchmark v2, owner-reviewed deployments and live-agent
evaluation. Timings describe these constructions, not worst-case scalability.

Use an already-built `soundcheck` binary and Z3:

```bash
python3 bench/kubernetes-rbac/transition-stress/test_runner.py
python3 bench/kubernetes-rbac/transition-stress/run.py \
  --binary _build/default/cli/main.exe --tier smoke \
  --output /tmp/soundcheck-transition-smoke-001
python3 bench/kubernetes-rbac/transition-stress/run.py \
  --binary _build/default/cli/main.exe --tier full \
  --output /tmp/soundcheck-transition-full-001
```

Each output directory must be new. `--z3 /absolute/path/to/z3` is optional when
Z3 is already on `PATH`. The runner pins its resolved bytes and version, then
puts that invocation directory first on the verifier's `PATH`.

The smoke tier has eight cases. Full includes those and eight larger/variant
cases. No Cartesian product or unbounded repetition is performed. Limits are
60 seconds per run, 600 seconds for the tier and 8 MiB combined stdout/stderr per
run. Flags `--per-run-seconds`, `--total-seconds` and `--output-bytes` may reduce
these limits. A timeout, output overflow, unexpected verdict, changed input/tool
or exhausted overall budget fails the campaign. Skipped budget rows remain in
the results. Process groups are terminated so a timed-out verifier's Z3 children
do not continue running.

For a review point before verification, use `--prepare-only`, inspect
`before-execution.json` and `inputs/`, then execute the same untouched plan:

```bash
python3 bench/kubernetes-rbac/transition-stress/run.py \
  --binary _build/default/cli/main.exe --tier full \
  --output /tmp/soundcheck-transition-reviewed-001 --prepare-only
python3 bench/kubernetes-rbac/transition-stress/run.py \
  --binary _build/default/cli/main.exe \
  --output /tmp/soundcheck-transition-reviewed-001 --execute-prepared
```

Execution always uses the prepared tier and budgets. It refuses a directory that
was already started; retries need a new directory, preserving initial failures.
The plan freezes every input byte/hash, expected outcome, construction rationale,
dimension, budget, harness source and executable/solver identity before the first
verifier call. The runner rechecks inputs, tools, plan and source hashes throughout.
It also regenerates the deterministic constructions before execution to reject
joint edits to an input and its recorded digest or expected answer.

## Constructions and independent expectations

All policies use literal resource names and direct User bindings, without
wildcards or aggregate roles. The operator has explicit native write and
bind/escalate authority; only the revoked-actor case removes its binding.
Migration units occupy separate namespaces. Unchanged background Role/binding
pairs grant Pod reads to the frozen clients outside every approved change scope.

| Cases | Frozen expected result and reason |
|---|---|
| `valid-one`, `valid-four`, `valid-eight`, `valid-sixteen`, `inventory-128-pairs`, `sixteen-final-only` | `valid_sequence`: required ConfigMap grants persist; in-scope Secret grants are removed. Replacement bindings precede retirement. The final-only case explicitly selects no intermediate invariants. |
| `temporary-loss`, `loss-sixteen` | `invariant_failed` at S2: the old binding is removed before its replacement. Required ConfigMap access returns at S3, so final requirements pass. |
| `temporary-grant`, `grant-sixteen` | `invariant_failed` at S1: a bound empty role acquires Secret reads. Its binding is removed at step 2. An unchanged anchor preserves ConfigMap access throughout. Other new roles remain unbound. |
| `actor-revoked` | `authorization_failed` at step 2: step 1 removes the operator's only authorization binding. |
| `outside-scope` | `out_of_scope_regression` at final verification: retiring the old role removes Pod reads outside the approved ConfigMap/Secret scope. |
| `initial-invariant` | `invariant_failed` at S0: the baseline lacks required ConfigMap access; the final replacement repairs it. |
| `final-requirement` | `contract_failed` at final verification: the replacement still grants forbidden Secret reads. |
| `seventeen-steps`, `duplicate-target` | `unknown` in preparation with the specified rejection reason: the frozen sequence violates a structural bound. No operation may execute. |

The largest inventory has 128 background Role/binding pairs (260 objects total),
16 trusted identities and 16 clauses. Successful sequence lengths are 1, 4, 8 and
16. Larger cases select up to eight throughout-transition clauses. Expectations
come from these constructions and the documented gate stage order, before any
production comparison; they are not inferred from the verifier's answers. This
is not an independent native Kubernetes execution or a new target-semantics model.

## Receipts and exit codes

`results.json` is harness format 1. It retains every scheduled row, exact raw
stdout/stderr hashes, process exit status, typed result/phase/failing step,
dimensions, elapsed time and mismatch/error details. Report acceptance checks
frozen contract, exact inputs, state/step chains, authorization prefix, final
requirements, selected invariant execution and preservation completion. Unknown
schemas and incoherent success claims fail closed. Complete expected rejection
controls count as matches, not proofs.

`all_attempt_timings` includes every attempted process, including failures and
censored timeout durations; unattempted budget rows have no duration. There is no
success-only timing average or performance threshold. Whole-tier wall time is
reported separately from summed process durations. Exit 0 requires every frozen
expectation to match, exit 1 means an incomplete/mismatching campaign, and exit 2
means the invocation or prepared artifact was rejected before execution.

Inputs and full reports can contain policy details. Keep the private output
directory local unless intentionally sharing the synthetic artifacts. Receipts
are reproducibility material, not independently checked UNSAT certificates.
