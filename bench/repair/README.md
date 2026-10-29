# Experimental submitted-repair benchmark

Evaluate externally supplied candidate configurations against fixed requirements
and an original baseline. The evaluator calls Soundcheck's existing
`Compare.run_repair`: the candidate must satisfy its frozen contract **and**
preserve every modeled Allow/Deny decision outside the contract's endpoint
scope. A deny-all response and a repair that breaks unrelated public access
therefore receive no acceptance credit.

This is a reproducible evaluator, not an agent runtime or a trained model.
It does not call a model, generate repairs, execute submitted commands, access
the network, probe a gateway, or change a configuration. The shipped candidates
are hand-authored synthetic controls. Their results establish evaluator behavior,
not autonomous repair success, real-deployment accuracy, or benchmark difficulty.

## Run the synthetic controls

Use the [normal toolchain](../../README.md#quickstart), including Z3 4.16.0:

```sh
eval "$(opam env)"
dune exec bench/repair/main.exe -- \
  bench/repair/examples/suite.yaml \
  bench/repair/examples/submissions.yaml
```

The five attempts deliberately exercise different outcomes:

| Submitted candidate | Contract | Repair evaluation |
| --- | --- | --- |
| Unchanged open `/admin` | violated | contract_failed |
| Deny everything | violated | contract_failed |
| Service-wide auth that also closes `/public` | proved | out_of_scope_regression |
| Unsupported plugin | unknown | unknown |
| Auth only on the intended `/admin` route | proved | valid_repair |

The single task has its first valid submitted repair at attempt 5. Exit 0 means
each task has at least one accepted submitted candidate and there were no
input/tool errors; it does **not** mean every attempt was valid.

A second synthetic task uses the public-exceptions contract. An exposed API,
deny-all, and a repair that locks out health checks all fail before the valid
repair at attempt 4:

```sh
dune exec bench/repair/main.exe -- \
  bench/repair/examples/public-suite.yaml \
  bench/repair/examples/public-submissions.yaml
```

These are supplied control sequences, not observed agent trajectories. The
public contract's `/api/health` is a literal prefix including `/api/healthcheck`.

## Keep tasks outside the repairer's control

The evaluator-owned suite uses the existing
[pilot manifest](../pilot/README.md#explicit-manifest) format. Its `config` is the
original baseline, not the latest candidate:

```yaml
format_version: 1
cases:
  - id: task-001
    provenance: synthetic
    config: baselines/task-001.yaml
    contract: reviewed/task-001.yaml
```

The separately supplied submissions file has exactly this format:

```yaml
format_version: 1
attempts:
  - task: task-001
    id: attempt-01
    config: candidates/attempt-01.yaml
```

Submissions contain candidate paths and identifiers only. They cannot provide
contracts, change scope, select a weaker comparison, supply claimed outcomes,
or override a solver. Unknown task IDs and duplicate attempt IDs within a task
invalidate the submission file. Reusing an attempt ID for a different task is
allowed. An empty submissions list is valid input: every scheduled task is then
reported with `missing_submission`, and the run fails.

Both metadata files use a strict versioned YAML/JSON subset. Unknown and duplicate
keys, tags, aliases, merge keys, multiple documents, literal NUL, and backslash
escape syntax are rejected. Paths are literal and relative to their respective
metadata file's directory; empty/dot/traversal components and control characters
are rejected. File reads reuse `Pilot.read_regular`, which rejects symlinks,
directories, and special files. Neither input directory is scanned.

The operator must own the suite, contracts and baseline, and control which
submitted artifacts are evaluated. The process snapshots every distinct contract
and baseline before evaluating any attempt. Every candidate is read once per
attempt, hashed, and evaluated against those same snapshots, never against the
previous candidate. Stable input directories are required: this is not a
race-resistant sandbox, a contract-approval mechanism, or protection against a
repairer that can rewrite the evaluator's files before the snapshot. Preserve
the suite in a separate evaluator-controlled checkout/directory in a live study.

The fixed comparison is `Security_decision`. It preserves Allow/Deny outside
the scope, not selected route/service, upstream destination, response content,
or runtime availability. It does not require preservation of arbitrary
in-scope behavior beyond the approved contract. Results retain Soundcheck's
versioned model and assumptions; conservative or unsupported comparison stays
unknown and receives no acceptance credit.

## Interpret the summary

`kind: submitted_repair_evaluation` and `experimental_format_version: 1` mark
an experimental bench format, not a new stable verifier API. The summary includes:

- Every scheduled task in suite order, including missing submissions and errors.
- SHA-256 of the exact baseline bytes and normalized frozen contract identity.
- Every submitted attempt in its per-task input order, its ordinal, exact
  candidate-byte digest, contract verdict, repair outcome, `contract_assurance`,
  `contract_finding_codes`, and failure category. Those assurance fields describe
  the candidate's contract check only. Preservation can remain unknown because
  of the baseline even when the candidate is within the supported profile.
- `first_valid_attempt`: the first accepted ordinal, or null. All later attempts
  still run and remain in the result, including errors.
- `scheduled_tasks`, `tasks_with_valid_repair`, `tasks_with_errors`,
  `submitted_attempts`, and disjoint attempt outcome/error counts.
- Per-attempt wall time for reading and evaluation, excluding suite/baseline
  loading and any external generation time. Timings vary; they are not runtime
  guarantees or model-cost measurements.

Errors never disappear from denominators. A task can have both a valid attempt
and an error, and both task counts reflect that. A contract proof with failed
preservation is not an accepted repair. Unknowns are never counted as valid.

| Exit | Meaning |
| --- | --- |
| 0 | Every task has a valid submitted repair; no input/tool errors. |
| 1 | Invalid input/tool result, missing submission, or an input/tool failure. |
| 2 | Invalid invocation. |
| 3 | All attempts evaluated without input/tool errors, but some tasks have no valid repair. |

An unreadable or invalid suite reports no trustworthy schedule
(`scheduled_tasks: null`). If the suite is valid but submissions are unreadable
or invalid, every scheduled task remains with that explicit failure and no
attempt records; `submitted_attempts` is null rather than guessing a count from
malformed metadata.
Normal summaries exclude raw configs, paths, canonical contracts, credentials,
witnesses, diagnostics and formulas. IDs, digests, counts and timing are still
potentially sensitive; this is minimization, not anonymization. Nothing is
written or uploaded automatically. Obtain separately authorized detailed
feedback through the existing CLI/MCP and `compare --contract` workflows.

## Use with an external agent

1. Before generation, freeze the evaluator-owned suite, baseline and reviewed
   contracts. Define the agent, tool access, attempt/time budget, stopping rule,
   permitted edits, and task selection. Record provenance privately.
2. Give the agent a working copy of the baseline and a read-only statement of
   the approved requirement. An existing frozen MCP server can supply iterative
   feedback; model clients and credentials stay outside Soundcheck.
3. Collect ordered candidate files and build the submissions metadata. Do not
   accept a candidate-supplied contract or a claimed success result. Keep failed
   and missing tasks in the evaluator-owned suite.
4. Evaluate the candidates. Review minimized summaries before retention/sharing;
   keep generation time, token/cost records and independent target review separate.
5. For a measured agent study, repeat the preregistered tasks/runs and report
   the complete denominator, unknowns, failures and selection limits. These
   counts alone cannot establish security accuracy, production usefulness, an
   agent's pass@k under sampling assumptions, or generalization beyond the tasks.

Real deployment evaluation follows the
[pilot protocol](../../docs/evaluation/pilot-protocol.md). Choosing another
connector follows [evidence and semantic fit](../../docs/evaluation/connector-selection.md),
not the synthetic controls' success count.

## Focused checks

```sh
eval "$(opam env)"
dune runtest bench/repair --force -j 1
```

Unit tests cover strict metadata, frozen snapshots, failure accounting, spoofed
reports and privacy. Process tests exercise the evaluator with the real solver,
including valid repair, deny-all, out-of-scope regression, unsupported semantics,
missing/malformed inputs and symlink rejection. No live agent or deployment is
part of those checks.
