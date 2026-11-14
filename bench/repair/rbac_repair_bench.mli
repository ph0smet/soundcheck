(** Experimental evaluator for submitted static RBAC repairs. Candidate
    generation and agent execution remain outside Soundcheck. *)

type frozen_suite
type submissions

type failure =
  | Contract_read_error | Contract_invalid | Baseline_read_error
  | Candidate_read_error | Evaluation_error | Report_mismatch
  | Missing_submission | Submissions_read_error | Submissions_invalid | Unexpected_error

type attempt_row = {
  id : string;
  ordinal : int;
  candidate_sha256 : string option;
  contract_result : string option;
  repair_result : string option;
  contract_assurance : string option;
  comparison_assurance : string option;
  authorization_result : string option;
  change_assurance : string option;
  failure : failure option;
  elapsed_seconds : float;
}

type task_row = {
  id : string;
  provenance : Pilot.provenance;
  profile : string option;
  contract_kind : string option;
  access_profile : string option;
  baseline_sha256 : string option;
  contract_sha256 : string option;
  frozen_contract_sha256 : string option;
  failure : failure option;
  attempts : attempt_row list;
}

val freeze :
  ?read_suite:(string -> (string, unit) result) ->
  suite_root:string -> Pilot.manifest -> frozen_suite
(** Read each distinct evaluator-owned input path once, before reading
    submissions. Keep exact baseline bytes and immutable parsed contracts.
    [contract_sha256] binds raw contract bytes; [frozen_contract_sha256] binds
    their canonical identity, including fixed context and change scope. Change
    contracts also freeze actor, operation, target and all nested requirements.
    Stable trusted inputs are required while freezing; this is not a sandbox. *)

val parse_submissions :
  frozen_suite -> string -> (submissions, unit) result
(** Reuse the strict candidate-only submission metadata format. Contract,
    baseline, scope, context, solver and outcome overrides are rejected. *)

val run :
  ?read_candidate:(string -> (string, unit) result) ->
  ?evaluate:(Soundcheck_kubernetes_rbac.Contract_spec.t -> before:string ->
             after:string -> Soundcheck_kubernetes_rbac.Verify.comparison) ->
  ?evaluate_change:(Soundcheck_kubernetes_rbac.Change_spec.t -> before:string ->
             after:string -> Soundcheck_kubernetes_rbac.Policy_change.t) ->
  ?now:(unit -> float) -> submission_root:string ->
  frozen_suite -> submissions -> task_row list
(** Read each candidate once per attempt. Dispatch the frozen contract to either
    [Verify.compare_with_trace] or [Policy_change.run] exactly once. Project
    stages from that run without rerunning authorization or the solver.
    Unsupported snapshots leave the candidate stage unavailable; all Unknown
    verdicts stay unknown, including solver failures/timeouts. Raised evaluator
    exceptions and incoherent reports become explicit tool failures. A change
    result must bind the outer frozen contract and exact before/after bytes. *)

val failed_tasks : failure -> frozen_suite -> task_row list
(** Preserve the frozen schedule and available input digests when submission
    metadata is missing or invalid. *)

val exit_code : task_row list -> int
(** 0: every task has a valid repair/change and no input/tool errors; 1: an input/tool
    error, missing submission or empty suite; 3: completed but not all solved. *)

val to_json : task_row list -> string
(** Minimized experimental summary: never contains raw reports, inputs,
    witnesses, formulas, paths, canonical contracts or diagnostic text.
    Access-only suites retain formats 1/2 (2 for any frozen non-v1 access
    contract). Any frozen policy-change contract selects format 3, including
    mixed suites and failed submissions; it adds authorization/outer assurance,
    per-task contract kind/access profile, valid_change and authorization_failed.
    No frozen public contract or verifier report schema is changed. *)

val fatal_json : string -> string
(** The argument must be an internal failure constant, not a diagnostic. *)
