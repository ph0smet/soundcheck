(** Experimental, local evaluation of externally supplied repair attempts.
    This module does not generate candidates or execute external agents. *)

type attempt = { task : string; id : string; config : string }

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
  (** The following assurance fields concern only the candidate's contract
      check; the baseline/preservation check may independently remain unknown. *)
  assurance : string option;
  finding_codes : string list;
  failure : failure option;
  elapsed_seconds : float;
}

type task_row = {
  id : string;
  provenance : Pilot.provenance;
  baseline_sha256 : string option;
  contract_sha256 : string option;
  failure : failure option;
  attempts : attempt_row list;
}

val parse_submissions :
  tasks:Pilot.manifest -> string -> (attempt list, unit) result
(** Strict versioned metadata. Unknown task IDs, duplicate attempt IDs within a
    task, and contract/result/mode overrides are rejected. Empty submissions are
    permitted so all missing tasks can be recorded explicitly. *)

val run :
  ?read_suite:(string -> (string, unit) result) ->
  ?read_candidate:(string -> (string, unit) result) ->
  ?evaluate:(Soundcheck_kong.Contract_spec.t -> string -> string ->
             (Soundcheck_kong.Compare.repair_report, string) result) ->
  ?now:(unit -> float) ->
  suite_root:string -> submission_root:string ->
  Pilot.manifest -> attempt list -> task_row list
(** Snapshot all distinct contracts and baseline files before the first
    evaluation. Each candidate is read once per attempt and evaluated against
    that original snapshot using security-decision preservation. Tasks and
    attempts retain suite/submission order, including failures. Inputs must be
    stable while read; this is not a race-resistant sandbox or approval system. *)

val exit_code : task_row list -> int
(** 0: each task has an accepted submitted repair and no input/tool errors.
    1: any input/tool error, missing submission, or empty suite.
    3: evaluation completed without errors, but some tasks have no valid repair. *)

val to_json : task_row list -> string
(** Minimized summary of submitted artifacts, not an autonomous-agent score. *)

val failed_tasks : failure -> Pilot.manifest -> task_row list
(** Retain a known evaluator-owned schedule if submissions cannot be loaded.
    No baseline, contract, or candidate is read. *)

val fatal_json : string -> string
(** Argument must be an internal failure constant, never a raw diagnostic. *)
