(** Thin connector orchestration over the shared core. Contracts are immutable
    typed values loaded outside candidate control. All SAT witnesses are checked
    by core before lifting. No runtime target/cluster replay is claimed. *)
val invalid_contract : string -> Soundcheck_core.Report.t
val run : ?z3:string -> Contract_spec.t -> string -> Soundcheck_core.Report.t
val run_with_trace : ?z3:string -> Contract_spec.t -> string ->
  Soundcheck_core.Report.t * Soundcheck_core.Contract_verify.trace_entry list option
(** The same verification run, with every planned obligation and its validated
    execution result. Short-circuited obligations are retained as unexecuted.
    Unsupported snapshots return [None]; no solver is rerun to collect evidence. *)

val compare : ?z3:string -> Contract_spec.t -> before:string -> after:string -> Soundcheck_core.Report.t

type comparison = {
  report : Soundcheck_core.Report.t;
  candidate_report : Soundcheck_core.Report.t option;
  trace : Soundcheck_core.Evidence.comparison_trace option;
}

val compare_with_trace : ?z3:string -> Contract_spec.t -> before:string -> after:string -> comparison
(** The same comparison with candidate and preservation evidence from one run.
    Both snapshots must be supported before planning; otherwise [candidate_report]
    and [trace] are absent. A failed candidate retains an unexecuted preservation
    query. Executed preservation models are validated before recording. *)

type preservation_plan
type preservation = {
  report : Soundcheck_core.Report.t;
  trace : Soundcheck_core.Evidence.preservation_trace;
}
val plan_preservation : Contract_spec.t -> before:string -> after:string ->
  (preservation_plan, string) result
val preservation_query : preservation_plan -> string
val execute_preservation : ?z3:string -> preservation_plan -> preservation
(** A preservation-only obligation for an intermediate sequence state. It does
    not check or assert access clauses. Every SAT result is validated against
    baseline/candidate decisions outside the frozen scope before lifting. *)
