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
