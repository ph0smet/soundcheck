(** Thin connector orchestration over the shared core. Contracts are immutable
    typed values loaded outside candidate control. All SAT witnesses are checked
    by core before lifting. No runtime target/cluster replay is claimed. *)
val invalid_contract : string -> Soundcheck_core.Report.t
val run : ?z3:string -> Contract_spec.t -> string -> Soundcheck_core.Report.t
val compare : ?z3:string -> Contract_spec.t -> before:string -> after:string -> Soundcheck_core.Report.t
