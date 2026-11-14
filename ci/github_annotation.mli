val render : file:string -> Soundcheck_core.Report.t -> string
(** Render one GitHub workflow-command annotation for a verification report. *)

val error : file:string -> title:string -> string -> string
(** Render an error annotation for failures that occur before a report exists. *)

val command : level:string -> file:string -> title:string -> string -> string
(** Escape a workflow-command annotation. Callers choose a fixed notice/error
    level, never a value from candidate configuration. *)
