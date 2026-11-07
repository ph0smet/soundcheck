(** Frozen identity context, paired access requirements and approved change
    scope, loaded independently of candidate configuration. *)
type scope = { subject:string; namespace:string; resource:string; names:string list option }
type kind = Must_allow | Must_not_grant
type clause = { name:string; kind:kind; scope:scope }
type t
val kind : string
val of_string : string -> (t,string) result
val identities : t -> Identity.identity list
val clauses : t -> clause list
val changes : t -> scope list
val scope_condition : scope -> Soundcheck_core.Ir.condition
val approved_changes : t -> Soundcheck_core.Ir.condition
val to_contract : t -> Soundcheck_core.Contract.t
val canonical : t -> string
val frozen_spec : t -> Soundcheck_core.Report.frozen_spec
