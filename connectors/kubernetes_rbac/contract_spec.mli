(** Frozen identity context, paired access requirements and approved change
    scope, loaded independently of candidate configuration.
    Empty [namespace] denotes the all-namespace collection endpoint in v2/v3.
    For list/watch, [names=None] includes both empty effective request name and
    every valid DNS object name. Named scopes use the effective authorization
    name, not the eventual list contents. V1 is always named get. V3 also
    supports named update/patch/delete, requiring nonempty namespace and name;
    [names=None] for these verbs means all supported named requests. *)
type scope = { subject:string; verb:string; namespace:string; resource:string; names:string list option }
type kind = Must_allow | Must_not_grant
type clause = { name:string; kind:kind; scope:scope }
type t
val kind : string
val of_string : string -> (t,string) result
val version : t -> int
val identities : t -> Identity.identity list
val clauses : t -> clause list
val changes : t -> scope list
val scope_condition : scope -> Soundcheck_core.Ir.condition
val approved_changes : t -> Soundcheck_core.Ir.condition
val to_contract : t -> Soundcheck_core.Contract.t
val canonical : t -> string
val frozen_spec : t -> Soundcheck_core.Report.frozen_spec
