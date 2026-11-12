val domain : Contract_spec.t -> Soundcheck_core.Ir.condition
val policy : Contract_spec.t -> Snapshot.t -> Soundcheck_core.Ir.policy
val granting_rules : Soundcheck_core.Ir.policy -> Soundcheck_core.Ir.request -> string list

(** Per-prerequisite source grants for an in-domain operation. Additional create
    uses the named SSA target. These are conditional evaluations, not an execution
    trace: an ungranted patch stops the native handler before its create check.
    This function accepts the exact additive policies produced by [policy]. *)
val authorization_checks : Soundcheck_core.Ir.policy -> Soundcheck_core.Ir.request -> (string * string list) list
