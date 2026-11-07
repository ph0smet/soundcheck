val domain : Contract_spec.t -> Soundcheck_core.Ir.condition
val policy : Contract_spec.t -> Snapshot.t -> Soundcheck_core.Ir.policy
val granting_rules : Soundcheck_core.Ir.policy -> Soundcheck_core.Ir.request -> string list
