(** Concrete requests for reference conformance; arbitrary identity/group
    substitutions and out-of-profile requests are rejected. Schema 8 requires
    operation instead of verb, including conditional SSA branches. *)
type request = private { id:string; request:Soundcheck_core.Ir.request }
val requests : Contract_spec.t -> string -> (request list,string) result
val decisions : Soundcheck_core.Ir.policy -> request list -> Strict_json.value
val matrix_smt : Soundcheck_core.Ir.policy -> request list -> string
