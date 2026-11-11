(** Read-only, solver-free rendering of a structurally accepted frozen contract.
    This is an authoring aid, not a verification result or a new report schema.
    Inhabitation, consistency, access and preservation remain unchecked. *)
val run : string -> (string, string) result
