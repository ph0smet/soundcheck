(** Review the exact independently supplied frozen identity context and subject
    matches. A matching binding may have empty or out-of-domain rules; this is
    not an authorization decision, proof, or authentication/completeness check. *)
val run : snapshot:string -> contract:string -> (string, string) result
