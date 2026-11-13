(** Solver-free review of the frozen request domain and source rule references.
    Does not infer requirements, evaluate access, or establish completeness. *)
val run : snapshot:string -> contract:string -> (string,string) result
