(** Frozen ordered policy operations. Array order is part of canonical identity;
    every step shares the unchanged actor and nested access requirements. *)
type t
val kind : string
val max_steps : int
val has_kind : string -> bool
val of_string : string -> (t, string) result
val actor : t -> Identity.identity
val steps : t -> Change_spec.t list
val requirements : t -> Contract_spec.t
val canonical : t -> string
val review : t -> string
