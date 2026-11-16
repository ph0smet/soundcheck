(** Frozen ordered policy operations. Array order is part of canonical identity;
    every step shares the unchanged actor and nested access requirements. *)
type t
val kind : string
val max_steps : int
val has_kind : string -> bool
val of_string : string -> (t, string) result
val version : t -> int
val invariants : t -> string list
(** Schema 2 selects existing nested requirement clause names. They must hold
    at S0 and every post-step state, with the same identity and request domain. *)

val actor : t -> Identity.identity
val steps : t -> Change_spec.t list
val requirements : t -> Contract_spec.t
val canonical : t -> string
val frozen_spec : t -> Soundcheck_core.Report.frozen_spec
val review : t -> string
