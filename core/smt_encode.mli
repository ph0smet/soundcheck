(** Encode an {!Ir.policy} together with a {!Property.t} into an SMT-LIB2 query.

    The emitted script is satisfiable iff some request {e violates} the property
    (is in the forbidden class yet allowed by the policy). We emit standard
    SMT-LIB2 text that any SMT solver can check; the string doubles as an
    inspectable audit artifact.

    v0 symbolic request model:
    - [path]    : the resource, as an SMT [String]
    - [method]  : the action, as an SMT [String]
    - [is_anon] : whether the principal is anonymous, as a [Bool] *)

val to_smtlib : Ir.policy -> Property.t -> string
(** Full SMT-LIB2 script ending in [(check-sat)] and a [(get-value ...)] over the
    symbolic request fields, so a [sat] result yields a concrete counterexample. *)
