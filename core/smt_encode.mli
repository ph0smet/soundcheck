(** Encode an {!Ir.policy} together with a {!Property.t} into an SMT-LIB2 query.

    The emitted script is satisfiable iff some request {e violates} the property
    (is in the forbidden class yet allowed by the policy). We emit standard
    SMT-LIB2 text that any SMT solver can check; the string doubles as an
    inspectable audit artifact.

    v0 symbolic request model:
    - [path]    : the resource, as an SMT [String]
    - [method]  : the action, as an SMT [String]
    - [is_anon] : whether the principal is anonymous, as a [Bool] *)

val cond : Ir.condition -> string
(** One condition as an SMT-LIB2 boolean over the symbolic request constants.
    Exposed so tests can check a single condition against its concrete reading
    without building a whole policy. *)

val to_smtlib : Ir.policy -> Property.t -> string
(** Full SMT-LIB2 script ending in [(check-sat)] and a [(get-value ...)] over the
    symbolic request fields, so a [sat] result yields a concrete counterexample. *)

val shadowing_query : Ir.policy -> Shadowing.pair -> string
(** Script for ONE candidate shadowing pair, satisfiable iff the shadowing rule
    serves and permits a request the shadowed rule was written to handle and
    would have denied. Shares the winner-takes-all selection encoding with
    {!to_smtlib}, so both agree on which rule serves a request. *)
