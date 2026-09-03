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

val condition_query :
  name:string -> description:string -> Ir.condition -> string
(** Full SMT-LIB2 script asking whether a condition is satisfiable. Used to
    reject a must-deny property whose forbidden request class is empty before
    interpreting [unsat] against a policy as a proof. *)

val overlap_query : Contract.clause -> Contract.clause -> string
(** Ask whether the request classes of two clauses overlap. A satisfiable result
    for a [Must_deny]/[Must_allow] pair means the contract is inconsistent. *)

val definitely_allowed_formula : Ir.policy -> string
(** A conservative allowance predicate for functionality proofs. With a known
    winner it requires that winner to allow the request. When several rules are
    possible because their order is tied or incomparable, it requires every
    possible winner to allow. Uncertainty can therefore cause a false violation,
    never a false functionality proof. *)

val contract_clause_query : Ir.policy -> Contract.clause -> string
(** Ask for a counterexample to one contract clause. For [Must_deny], this is an
    allowed forbidden request. For [Must_allow], it is a required request that is
    not definitely allowed. *)

val to_smtlib : Ir.policy -> Property.t -> string
(** Full SMT-LIB2 script ending in [(check-sat)] and a [(get-value ...)] over the
    symbolic request fields, so a [sat] result yields a concrete counterexample. *)

val shadowing_query : Ir.policy -> Shadowing.pair -> string
(** Script for ONE candidate shadowing pair, satisfiable iff the shadowing rule
    serves and permits a request the shadowed rule was written to handle and
    would have denied. Shares the winner-takes-all selection encoding with
    {!to_smtlib}, so both agree on which rule serves a request. *)
