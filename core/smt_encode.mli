(** Encode an {!Ir.policy} together with a {!Property.t} into an SMT-LIB2 query.

    The emitted script is satisfiable iff some request {e violates} the property
    (is in the forbidden class yet allowed by the policy). We emit standard
    SMT-LIB2 text that any SMT solver can check; the string doubles as an
    inspectable audit artifact.

    v0 symbolic request model:
    - [path]    : the resource, as an SMT [String]
    - [method]  : the action, as an SMT [String]
    - [is_anon] : whether the principal is anonymous, as a [Bool]
    - [scheme]  : the normalized request protocol
    - [sni]     : TLS Server Name Indication, or the empty string
    - one [Bool] for every exact header-name/value membership used by a policy

    Exact named-principal and typed object coordinates are declared and observed
    only when the obligation uses their predicates. Existing HTTP queries retain
    their original observation fields. Object predicates require an explicit
    [has_object_request] Boolean, so absent coordinates cannot match a literal. *)

val cond : Ir.condition -> string
(** One condition as an SMT-LIB2 boolean over the symbolic request constants.
    Exposed so tests can check a single condition against its concrete reading
    without building a whole policy. *)

val condition_query :
  ?domain:Ir.condition ->
  name:string -> description:string -> Ir.condition -> string
(** Full SMT-LIB2 script asking whether a condition is satisfiable. Used to
    reject a must-deny property whose forbidden request class is empty before
    interpreting [unsat] against a policy as a proof. *)

val overlap_query :
  ?domain:Ir.condition -> Contract.clause -> Contract.clause -> string
(** Ask whether the request classes of two clauses overlap. A satisfiable result
    for a [Must_deny]/[Must_allow] pair means the contract is inconsistent. *)

val definitely_allowed_formula : Ir.policy -> string
(** A conservative allowance predicate for functionality proofs. With a known
    winner it requires that winner to allow the request. When several rules are
    possible because their order is tied or incomparable, it requires every
    possible winner to allow. Uncertainty can therefore cause a false violation,
    never a false functionality proof. *)

val possibly_allowed_formula : Ir.policy -> string
(** The same possible-allowance expression used by the production safety
    encoder, without a structural rule filter. Callers must separately assert
    [policy.request_domain]. Exposed for independent target conformance of
    concrete request decisions, without reconstructing the policy encoding. *)

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

val decision_equivalence_query :
  ?when_:Ir.condition -> Ir.policy -> Ir.policy -> string
(** Ask for a request on which two policies make different Allow/Deny decisions.
    Unsatisfiable means decision-equivalent over the union of their request
    domains and within [when_] (default: every request). Connectors must
    separately establish that each lowered policy is exact enough for an
    equivalence proof. *)

type string_term =
  | Request_path
  | Literal of string
  | Concat of string_term list
  | Drop_prefix of int
  | If of string_test * string_term * string_term

and string_test =
  | Equal of string_term * string_term
  | Starts_with of string_term * string
  | Ends_with of string_term * string
  | Length_greater_than of string_term * int

val eval_string_term : path:string -> string_term -> string
(** Concrete reading of a symbolic string observation. Connectors use the same
    term for SMT comparison and counterexample rendering. *)

val route_equivalence_query :
  ?when_:Ir.condition ->
  ?left_value:(Ir.rule -> string_term) ->
  ?right_value:(Ir.rule -> string_term) ->
  left_label:(Ir.rule -> string) ->
  right_label:(Ir.rule -> string) ->
  Ir.policy ->
  Ir.policy ->
  string
(** Ask for a request where either the decision, connector-supplied selected
    label, or optional request-dependent string observation differs. Labels and
    values are connector-defined, so target concepts do not enter the IR. *)
