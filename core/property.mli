(** Security invariants (properties) over the decision IR.

    A property in Soundcheck's v0 {e reachability} family asserts that a class of
    requests must never be allowed:

    {[ ∀ req. matches [forbidden_when] req  ⇒  evaluate policy req = Deny ]}

    Verification checks the {e negation} — does there exist an allowed request in
    that forbidden class? — so an SMT [sat] result is a concrete counterexample
    and [unsat] is a proof the property holds for all requests. *)

type t = {
  name           : string;
  description    : string;
  forbidden_when : Ir.condition;
      (** the class of requests the policy must Deny *)
}

val must_deny : name:string -> description:string -> Ir.condition -> t
(** General constructor: every request matching the condition must be denied. *)

val no_anonymous_access : path_prefix:string -> t
(** Template: no anonymous request may be allowed under [path_prefix]
    (e.g. ["/admin"]). *)
