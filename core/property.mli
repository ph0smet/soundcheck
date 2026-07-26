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
  reach_via      : Ir.rule -> bool;
      (** which [Allow] rules count as "reaching" for this property. The encoder
          treats a request as allowed only via an allow-rule satisfying this
          predicate (the [Deny] side is unfiltered). Defaults to all rules — a
          plain reachability property. A {e structural} property narrows it: e.g.
          rate-limit-on-public counts only rules whose route lacks a rate limiter,
          so a satisfying model is a request reaching an unthrottled route. *)
}

val must_deny :
  ?reach_via:(Ir.rule -> bool) ->
  name:string -> description:string -> Ir.condition -> t
(** General constructor: every request matching the condition must be denied.
    [reach_via] defaults to [fun _ -> true] (all allow-rules reach). *)

val no_anonymous_access : path_prefix:string -> t
(** Template: no anonymous request may be allowed under [path_prefix]
    (e.g. ["/admin"]). *)

val rate_limit_on_public : t
(** Template: every anonymous-reachable route must carry a rate-limiting plugin.
    Encoded as reachability of an anonymous request via an {e unthrottled} allow
    rule ([reach_via] = not rate-limited); auth-required routes are exempt (an
    anonymous request cannot reach them). *)
