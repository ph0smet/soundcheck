(* The no-shadowed-routes property.

   Unlike the reachability templates, this one is not a single query over
   requests: it quantifies over WHICH RULE SERVES a request, so it is asked once
   per candidate pair of rules. That is why it lives here rather than as a
   {!Property.t} value — [Property.t] describes one forbidden class of requests,
   and this describes a relationship between two rules.

   For an ordered pair (shadowing i, shadowed k) the query is

     ∃ req.  selected_i(req) ∧ match_k(req) ∧ guard_i(req) ∧ ¬guard_k(req)

   read as: a request that i actually serves AND LETS THROUGH, which k was
   written to handle and WOULD HAVE STOPPED. Satisfiable means k's guard does not
   cover traffic k's own match would accept, because i outranks it.

   Note the polarity: it is [guard_i] (i permits) and [¬guard_k] (k would deny).
   Writing ¬guard_i instead makes the query trivially unsatisfiable exactly when i
   is unguarded, which is the interesting case, so the property would silently
   find nothing. *)

type pair = {
  shadowing : Ir.rule;  (** higher priority: the rule that actually serves *)
  shadowed  : Ir.rule;  (** lower priority: the rule written to handle it *)
}

(* [a] is strictly weaker than [b] when b constrains requests that a lets
   through. With the v0 condition set the only guards a connector produces are
   [True] and [Requires_auth], so this is the one meaningful pairing; it is a
   function rather than a literal so widening the guard vocabulary has one place
   to change. Being conservative here costs findings, never soundness. *)
let strictly_weaker (a : Ir.condition) (b : Ir.condition) : bool =
  match (a, b) with Ir.True, Ir.Requires_auth -> true | _ -> false

(* Pairs worth asking the solver about. Pruning is purely static and only removes
   pairs whose query could not be interesting:

   - i ranks at least as high as k, so it can take the request;
   - a strictly weaker guard on i, else serving the request is no loss;
   - different routes — a route split across several paths cannot shadow itself.

   Note the test is "k does not outrank i", not "i outranks k". That admits three
   cases: i genuinely outranks k, the two are equal, and the two are incomparable.
   The latter two both mean the connector could not establish an order (Kong
   breaks such ties on a creation timestamp a declarative config does not carry),
   so EITHER may serve — and if the weaker one does, the guard is bypassed.
   Requiring a strict outranking would report [proved] for a config whose
   behaviour is genuinely undetermined, which is the false-proof direction.
   Reporting it costs a review; missing it does not.

   This is the opposite of the choice {!Smt_encode.selected} makes about ties, and
   deliberately so: there, admitting both rules over-approximates what is
   reachable (sound for reachability); here, admitting both over-approximates what
   might be shadowed (sound for shadowing). Both err away from a false proof.

   Whether the matches actually overlap is left to the solver: that is a
   satisfiability question, and answering it here would duplicate the encoder. *)
let candidates (p : Ir.policy) : pair list =
  List.concat_map
    (fun (i : Ir.rule) ->
      List.filter_map
        (fun (k : Ir.rule) ->
          if
            (not (Ir.outranks k.Ir.priority i.Ir.priority))
            && i.Ir.id <> k.Ir.id
            && i.Ir.decision = Ir.Allow
            && k.Ir.decision = Ir.Allow
            && strictly_weaker i.Ir.guard k.Ir.guard
          then Some { shadowing = i; shadowed = k }
          else None)
        p.rules)
    p.rules

let name = "no-shadowed-routes"

let description =
  "No route may be shadowed by a more permissive route that outranks it"
