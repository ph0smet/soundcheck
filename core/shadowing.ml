(* The no-shadowed-routes property.

   Unlike the reachability templates, this one is not a single query over
   requests: it quantifies over WHICH RULE SERVES a request, so it is asked once
   per candidate pair of rules. That is why it lives here rather than as a
   {!Property.t} value — [Property.t] describes one forbidden class of requests,
   and this describes a relationship between two rules.

   For an ordered pair (shadowing i, shadowed k) the query is

     ∃ req.  selected_i(req) ∧ may_match_k(req) ∧ may_guard_i(req) ∧ ¬must_guard_k(req)

   read as a model-level candidate that i may serve while k's protection is
   not established. With incomplete matches/guards this can be a conservative
   finding, not a guaranteed target execution.

   Note the polarity: may-guard for i, negated must-guard for k. Negating k's
   upper bound would omit possible violations under an incomplete guard.
   Writing ¬guard_i instead makes the query trivially unsatisfiable exactly when i
   is unguarded, which is the interesting case, so the property would silently
   find nothing. *)

type pair = {
  shadowing : Ir.rule;  (** possible permissive winner *)
  shadowed  : Ir.rule;  (** route whose protection is not established *)
}

(* A guard read as the SET of constraints it imposes: [True] imposes nothing, a
   conjunction imposes each conjunct, anything else is one opaque constraint. *)
let rec constraints (c : Ir.condition) : Ir.condition list =
  match c with
  | Ir.True -> []
  | Ir.And cs -> List.concat_map constraints cs
  | c -> [ c ]

let subset xs ys = List.for_all (fun x -> List.mem x ys) xs

(* Retained for library compatibility; this syntactic heuristic is incomplete
   and must not be used to exclude candidate pairs. *)
let strictly_weaker (a : Ir.condition) (b : Ir.condition) : bool =
  let ca = constraints a and cb = constraints b in
  subset ca cb && not (subset cb ca)

(* Prune only with a sufficient implication proof: every conjunct of [b] also
   occurs in [a], so [a && not b] is impossible. Otherwise ask the solver.
   Requiring [a]'s constraints to be a strict subset of [b]'s was UNSOUND:
   unrelated guards (auth versus a network, or two distinct networks) can still
   admit a request through [a] that [b] denies. Structural non-implication is
   not evidence of semantic implication, so it must never suppress a query. *)
let may_be_more_permissive (a : Ir.condition) (b : Ir.condition) : bool =
  not (subset (constraints b) (constraints a))

(* Pairs worth asking the solver about. Pruning is purely static and only removes
   pairs whose query could not be interesting:

   - i ranks at least as high as k, so it can take the request;
   - i's guard is not syntactically known to imply k's guard;
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
            (not (k.Ir.match_complete && Ir.outranks k.Ir.priority i.Ir.priority))
            && i.Ir.id <> k.Ir.id
            && i.Ir.decision = Ir.Allow
            && k.Ir.decision = Ir.Allow
            && may_be_more_permissive i.Ir.guard (Ir.must_guard k)
          then Some { shadowing = i; shadowed = k }
          else None)
        p.rules)
    p.rules

let name = "no-shadowed-routes"

let description =
  "No route may be shadowed by a more permissive route that outranks it"
