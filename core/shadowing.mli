(** The no-shadowed-routes property: a route whose guard fails to cover traffic
    its own match would accept, because a more permissive route outranks it.

    Asked once per candidate pair rather than once per config, because it
    quantifies over which rule serves a request rather than over requests alone.
    See {!Smt_encode.shadowing_query} for the emitted formula. *)

type pair = {
  shadowing : Ir.rule;  (** higher priority: the rule that actually serves *)
  shadowed  : Ir.rule;  (** lower priority: the rule written to handle it *)
}

val strictly_weaker : Ir.condition -> Ir.condition -> bool
(** Whether the first guard permits requests the second would stop. Conservative:
    an unrecognised pairing is reported as not-weaker, which costs findings but
    never soundness. *)

val candidates : Ir.policy -> pair list
(** Statically-pruned pairs worth querying: priority at least as high, strictly
    weaker guard, and distinct routes (a route split across paths cannot shadow
    itself). Match overlap is left to the solver.

    Equal priority counts, because it means the order is undetermined and the
    weaker rule may serve. Excluding ties would report [proved] for a config whose
    behaviour the file does not pin down. *)

val name : string
val description : string
