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
(** Legacy syntactic constraint-subset heuristic, retained for compatibility.
    [false] does NOT imply that no violating request exists. Do not use this
    incomplete heuristic to exclude pairs from a sound shadowing check. *)

val candidates : Ir.policy -> pair list
(** Statically-pruned pairs worth querying: priority at least as high and distinct
    routes (a route split across paths cannot shadow itself). Guard pruning is
    allowed only when a syntactic implication proves the pair cannot violate;
    unrelated guards still require a query. Match overlap is left to the solver.

    Equal priority counts, because it means the order is undetermined and the
    weaker rule may serve. Excluding ties would report [proved] for a config whose
    behaviour the file does not pin down. *)

val name : string
val description : string
