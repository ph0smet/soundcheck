(** Concrete validation of decoded SAT witnesses against the asserted
    obligation. This is a model-level sanity check, not replay against a target
    system and not an independent proof of the encoder's soundness. *)

val request_of_model : Solve.model -> Ir.request

val validate :
  obligation:string -> (Ir.request -> bool) -> Solve.result -> Solve.result
(** Preserve non-SAT results. A SAT witness that does not satisfy the supplied
    obligation, or whose evaluation raises, becomes [Solve.Unknown]. Consumers
    must store and use this checked result, including in execution traces. *)

val condition : domain:Ir.condition -> Ir.condition -> Ir.request -> bool
val property : Ir.policy -> Property.t -> Ir.request -> bool
val clause : Ir.policy -> Contract.clause -> Ir.request -> bool
val shadowing : Ir.policy -> Shadowing.pair -> Ir.request -> bool

val decision_difference :
  ?when_:Ir.condition -> Ir.policy -> Ir.policy -> Ir.request -> bool

val route_difference :
  ?when_:Ir.condition ->
  ?left_value:(Ir.rule -> Smt_encode.string_term) ->
  ?right_value:(Ir.rule -> Smt_encode.string_term) ->
  left_label:(Ir.rule -> string) -> right_label:(Ir.rule -> string) ->
  Ir.policy -> Ir.policy -> Ir.request -> bool
(** Validate the same decision, selected-label set, and optional selected-value
    disjunction as [Smt_encode.route_equivalence_query]. Domain and comparison
    scope checks are required even when a difference exists elsewhere. *)
