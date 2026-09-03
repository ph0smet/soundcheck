(** A frozen verification contract composed of safety and functionality clauses.

    [Must_deny] is the existing safety shape: every request in a class must be
    denied. [Must_allow] is its functionality dual: every request in a class
    must be allowed. A contract is satisfied only when every clause holds. *)

type clause =
  | Must_deny of {
      name           : string;
      description    : string;
      forbidden_when : Ir.condition;
      reach_via      : Ir.rule -> bool;
    }
  | Must_allow of {
      name          : string;
      description   : string;
      required_when : Ir.condition;
    }

type t = {
  name        : string;
  description : string;
  clauses     : clause list;
}

val must_deny :
  ?reach_via:(Ir.rule -> bool) ->
  name:string -> description:string -> Ir.condition -> clause

val must_allow :
  name:string -> description:string -> Ir.condition -> clause

val request_class : clause -> Ir.condition
(** The request class governed by a clause, independent of the policy. *)

val name : clause -> string
val description : clause -> string

val safety_functionality_overlaps : t -> (clause * clause) list
(** Every safety/functionality pair whose request classes must be checked for
    overlap. Satisfiable overlap makes the contract internally inconsistent. *)
