(** Run an SMT-LIB2 query through the [z3] CLI and interpret the outcome. *)

type model = {
  path    : string;
  method_ : string;
  is_anon : bool;
}
(** A concrete counterexample request extracted from a [sat] model. *)

type result =
  | Proved                 (** [unsat]: no request violates the property *)
  | Violated of model      (** [sat]: a concrete violating request *)
  | Unknown of string      (** solver said [unknown], or output was unparseable *)

val check : ?z3:string -> string -> result
(** [check ?z3 smtlib] writes [smtlib] to a temp file, runs [z3 -smt2] on it
    (default binary ["z3"], resolved on PATH) and parses the result. *)

val string_of_result : result -> string
