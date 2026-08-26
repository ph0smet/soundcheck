(** Run an SMT-LIB2 query through the [z3] CLI and interpret the outcome. *)

type model = {
  path    : string;
  method_ : string;
  is_anon : bool;
  src_ip  : int32;   (** IPv4 source address of the violating request *)
}
(** A concrete counterexample request extracted from a [sat] model. *)

type result =
  | Proved                 (** [unsat]: no request violates the property *)
  | Violated of model      (** [sat]: a concrete violating request *)
  | Unknown of string      (** solver said [unknown], or output was unparseable *)

val check : ?z3:string -> ?emit_smt:string -> string -> result
(** [check ?z3 ?emit_smt smtlib] writes [smtlib] to a file, runs [z3 -smt2] on it
    (default binary ["z3"], resolved on PATH) and parses the result.

    When [emit_smt] is [Some path] the query is written there and kept, so the
    proof obligation remains as an audit artifact that any SMT-LIB2 solver can
    re-check independently. Otherwise a temp file is used and removed. *)

val string_of_result : result -> string
