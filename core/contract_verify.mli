(** Connector-independent verification of a frozen multi-clause contract. *)

type result =
  | Proved
  | Vacuous of Contract.clause
      (** One clause governs an empty request class. *)
  | Inconsistent of Contract.clause * Contract.clause
      (** A safety and functionality clause govern at least one common request. *)
  | Violated of Contract.clause * Solve.model
      (** A concrete request violates the named clause. *)
  | Unknown of string

type phase = Inhabitance | Consistency | Clause

type obligation = {
  id      : string;
      (** Stable, filesystem-safe identity derived from phase, ordinal, and
          related clause names. *)
  phase   : phase;
  clauses : string list;
  smtlib  : string;
}

type execution = Not_executed | Executed of Solve.result

type trace_entry = {
  obligation : obligation;
  execution  : execution;
}

val plan : Ir.policy -> Contract.t -> obligation list
(** Construct every proof obligation in deterministic execution order:
    inhabitance, safety/functionality consistency, then policy clauses. No
    solver is invoked. *)

val run_with_trace : ?z3:string -> Ir.policy -> Contract.t -> result * trace_entry list
(** Verify with the same short-circuit semantics as {!run}, while retaining the
    complete plan. Obligations after the decisive result are [Not_executed]
    rather than silently absent. Every SAT witness is checked before it is
    recorded: an invalid witness is [Executed (Solve.Unknown _)], never a
    published counterexample or unchecked preflight result. *)

val run : ?z3:string -> Ir.policy -> Contract.t -> result
(** Validate and verify a contract atomically.

    Validation precedes policy verification: every clause class must be
    inhabited, then every safety/functionality pair must be disjoint. Only a
    valid contract is checked against the policy. Clauses are checked in their
    declared order and the first violation is returned. *)
