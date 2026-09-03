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

val run : Ir.policy -> Contract.t -> result
(** Validate and verify a contract atomically.

    Validation precedes policy verification: every clause class must be
    inhabited, then every safety/functionality pair must be disjoint. Only a
    valid contract is checked against the policy. Clauses are checked in their
    declared order and the first violation is returned. *)
