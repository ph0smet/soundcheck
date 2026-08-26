(** IPv4 address blocks for source-address policy.

    Membership in a block is a bitmask test, so the symbolic source address is a
    32-bit bitvector and {!to_smt} emits [(= (bvand ip mask) base)] — decided
    exactly and cheaply, where a string encoding would have turned every range
    test into string arithmetic. IPv6 is out of scope for v0 and {!parse} rejects
    it rather than ignoring it. *)

type t = {
  base : int32;  (** network address, already masked *)
  bits : int;    (** prefix length, 0..32 *)
}

val parse : string -> (t, string) result
(** Accepts ["10.0.0.0/8"] and a bare ["10.1.2.3"] (treated as [/32]).
    [Error reason] for IPv6, malformed addresses, or an out-of-range prefix. *)

val contains : t -> int32 -> bool
(** Concrete membership, used to re-check a counterexample without the solver. *)

val to_smt : var:string -> t -> string
(** Membership as an SMT-LIB2 boolean over the named [(_ BitVec 32)] constant. *)

val to_string : t -> string
val string_of_ip : int32 -> string
