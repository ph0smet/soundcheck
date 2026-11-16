(** A distinct frozen single-operation contract. Existing access contracts and
    their canonical identities are nested without changing their semantics. *)
type operation = Create | Update_existing | Delete_existing
type target = { kind : string; namespace : string; name : string }
type t
val kind : string
val has_kind : string -> bool
(** Dispatch only; this does not validate a change contract. *)

val of_string : string -> (t, string) result
val version : t -> int
val actor : t -> Identity.identity
val operation : t -> operation
val target : t -> target
val requirements : t -> Contract_spec.t
val operation_name : operation -> string
val resource : target -> string
val canonical : t -> string
val review : t -> string
