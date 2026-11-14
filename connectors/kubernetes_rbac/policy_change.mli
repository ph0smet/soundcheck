(** Single-operation RBAC authorization from the original snapshot, followed by
    the existing frozen access/preservation verifier. Authorization is a bounded
    native-policy computation; only the nested verification uses SMT. *)
type attributes = { verb : string; namespace : string; resource : string; name : string }
type check = { attributes : attributes; granting_rules : int list }
type authorization = {
  allowed : bool; initial : check; special : check option;
  coverage : Policy_coverage.t option; reason : string;
}
val authorize : Change_spec.t -> before:string -> after:string -> (authorization, string) result
val authorization_json : authorization -> string
type t
val run : ?z3:string -> Change_spec.t -> before:string -> after:string -> t
val invalid_contract : string -> before:string -> after:string -> t
val to_json : t -> string
val to_human : t -> string
val exit_code : t -> int
val profile_json : string
val evidence_files : Soundcheck_core.Evidence.provenance -> t -> ((string * string) list, string) result
val write_evidence : directory:string -> t -> (unit, string) result
