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
type outcome = Valid_change | Authorization_failed | Contract_failed | Out_of_scope_regression | Unknown
type evaluation = {
  outcome : outcome;
  frozen_contract : string option;
  before_sha256 : string;
  after_sha256 : string;
  authorization_allowed : bool option;
  comparison : Verify.comparison option;
}
val profile_id : string
val evaluation : t -> evaluation
(** Read-only view of one completed run for trusted evaluators. Binds the outer
    contract and exact inputs, retaining the original nested comparison/trace.
    Does not rerun authorization or the solver. This view contains private
    contract/report data; callers must minimize any published summary. *)

val run : ?z3:string -> Change_spec.t -> before:string -> after:string -> t
val invalid_contract : string -> before:string -> after:string -> t
val to_json : t -> string
val to_human : t -> string
val exit_code : t -> int
val profile_json : string
val evidence_files : Soundcheck_core.Evidence.provenance -> t -> ((string * string) list, string) result
val write_evidence : directory:string -> t -> (unit, string) result
