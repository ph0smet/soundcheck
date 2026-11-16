(** Ordered conditional policy changes; final access plus preservation at every
    post-step state. Authorization is deterministic native-policy analysis. *)
type outcome = Valid_sequence | Authorization_failed | Contract_failed | Invariant_failed | Out_of_scope_regression | Unknown
type phase = Preparation | Authorization | Final_verification | State_invariants | Intermediate_preservation | Complete
val phase_name : phase -> string
type step = {
  index : int;
  change : Change_spec.t;
  before_sha256 : string;
  after_sha256 : string;
  authorization : Policy_change.authorization option;
}
type invariant = {
  state : int;
  state_sha256 : string;
  queries : Soundcheck_core.Contract_verify.obligation list;
  verification : Verify.selected option;
}
type intermediate = { step : int; query : string; verification : Verify.preservation option }
type t
type evaluation = {
  outcome : outcome;
  frozen_contract : string option;
  before_sha256 : string;
  after_sha256 : string;
  authorization_allowed : bool option;
  comparison : Verify.comparison option;
  phase : phase;
  failing_step : int option;
  steps : step list;
  intermediate_preservation : intermediate list;
  state_invariants : invariant list;
}
val evaluation : t -> evaluation
val validate_evaluation : t -> (unit, string) result
(** Pure structural coherence of this single run's phase, identity, state chain,
    stage reports and recorded executions. Does not rerun any solver or imply
    independent verification of queries or target semantics. Evaluators must
    also bind the expected outer contract and exact input hashes. *)

val run : ?z3:string -> Sequence_spec.t -> before:string -> after:string -> t
val invalid_contract : string -> before:string -> after:string -> t
val profile_id : string
val profile_id_for_version : int -> string
val profile_json_for_version : int -> string
val profile_human_for_version : int -> string
val profile_json : string
val profile_human : string
val to_json : t -> string
val to_human : t -> string
val exit_code : t -> int
val evidence_files : Soundcheck_core.Evidence.provenance -> t -> ((string * string) list, string) result
val write_evidence : directory:string -> t -> (unit, string) result
