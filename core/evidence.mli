(** Versioned audit bundles, independent of any connector or adapter. The
    manifest binds the exact input bytes and every payload with SHA-256. *)

type provenance = {
  executable_sha256 : string;
  ocaml_version     : string;
  z3_version        : (string, string) result;
}

type profile = {
  id   : string;
  json : string;
}
(** A connector supplies its complete profile as opaque canonical JSON. *)

type t

val schema_version : int
(** Manifest schema 2 retains optional exact named identity and typed object
    coordinates on every recorded SAT model; absent dimensions are null. *)

val collect_provenance : unit -> (provenance, string) result
(** Identify this verifier executable by SHA-256 and capture the OCaml and Z3
    versions. An unavailable Z3 version remains explicit in the bundle. *)

val create :
  config:string -> profile:profile -> provenance:provenance ->
  report:Report.t -> trace:Contract_verify.trace_entry list option ->
  (t, string) result
(** Construct deterministic bundle contents from one frozen verification run.
    [config] must be the exact string passed to the verifier. [trace] retains
    every planned query, including those not executed after short-circuiting.
    [None] is accepted only for an unsupported [Unknown] report, and records
    that no plan could be generated. The config itself is not copied. *)

type preservation_trace = {
  id : string;
  smtlib : string;
  execution : Contract_verify.execution;
}

type comparison_trace = {
  candidate : Contract_verify.trace_entry list;
  preservation : preservation_trace;
}
(** One candidate-contract execution followed by the planned preservation
    obligation. An unsuccessful candidate leaves preservation [Not_executed],
    retaining its query. SAT executions must already have passed witness
    validation before being supplied here. *)

val comparison_schema_version : int
(** Schema 3 identifies repair comparisons explicitly; verification bundles
    retain schema 2 and their existing serialization. *)

val create_comparison :
  before:string -> after:string -> profile:profile -> provenance:provenance ->
  report:Report.t -> candidate_report:Report.t option ->
  trace:comparison_trace option -> (t, string) result
(** Bind the exact before/after bytes to the frozen contract, candidate report,
    final comparison report, and complete candidate/preservation plan. Input
    contents are hashed, not copied. The candidate report is written separately
    as [candidate-report.json]. The final report remains [report.json].

    Complete plans require a candidate report with the same frozen specification
    and profile. Execution order and outcomes must agree with both reports:
    only a proved candidate can execute preservation; a proved comparison also
    requires an executed UNSAT preservation result. Query IDs must be safe and
    unique across both stages. For unsupported input, both optional arguments
    are [None] and the final report must be unsupported/unknown; its unavailable
    plan and absent candidate report remain explicit.

    This checks structural consistency, not the semantics of supplied SMT text
    or the completeness of a connector's plan. It never invokes a solver or
    revalidates a witness. The caller must retain the exact queries, validated
    executions, and reports from the single comparison run. *)

val files : t -> (string * string) list
(** Relative paths and exact contents, in deterministic write order. The
    manifest is last and serves as the completion marker. *)

val write : directory:string -> t -> (unit, string) result
(** Create a new private directory and exclusively create its files. An
    existing file, directory, or symlink at [directory] is never overwritten.
    The parent directory must exist. A failed write can leave an incomplete
    new directory without a manifest; errors are returned to the caller. *)
