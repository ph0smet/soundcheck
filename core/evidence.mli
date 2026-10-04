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

val files : t -> (string * string) list
(** Relative paths and exact contents, in deterministic write order. The
    manifest is last and serves as the completion marker. *)

val write : directory:string -> t -> (unit, string) result
(** Create a new private directory and exclusively create its files. An
    existing file, directory, or symlink at [directory] is never overwritten.
    The parent directory must exist. A failed write can leave an incomplete
    new directory without a manifest; errors are returned to the caller. *)
