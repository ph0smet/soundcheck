(** A versioned, human-confirmed Kong contract artifact.

    The artifact is parsed before a repair loop starts and converted once into
    the verifier's typed property. Keeping this format target-specific avoids
    pretending the current Kong-derived request vocabulary is already a
    universal specification language. *)

type t = {
  schema_version : int;
  kind           : string;
  path_prefix    : string;
  method_        : string option;
  host           : string option;
}

val parse_string : string -> (t, string) result
(** Parse a strict YAML/JSON artifact. Unknown fields, unsupported versions and
    unsupported contract kinds are rejected rather than ignored. *)

val read_file : string -> (t, string) result

val to_property : t -> Verify.property
(** Convert the confirmed artifact to the immutable verifier input. *)

val canonical_json : t -> string
(** Stable, normalized identity material for report provenance. Host names are
    lowercased because Kong matches them case-insensitively. *)

val report_identity : t -> Soundcheck_core.Report.frozen_spec
(** Connector-neutral provenance attached to reports produced under this
    artifact. *)

val bind_report : t -> Soundcheck_core.Report.t -> Soundcheck_core.Report.t
(** Attach this artifact's exact normalized identity to a verification report. *)
