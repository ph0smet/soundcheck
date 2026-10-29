(** A versioned, human-confirmed Kong contract artifact.

    The artifact is parsed before a repair loop starts and converted once into
    the verifier's typed property. Keeping this format target-specific avoids
    pretending the current Kong-derived request vocabulary is already a
    universal specification language. *)

type source_ip_integrity = Externally_enforced
(** Acknowledges that the deployment is responsible for ensuring Kong's derived
    client IP cannot be spoofed. Soundcheck verifies decisions over that value;
    it does not inspect trusted-proxy or real-IP deployment settings. *)

type kind =
  | Authenticated_access
  | Network_restricted_access of {
      trusted_cidr        : Soundcheck_core.Cidr.t;
      source_ip_integrity : source_ip_integrity;
    }
  | Protected_prefix_with_public_exceptions of { public_path_prefixes : string list }
      (** Nonempty normalized literal prefixes strictly inside [path_prefix].
          The artifact reader rejects duplicates and sorts prefixes canonically. *)

type t = {
  schema_version : int;
  kind           : kind;
  path_prefix    : string;
  method_        : string option;
  host           : string option;
}

val kind_name : kind -> string

val parse_string : string -> (t, string) result
(** Parse a strict YAML/JSON artifact. Unknown fields, unsupported versions and
    unsupported contract kinds are rejected rather than ignored. *)

val read_file : string -> (t, string) result

val to_property : t -> Verify.property
(** Convert the confirmed artifact to the immutable verifier input. *)

val scope_condition : t -> Soundcheck_core.Ir.condition
(** The outer endpoint scope controlled by the human-confirmed artifact: path
    prefix plus optional method and host. Principal, source-IP, and other clause
    constraints deliberately do not narrow the repair boundary. *)

val canonical_json : t -> string
(** Stable, normalized identity material for report provenance. Host names are
    lowercased because Kong matches them case-insensitively. *)

val report_identity : t -> Soundcheck_core.Report.frozen_spec
(** Connector-neutral provenance attached to reports produced under this
    artifact. *)

val bind_report : t -> Soundcheck_core.Report.t -> Soundcheck_core.Report.t
(** Attach this artifact's exact normalized identity to a verification report. *)
