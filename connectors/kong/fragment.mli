(** Decidability boundary: reject Kong configs the encoder cannot model soundly.

    Regex support is the bounded common language accepted by
    {!Regex_boundary.parse}, not every regular expression. Unmodeled plugins,
    unresolved nested/consumer relationships, and non-string foreign keys also
    fail closed. Such a config reports [unknown] rather than being approximated. *)

type finding = {
  service : string;
  route   : string;
  path    : string;
  why     : string;  (** which construct put it out of scope *)
}

val is_regex_path : string -> bool
(** Whether an already migrated path has the explicit Kong 3.x ['~'] marker.
    {!Parse} performs the version-specific 1.1/2.1 migration first. *)

val pattern_of : string -> string
(** The path with Kong's leading ['~'] marker removed. *)

val findings : Ast.config -> finding list
(** Every path outside the supported fragment, in service-then-route order. *)

val check : Ast.config -> (unit, string) result
(** [Ok ()] if the whole config is inside the supported fragment, otherwise
    [Error reason] naming top-level routing, the first unsupported plugin scope,
    or every offending regex route. *)
