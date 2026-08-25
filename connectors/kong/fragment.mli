(** Decidability boundary: reject Kong configs the encoder cannot model soundly.

    Literal-prefix and regex paths are both modelled, so what remains outside the
    fragment is exactly what {!Regex.parse} refuses — constructs that are not
    regular, or whose language we decline to guess. Such a config reports
    [unknown] rather than being approximated. *)

type finding = {
  service : string;
  route   : string;
  path    : string;
  why     : string;  (** which construct put it out of scope *)
}

val is_regex_path : string -> bool
(** Whether Kong would compile this path as a regex: a leading ['~'] (Kong 3.x) or,
    for pre-3.0 configs where the marker was implicit, any character outside
    Kong's plain-path set. *)

val pattern_of : string -> string
(** The path with Kong's leading ['~'] marker removed, ready for {!Regex.parse}. *)

val findings : Ast.config -> finding list
(** Every path outside the supported fragment, in service-then-route order. *)

val check : Ast.config -> (unit, string) result
(** [Ok ()] if the whole config is inside the supported fragment, otherwise
    [Error reason] naming each offending route and the construct responsible. *)
