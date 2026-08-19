(** Decidability boundary: reject Kong configs the encoder cannot model soundly.

    Paths are encoded as literal prefixes, so a regex path is outside the
    supported fragment. Rather than under-approximate it (which can yield a false
    proof) the whole config is refused and the verification reports [unknown]. *)

type finding = {
  service : string;
  route   : string;
  path    : string;
}
(** A route path that falls outside the supported fragment. *)

val is_regex_path : string -> bool
(** Whether Kong would compile this path as a regex: a leading ['~'] (Kong 3.x)
    or, for pre-3.0 configs where the marker was implicit, any character outside
    Kong's plain-path set. Errs toward [true], since a spurious [unknown] is
    recoverable and a missed regex is not. *)

val findings : Ast.config -> finding list
(** Every unsupported path in the config, in service-then-route order. *)

val check : Ast.config -> (unit, string) result
(** [Ok ()] if the whole config is inside the supported fragment, otherwise
    [Error reason] naming each offending route. *)
