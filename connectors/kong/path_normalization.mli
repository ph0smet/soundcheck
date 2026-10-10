(** Kong's RFC 3986 request-path normalization boundary. *)

val normalize_literal : string -> string
(** Normalize a literal path using Kong's percent-decoding, dot-segment removal,
    and duplicate-slash merging behavior. *)

val migrate_legacy_path : string -> string
(** Kong 3.9.3's declarative path migration for explicit format 1.1/2.1 inputs.
    Adds regex markers only for legacy implicit syntax and preserves escaped
    metacharacters while percent-decoding. Not applied to modern/omitted format. *)

val is_normalized_literal : string -> bool
(** Whether a configured literal route/property path is absolute and already in
    the canonical form required by Kong's route schema. *)

val has_valid_percent_encoding : string -> bool
(** Whether every percent sign begins a complete hexadecimal triplet. *)

val request_path_language : Soundcheck_core.Regex.t
(** The regular language of paths Kong can present to its router after
    normalization. *)

val request_domain : Soundcheck_core.Ir.condition
(** [request_path_language] as an IR request-domain condition. *)

val is_normalized_request_path : string -> bool
(** Concrete membership check for differential and witness validation. *)
