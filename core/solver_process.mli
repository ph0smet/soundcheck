(** Internal, bounded capture of one directly launched POSIX subprocess. *)

val diagnostic : string -> string
(** UTF-8 diagnostic excerpt of at most 2048 source bytes (plus a truncation
    marker). Valid Unicode is preserved without splitting scalars; invalid
    bytes are shown as ASCII hex escapes. Not for protocol/model values. *)

val deadline : float -> (float, string) result
val run : deadline:float -> string -> string list -> (string, string) result
(** Successful stdout is returned unchanged; error diagnostics are UTF-8. *)
