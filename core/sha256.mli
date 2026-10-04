(** SHA-256 digests, rendered as 64 lowercase hexadecimal characters. *)

val string : string -> string
(** Hash the exact bytes, without text or newline normalization. *)

val file : string -> (string, string) result
(** Hash a binary file, or report its read error. *)
