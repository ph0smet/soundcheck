(** Internal framing for one SMT query and its conditional model observation. *)

type sexp = Atom of string | String of string | List of sexp list
exception Invalid of string

type query = { check : string; observation : string option; fields : string list }

val encode_string : string -> string
(** Encode one byte-oriented request string as an ASCII SMT-LIB literal.
    Quotes are doubled; backslashes and nonprintable bytes use Unicode escapes
    so neither literal escape-looking text nor UTF-8 bytes are reinterpreted. *)

val decode_string : string -> string
(** Decode a lexically unquoted model string (quotes already undoubled).
    SMT codepoints 0..255 represent bytes in the current request model.
    Larger codepoints or a result that is not UTF-8 raise [Invalid]; no
    Unicode scalar-to-UTF-8 transcoding or recursive unescaping is performed. *)

val query : string -> query
val status : string -> [ `Sat | `Unsat | `Unknown ]
val response :
  string list -> string ->
  [ `Unsat | `Unknown | `Sat of (string * sexp) list ]
