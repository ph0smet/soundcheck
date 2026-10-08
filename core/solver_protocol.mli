(** Internal framing for one SMT query and its conditional model observation. *)

type sexp = Atom of string | String of string | List of sexp list
exception Invalid of string

type query = { check : string; observation : string option; fields : string list }

val query : string -> query
val status : string -> [ `Sat | `Unsat | `Unknown ]
val response :
  string list -> string ->
  [ `Unsat | `Unknown | `Sat of (string * sexp) list ]
