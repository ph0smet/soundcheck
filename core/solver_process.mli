(** Internal, bounded capture of one directly launched POSIX subprocess. *)

val deadline : float -> (float, string) result
val run : deadline:float -> string -> string list -> (string, string) result
