(** Independently reviewed, frozen API metadata. It is never inferred from
    candidate grants. Only initial authorization attributes are modeled. *)
type t
val parse : string -> Strict_json.value -> t
val of_string : string -> (t,string) result
val resources : t -> Resource_domain.t list
val json : t -> Strict_json.value
