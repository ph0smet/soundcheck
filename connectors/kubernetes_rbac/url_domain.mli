(** Canonical non-resource authorization paths, classified using pinned
    Kubernetes api/apis prefixes. Does not establish endpoint availability. *)
type selector = Exact of string | Prefix of string
val methods : string list
val path_condition : Soundcheck_core.Ir.condition
val condition : Soundcheck_core.Ir.condition
val canonical_path : string -> bool
val valid_path : string -> bool
val parse : string -> Strict_json.value -> selector
val selector_condition : selector -> Soundcheck_core.Ir.condition
val rule_condition : string -> Soundcheck_core.Ir.condition
val json : selector -> Strict_json.value
val describe : selector -> string
