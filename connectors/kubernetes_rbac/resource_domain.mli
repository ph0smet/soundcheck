(** The resource catalogue is part of each frozen contract version's meaning,
    including preservation outside clauses. Never expand an existing catalogue
    without an explicit contract-version opt-in. *)
type t = private { api_group : string; resource : string; namespaced : bool; subresource : string }
val for_version : int -> t list
val find : version:int -> api_group:string -> resource:string -> t option
val find_subresource : version:int -> api_group:string -> resource:string -> subresource:string -> t option
val combined_resource : t -> string

(** Injective, connector-defined IR/report discriminator. Core resources retain
    their plural; subresources use resource/subresource, and noncore entries
    append .group (for example deployments/scale.apps).
    Decode only through this finite catalogue, never by splitting arbitrary
    dotted strings. Contracts and evaluation inputs use separate raw fields. *)
val kind : t -> string
val of_kind : version:int -> string -> t option
val description : t -> string

(** Per-entry native initial verbs. Never includes synthetic operation IDs. *)
val verbs : version:int -> t -> string list

(** Contract operation catalogue, including the two conditional SSA branches
    for base resources in schema 8. *)
val operations : version:int -> t -> string list

(** Native RBAC prerequisites at the same request coordinates. Callers first
    check membership in the operation catalogue. State denotes a hypothetical
    storage branch; it is not an observation of live object existence. *)
val checks : operation:string -> string list
val object_state : operation:string -> string option

(** Authorization attribute domains: named, empty, or empty-or-named. *)
val name_domain : t -> verb:string -> string
val namespace_domain : t -> verb:string -> string
