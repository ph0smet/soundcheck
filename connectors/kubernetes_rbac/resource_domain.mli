(** The resource catalogue is part of each frozen contract version's meaning,
    including preservation outside clauses. Never expand an existing catalogue
    without an explicit contract-version opt-in. *)
type t = private { api_group : string; resource : string; namespaced : bool }
val for_version : int -> t list
val find : version:int -> api_group:string -> resource:string -> t option

(** Injective, connector-defined IR/report discriminator. Core resources retain
    their plural; noncore resources use Kubernetes' resource.group notation.
    Decode only through this finite catalogue, never by splitting arbitrary
    dotted strings. Contracts and evaluation inputs use separate raw fields. *)
val kind : t -> string
val of_kind : version:int -> string -> t option
val description : t -> string
