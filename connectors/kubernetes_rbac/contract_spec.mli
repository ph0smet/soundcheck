(** Frozen identity context, paired access requirements and approved change
    scope, loaded independently of candidate configuration.
    [Exact_namespace ""] denotes the all-namespace collection endpoint in v2+.
    For list/watch, [All_names] includes both empty effective request name and
    every valid DNS object name. Named scopes use the effective authorization
    name, not the eventual list contents. V1 is always named get. V3 also
    supports named update/patch/delete, requiring nonempty namespace and name;
    [All_names] for these verbs means all supported named requests.
    V4 retains that domain and adds sets/complements. Namespace complements
    exclude the empty namespace. Name complements include empty only explicitly;
    [Empty_name] and [include_empty=true] are permitted only for list/watch.
    V5 adds a fixed resource/API-group catalogue; Nodes use
    [Exact_namespace ""] for cluster scope for every supported verb. Other
    resources retain v4 namespace semantics. Older contracts retain their
    ConfigMap/Secret domain and implicit core group. *)
type namespace_selector =
  | Exact_namespace of string
  | Namespace_set of string list
  | Outside_namespaces of string list
type name_selector =
  | All_names
  | Names of string list
  | Empty_name
  | Other_names of { excluded:string list; include_empty:bool }
type scope = { subject:string; verb:string; namespace:namespace_selector; resource:string; names:name_selector; api_group:string }
type kind = Must_allow | Must_not_grant
type clause = { name:string; kind:kind; scope:scope }
type t
val kind : string
val of_string : string -> (t,string) result
val version : t -> int
val identities : t -> Identity.identity list
val clauses : t -> clause list
val changes : t -> scope list
val scope_condition : scope -> Soundcheck_core.Ir.condition
val approved_changes : t -> Soundcheck_core.Ir.condition

(** Human-readable meaning of an existing scope, with supplied strings quoted.
    A description does not check inhabitation or evaluate authorization. *)
val describe_scope : scope -> string

val to_contract : t -> Soundcheck_core.Contract.t
val canonical : t -> string
val frozen_spec : t -> Soundcheck_core.Report.frozen_spec
