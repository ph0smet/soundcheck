(** A complete static desired RBAC snapshot in one strict JSON Kubernetes List.
    Unsupported fields, invalid accepted fields, duplicate identities and
    unresolved role references fail closed. No live cluster is consulted. *)
type rule = {
  verbs : string list;
  api_groups : string list;
  resources : string list;
  resource_names : string list;
}
type subject = User of string | Group of string | Service_account of string * string
type role_ref = Local_role of string | Cluster_role of string
type binding = {
  binding_kind : string;
  binding_namespace : string;
  binding_name : string;
  subjects : subject list;
  role_ref : role_ref;
}
type bound_grant = { binding : binding; bound_rules : rule list }
type t
type missing_reference = { binding_index : int; binding_label : string; role_label : string }

val unresolved_references : string -> (missing_reference list, string) result
(** Validate the entire strict inventory, including unsupported rules and duplicate
    identities, then enumerate every missing reference. This does not construct
    a verified/closed [t]; [of_string] continues to reject missing roles. *)

val of_string : string -> (t, string) result
val grants : t -> bound_grant list
val binding_label : binding -> string
val role_label : binding -> string
val subject_matches : Identity.identity -> subject -> bool
