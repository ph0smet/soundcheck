(** A complete static desired RBAC snapshot in one strict JSON Kubernetes List.
    Unsupported fields, invalid accepted fields, duplicate identities and
    unresolved role references fail closed. Aggregate roles must have acyclic
    dependencies and stored full rules equal to their recursively selected rules.
    No live cluster is consulted or reconciliation performed. *)
type resource_rule = {
  verbs : string list;
  api_groups : string list;
  resources : string list;
  resource_names : string list;
}
type nonresource_rule = { verbs : string list; urls : string list }
type rule = Resource of resource_rule | Non_resource of nonresource_rule
(** Native rule domains remain distinct. URL rules are valid only on ClusterRole
    and cannot contain nonempty resource fields. Both variants retain their
    original rule-array positions; URL authorization requires schema 9. *)
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
type rule_source = { role_label : string; item_index : int; rule_index : int;
  bound : bool; rule : rule }

val unresolved_references : string -> (missing_reference list, string) result
(** Validate object structure, including unsupported rules and duplicate identities,
    then enumerate every missing reference. Fragment sources may omit contributors;
    this does not check aggregation consistency or construct a closed [t].
    [of_string] checks the complete assembled inventory. *)

val of_string : string -> (t, string) result

val rule_inventory : string -> (rule_source list, string) result
(** Validate the complete snapshot and retain every original rule, including
    unbound roles. [bound] means referenced by a binding, not an effective grant
    to any frozen identity. *)

val grants : t -> bound_grant list
val binding_label : binding -> string
val role_label : binding -> string
val subject_matches : Identity.identity -> subject -> bool

type object_spec = Role_spec of rule list | Binding_spec of binding
type object_view = {
  object_kind : string; object_namespace : string; object_name : string;
  object_spec : object_spec; aggregated : bool; canonical_object : string;
}
val object_views : string -> (object_view list, string) result
(** Validate a complete snapshot and retain each object for a single-operation
    check. Canonical object JSON sorts map keys recursively, retaining all arrays
    and accepted metadata. Typed specs retain rule/subject order and duplicates;
    they must not be compared as permission sets to infer a native no-op. *)
