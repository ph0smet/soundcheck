(** Bounded, solver-free policy containment matching Kubernetes 1.34.0
    [component-helpers/auth/rbac/validation.Covers]. This compares every
    proposed permission, including custom API groups, resources, verbs and URL
    strings. It does not project rules onto a frozen access-contract domain or
    establish request reachability, caller authentication or inventory completeness.

    Each operation rejects more than 100,000 input values (one per rule and
    string; resolver metadata and subjects also count) or 8 MiB of string bytes.
    Coverage additionally rejects more than 100,000 proposed atoms or 8 MiB of
    string bytes across the expanded atoms, including repeated field contents.
    This bounds diagnostic expansion even when the owner policy is empty.
    Comparison
    work is preflighted against 10,000,000 units: each owner rule costs 16 plus
    four times the sum of [1 + String.length value] across its fields, multiplied
    by the number of proposed atoms (one for an ordinary resource request).
    Limits fail with [Error], never an incomplete coverage result. No atoms or
    missing permissions are truncated. All input rules are checked, even when
    an earlier rule already grants access or the proposal is empty. *)

type missing = {
  proposed_rule_index : int;
  atom_index : int;
  rule : Snapshot.rule;
}
(** Both indices are zero-based; [atom_index] is local to its proposed rule.
    Atomic rules retain native order and duplicates. An unrestricted resource
    atom has an empty [resource_names] list, distinct from a singleton empty or
    wildcard-looking name. *)

type t = { covered : bool; atom_count : int; missing : missing list }

val covers : owner:Snapshot.rule list -> proposed:Snapshot.rule list -> (t, string) result
(** Mandatory rule arrays must be nonempty, as required by [Snapshot]. Literal
    empty strings remain permitted wherever the snapshot parser permits them.
    Wildcard names are literals, not unrestricted name permissions. *)

val rules_for :
  Snapshot.t -> identity:Identity.identity -> namespace:string ->
  (Snapshot.rule list, string) result
(** Resolve a fixed caller's baseline permissions as native [RulesFor] does:
    matching ClusterRoleBindings first, then matching RoleBindings in the exact
    nonempty namespace. No rules are projected by resource type or URL domain.
    The complete supplied snapshot is already structurally closed and has
    resolved aggregation. All bound rules and binding/subject strings count
    toward limits, including unmatched grants; repeated references count again.
    Caller-group scans also have a checked 10,000,000-unit budget before any
    matching: a potentially applicable subject costs 16 plus four times its
    string bytes and values, including all caller groups for a Group subject.
    No groups or identities are inferred. *)

val granting_rules :
  rules:Snapshot.rule list -> verb:string -> api_group:string -> resource:string ->
  subresource:string -> name:string -> (int list, string) result
(** Native ordinary resource-request matching, with no predefined operation
    catalogue. Returns every granting rule's zero-based index in source order.
    The caller supplies the API-server authorization attributes, including an
    empty request name when applicable. Namespace/subject resolution belongs to
    [rules_for]; this function does not infer either. *)

val allows_resource :
  rules:Snapshot.rule list -> verb:string -> api_group:string -> resource:string ->
  subresource:string -> name:string -> (bool, string) result
