(** Explicit offline preparation of an otherwise-supported static RBAC export.
    This does not widen the verification profile or establish completeness. *)
type t = {
  snapshot : string;
  input_sha256 : string;
  snapshot_sha256 : string;
  input_bytes : int;
  snapshot_bytes : int;
  object_count : int;
  removed_fields : string list;
}

val of_string : string -> (t, string) result
(** Accept one strict JSON v1/List, remove only validated bookkeeping and inert
    lifecycle fields, then require the unchanged snapshot reader to accept it.
    Objects, rules, references, identities, labels and annotations are retained.
    [snapshot] includes one final newline; its digest binds these exact bytes.
    Removal paths are sorted, e.g. [manifest.items[0].metadata.uid]. *)

val receipt_json : t -> string
(** Version-1 preparation receipt, without a trailing newline. It binds exact
    input/output hashes and removed field paths, never a verification verdict.
    No raw metadata values or policy contents are copied into the receipt. *)

type manifest

val of_manifest : format:Manifest_input.format -> ?namespace:string -> ?rbac_only:bool ->
  string -> (manifest, string) result
(** Explicit broader preparation: a JSON object/List or bounded UTF-8 YAML
    stream. Typed RBAC Lists infer both missing type fields together. Namespace
    context fills only absent/empty Role/RoleBinding metadata namespaces.
    Mixed bundles require [rbac_only]; every retained RBAC object is validated.
    No objects selected is an error. No rendering or cluster access occurs. *)

val manifest_snapshot : manifest -> t
val manifest_excluded_count : manifest -> int

val manifest_receipt_json : manifest -> string
(** Schema 2 binds the same exact input/output identities plus source format,
    defaulting context, source-to-output inventory, list wrappers, excluded
    objects, empty documents and every added/removed field. Schema 1 and
    [of_string] remain unchanged. *)

type fragment

val fragment_of_manifest : format:Manifest_input.format -> ?namespace:string -> ?rbac_only:bool ->
  string -> (fragment, string) result
(** Normalized, structurally validated source for explicit inventory assembly.
    References may be unresolved. This is NOT a closed [Snapshot.t] or a
    standalone prepared snapshot; the union must pass the strict snapshot reader.
    [of_manifest] and [of_string] retain their closed-inventory requirement. *)

val fragment_items : fragment -> Strict_json.value list
val fragment_source_paths : fragment -> string list
val fragment_provenance : fragment -> Strict_json.value
(** Source hash/settings, transformations and local object indices. No snapshot
    identity or verification/completeness claim is attached to a fragment. *)
