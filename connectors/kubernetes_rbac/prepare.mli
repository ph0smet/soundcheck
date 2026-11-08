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
