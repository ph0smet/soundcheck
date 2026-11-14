(** Explicit offline selection from pinned Kubernetes bootstrap policy packs.
    No role references are inspected, no bindings or identities are synthesized,
    and installed state/completeness are never inferred. *)
type t = { snapshot : string; receipt : string; object_count : int }

val available_packs : string list
val kubernetes_version : string
val prepare : kubernetes_version:string -> packs:string list -> (t,string) result
(** A nonempty, duplicate-free explicit selection is required. The only supported
    version is [1.34.0] with the documented upstream default feature gates.
    Pack [view] includes its declared bootstrap aggregation contributor. The
    snapshot includes its final newline; the receipt binds those exact bytes.
    Assemble this reference assumption with actual sources using [Inventory]. *)
