(** Explicit offline union of pinned local sources. No role, binding, identity,
    group or completeness claim is synthesized. Source versions are declarations. *)
type t = { snapshot : string; object_count : int; receipt : string }
val assemble : load:(string -> string) -> string -> (t, string) result
(** Read and hash each source once through [load], normalize it as a fragment,
    reject duplicate identities, then require closure of the complete union.
    The caller owns path resolution and I/O. Schema-1 inventory receipts bind
    the exact plan, ordered source bytes/settings/origins and final snapshot.
    Legacy single-input preparation receipts are not reused for partial inputs. *)
