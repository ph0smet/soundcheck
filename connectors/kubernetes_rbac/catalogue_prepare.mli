type t = { catalogue : string; receipt : string; object_count : int; excluded_count : int }

(** Extract reviewed API metadata from local apiextensions.k8s.io/v1 CRDs.
    Mixed manifests require [crd_only]. Conflicting served-version subresources
    reject; no candidate RBAC, cluster, schema validation or intent inference. *)
val run : ?crd_only:bool -> format:Manifest_input.format -> string -> (t,string) result
