(** Strict Kubernetes v1.34 label selectors. Validation and matching are separate
    from policy resolution; an empty selector matches every label map. *)
type t
val parse : string -> Strict_json.value -> t

val cost : t -> int
(** One unit per selector, label pair, expression and expression value. *)

val matches : t -> (string -> string option) -> bool
