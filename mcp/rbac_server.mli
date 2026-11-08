(** Frozen RBAC tools over bounded JSON-RPC stdio. No tool argument can change
    the contract, identity context, baseline, solver or filesystem destinations. *)
type t

val create : contract:Soundcheck_kubernetes_rbac.Contract_spec.t ->
  ?baseline:string -> unit -> (t, string) result
(** Capture immutable startup inputs. A supplied baseline must be a supported
    snapshot, but need not satisfy the contract (it may be the policy to repair). *)

val max_message_bytes : int
val handle_line : t -> string -> string option
(** Strict JSON messages; initialization is required before tool requests.
    Notifications produce no response and never invoke verification. *)

val run : t -> unit
(** Newline-delimited stdio. Oversized frames are drained with bounded storage
    before emitting a parse error. EOF closes the server without extra output. *)
