(** Soundcheck decision IR (v0).

    Every Shape-B policy target (Kong, K8s RBAC, ...) lowers into this shared
    decision model: a policy is a function from a symbolic {!request} to a
    {!decision} (Allow/Deny). Connectors translate their config into a
    {!policy}; the SMT encoder reasons over it; counterexamples are lifted back
    to the connector's own vocabulary.

    v0 is deliberately minimal and extracted from the Kong use case. Per the
    project discipline it will be *refined*, not rewritten, when connector #2
    (tenant isolation) lands. *)

type principal =
  | Anonymous                 (** no authenticated identity *)
  | Authenticated of string   (** an identified consumer / subject *)

type action = string          (** e.g. HTTP method: "GET", "POST" *)

type resource = string        (** e.g. a request path: "/admin/config" *)

type context = (string * string) list
(** free-form attribute bindings for conditions (reserved for ABAC-style
    predicates; unused by the v0 encoder). *)

type request = {
  principal : principal;
  action    : action;
  resource  : resource;
  context   : context;
}

(** The effect of a policy decision. ([effect] itself is a reserved keyword in
    OCaml 5.x, hence [decision].) *)
type decision = Allow | Deny

(** A predicate over requests. The v0 encoder supports exactly these forms. *)
type condition =
  | True
  | Path_prefix of string     (** [resource] starts with the given prefix *)
  | Path_exact  of string
  | Method_is   of string
  | Is_anonymous              (** [principal] = [Anonymous] *)
  | Requires_auth             (** [principal] is [Authenticated _] *)
  | Not of condition
  | And of condition list
  | Or  of condition list

type rule = {
  id           : string;      (** connector-facing identifier (e.g. route name) *)
  match_       : condition;
      (** ROUTING only: which requests this rule is a candidate to serve (path,
          method). Deliberately separate from {!guard}, because a real gateway
          picks the serving route from routing criteria ALONE and only then
          applies policy. Folding policy in here would let a request that fails
          authentication "fall through" to a more permissive rule, which no
          gateway does: it routes first, then returns 401. *)
  guard        : condition;
      (** POLICY applied once this rule serves the request (e.g. Requires_auth).
          Failing the guard denies the request; it does not re-route it. *)
  priority     : int;
      (** Higher wins when several rules match. EQUAL priority means "order
          unknown", not "same rank": the encoder only suppresses STRICTLY
          higher-priority rules, so tied rules stay simultaneously selectable and
          the encoding degrades to a sound union over the tied set. Connectors
          must therefore assign distinct priorities only where the target's
          ordering is actually known, and tie otherwise. *)
  decision     : decision;     (** effect produced when it applies *)
  rate_limited : bool;
      (** metadata (not a reachability guard): a rate-limiting / throttling plugin
          is attached to this rule's route or its service. Consumed by structural
          properties like rate-limit-on-public; ignored by {!evaluate}. *)
}

val applies_when : rule -> condition
(** [match_ ∧ guard]: the condition under which a rule both serves a request and
    permits it. This is the flat, order-insensitive reading of a rule; it ignores
    priority and so does not model winner-takes-all selection. *)

type policy = {
  rules   : rule list;
  default : decision;         (** decision when no rule applies *)
}

val matches : condition -> request -> bool
(** Concrete semantics of a condition against a concrete request. *)

val evaluate : policy -> request -> decision
(** Reference (ground-truth) decision function, using a {b deny-overrides}
    combining rule: [Deny] if any matching rule is [Deny]; else [Allow] if any
    matching rule is [Allow]; else [default]. Used for tests and to validate
    SMT counterexamples against the concrete semantics. *)

val string_of_decision : decision -> string
val string_of_principal : principal -> string
