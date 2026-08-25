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
  | Path_regex  of Regex.t
      (** [resource] belongs to the language, in full. A connector whose target
          matches a regex against a {e prefix} of the path expresses that by
          appending [Regex.Star Regex.Any] itself, keeping the anchoring
          convention in the connector where it belongs. Note [Path_prefix p] is
          the special case [Path_regex (Concat [Lit p; Star Any])] — proven
          equivalent, but kept separate because [str.prefixof] is the cheaper
          encoding for the common literal case. *)
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

type policy = {
  rules   : rule list;
  default : decision;         (** decision when no rule applies *)
}

val matches : condition -> request -> bool
(** Concrete semantics of a condition against a concrete request. *)

val selected : policy -> request -> rule -> bool
(** Whether [rule] is the one that SERVES [request]: its routing criteria match
    and no strictly higher-priority rule's do. Rules of equal priority are all
    selectable, since equal priority encodes "order unknown". *)

val evaluate : policy -> request -> decision
(** Reference (ground-truth) decision function. A rule counts when it both
    {!selected} the request and permits it (its guard holds); those are then
    combined {b deny-overrides}: [Deny] if any is [Deny]; else [Allow] if any is
    [Allow]; else [default]. Kept in step with {!Smt_encode.allowed_formula} —
    the two are the same semantics, one concrete and one symbolic. *)

val string_of_decision : decision -> string
val string_of_principal : principal -> string
