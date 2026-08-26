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
  source    : int32;
      (** IPv4 source address of the connection. A dedicated field rather than a
          [context] binding because it is a typed symbolic dimension the encoder
          reasons about, not an opaque attribute. *)
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
  | Source_in   of Cidr.t     (** [source] falls inside the address block *)
  | Not of condition
  | And of condition list
  | Or  of condition list

type priority = {
  shape : int;
      (** Rules of different shape are INCOMPARABLE — no order is claimed between
          them at all. Use it for target distinctions whose relative ranking is
          genuinely unknown (e.g. Kong orders routes into categories by which
          criteria they use, and that category order is not modelled). *)
  tier  : int;  (** higher wins, within one shape *)
  rank  : int;  (** higher wins, within one tier *)
}

val outranks : priority -> priority -> bool
(** Strictly outranks: same shape, and lexicographically greater on (tier, rank).
    False for equal or incomparable priorities, which is what makes an unknown
    order degrade to a union rather than a guess. *)

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
  priority     : priority;
      (** Which rule wins when several match. The encoder suppresses only rules
          that STRICTLY {!outranks} another, so anything the connector cannot
          order — equal or incomparable — stays simultaneously selectable and the
          encoding degrades to a sound union. Connectors must order two rules only
          where the target's own ordering is known, and leave them unordered
          otherwise: a wrong order is unsound in both directions, since ranking a
          rule too high hides violations behind it and too low hides violations
          through it. *)
  decision      : decision;    (** effect produced when it applies *)
  rate_limited  : bool;
      (** metadata (not a reachability guard): a rate-limiting / throttling plugin
          is attached to this rule's route or its service. Consumed by structural
          properties like rate-limit-on-public; ignored by {!evaluate}. *)
  targets_admin : bool;
      (** metadata: this rule's route proxies to the target's administrative API.
          Consumed by admin-api-not-reachable; ignored by {!evaluate}.

          Two such booleans is the point at which a third should instead become a
          general label set on the rule — noted here so the next connector does
          not simply add a fourth. *)
}

type policy = {
  rules   : rule list;
  default : decision;         (** decision when no rule applies *)
}

val matches : condition -> request -> bool
(** Concrete semantics of a condition against a concrete request. *)

val selected : policy -> request -> rule -> bool
(** Whether [rule] is the one that SERVES [request]: its routing criteria match
    and no rule that {!outranks} it does. Rules whose order is unknown — equal or
    incomparable — are all selectable. *)

val evaluate : policy -> request -> decision
(** Reference (ground-truth) decision function. A rule counts when it both
    {!selected} the request and permits it (its guard holds); those are then
    combined {b deny-overrides}: [Deny] if any is [Deny]; else [Allow] if any is
    [Allow]; else [default]. Kept in step with {!Smt_encode.allowed_formula} —
    the two are the same semantics, one concrete and one symbolic. *)

val string_of_decision : decision -> string
val string_of_principal : principal -> string
