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
  id       : string;          (** connector-facing identifier (e.g. route name) *)
  when_    : condition;       (** the rule applies to requests matching this *)
  decision : decision;        (** effect produced when it applies *)
}

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
