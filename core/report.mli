(** A verification result, ready for presentation.

    [Report.t] is the single value every adapter (CLI, MCP tool, HTTP service,
    CI gate) renders — either as human text or as the stable, versioned JSON
    contract. Keeping both serializers here (not in an adapter) is what lets the
    MCP tool and PR-bot reuse the exact same output. *)

type counterexample = {
  principal        : string;
      (** ["anonymous"] / ["authenticated"] for HTTP, or the exact named
          identity for an object-resource connector. *)
  action           : string;
      (** Exact modeled request method. [""] is an empty value, not a wildcard. *)
  path             : string;
  route            : string option;  (** connector location that SERVES the request *)
  service          : string option;
  shadowed_route   : string option;
      (** For shadowing findings: the route that was written to handle this
          request but is outranked by [route]. [None] for properties that name a
          single location. *)
  shadowed_service : string option;
  host             : string;
      (** Request Host of the violating request. Meaningful only where the config
          constrains it; otherwise the solver picked it freely. *)
  scheme           : string;
  sni              : string;
  source_ip        : int32;
      (** IPv4 source address of the violating request, rendered dotted-quad in
          JSON. Meaningful only for properties that constrain it; otherwise the
          solver was free to pick any value. *)
  headers          : (string * string) list;
      (** Header memberships required by the symbolic counterexample. *)
  object_request   : Ir.object_request option;
      (** Exact typed resource coordinates; absent for HTTP requests. *)
  identity_groups  : string list option;
      (** Fixed connector identity context, when supplied; [None] means no group
          context is represented, not an assertion of an empty group set. *)
  granting_rules   : string list;
      (** Opaque connector rule identifiers granting this request. An empty list
          carries no claim about a composed authorization chain. *)
  note             : string;  (** human-readable, connector-lifted explanation *)
}
(** A concrete violating request, lifted into the connector's vocabulary.
    [route]/[service] are populated by connectors that have that notion; core
    carries them as opaque strings and never depends on any connector. *)

type clause_kind = Must_deny | Must_allow | Must_not_grant | Must_preserve
(** [Must_not_grant] describes absence of a grant without claiming an explicit
    target denial. [Must_preserve] identifies a decision-preservation obligation. *)

type clause = {
  name        : string;
  description : string;
  kind        : clause_kind;
}
(** The particular clause of a multi-clause contract responsible for an
    outcome. Legacy single-property reports leave this absent. *)

type frozen_spec = {
  schema_version : int;
  kind           : string;
  canonical      : string;
}
(** Identity of the human-confirmed artifact loaded outside the repair loop.
    [canonical] is connector-produced normalized content; core treats it as an
    opaque string and exposes it so a consumer can compare the exact frozen
    specification behind two verdicts. *)

type assurance_status = Within_profile | Conservative | Unsupported

type assurance_finding = {
  code    : string;
  service : string option;
  route   : string option;
  detail  : string;
}

type assurance = {
  profile  : string;
  status   : assurance_status;
  findings : assurance_finding list;
}
(** Connector-owned semantic profile identity and assessment of the parsed
    artifact. [Conservative] may over-report but must not create a false proof;
    [Unsupported] means the outcome is [Unknown]. *)

type outcome =
  | Proved                     (** property holds for all requests *)
  | Vacuous                    (** the property's forbidden request class is empty *)
  | Inconsistent of string     (** the frozen contract contradicts itself *)
  | Violated of counterexample (** a validated counterexample to the reported obligation *)
  | Unknown of string          (** solver was inconclusive; string is the reason *)

type t = {
  result               : outcome;
  property_name        : string;
  property_description  : string;
  assurance             : assurance option;
  clause               : clause option;
  frozen_spec          : frozen_spec option;
}

val to_human : t -> string
(** Multi-line, human-facing rendering (the CLI's default format). *)

val schema_version : int
(** Version of the JSON contract below, emitted as ["schema_version"]. Bumped
    when the shape changes in a way a consumer must notice. *)

val to_json : t -> string
(** The stable, versioned JSON contract:
    {[ { "result": "violated|proved|vacuous|inconsistent|unknown",
         "schema_version": 10,
         "property": "...",
         "assurance": { "profile": "...",
                         "status": "within_profile|conservative|unsupported",
                         "findings": [] },
         "frozen_spec": { "schema_version": 1, "kind": "...",
                          "canonical": "..." },
         "clause": { "name": "...", "description": "...",
                     "kind": "must_deny|must_allow|must_not_grant|must_preserve" },
         "counterexample": { "principal", "action", "path", "host", "scheme",
                             "sni", "headers",
                             "source_ip", "route", "service",
                             "shadowed_route", "shadowed_service",
                             "object_request", "identity_groups", "granting_rules" } } ]}
    Every key is emitted unconditionally, [null] when absent, so consumers never
    probe for existence. [assurance] is [null] only when connector-neutral core
    code constructs a report without a semantic profile. [clause] is [null] for a legacy single property and
    [frozen_spec] is [null] for verification not bound to an external artifact.
    An HTTP counterexample has [object_request:null], [identity_groups:null] and
    [granting_rules:[]]. Object coordinates contain [namespace], [resource_kind]
    and [name]; profile constants define any additional request dimensions.
    [counterexample] is [null] for [Proved], [Vacuous], and [Inconsistent]; for
    [Unknown] and [Inconsistent] a ["reason"] field carries the explanation.
    Emitted with a hand-rolled encoder (no external JSON dependency) since the
    schema is small and flat. *)
