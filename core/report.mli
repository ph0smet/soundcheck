(** A verification result, ready for presentation.

    [Report.t] is the single value every adapter (CLI, MCP tool, HTTP service,
    CI gate) renders — either as human text or as the stable, versioned JSON
    contract. Keeping both serializers here (not in an adapter) is what lets the
    MCP tool and PR-bot reuse the exact same output. *)

type counterexample = {
  principal        : string;  (** e.g. ["anonymous"] / ["authenticated"] *)
  action           : string;  (** the request method, or [""] if unconstrained *)
  path             : string;
  route            : string option;  (** connector location that SERVES the request *)
  service          : string option;
  shadowed_route   : string option;
      (** For shadowing findings: the route that was written to handle this
          request but is outranked by [route]. [None] for properties that name a
          single location. *)
  shadowed_service : string option;
  source_ip        : int32;
      (** IPv4 source address of the violating request, rendered dotted-quad in
          JSON. Meaningful only for properties that constrain it; otherwise the
          solver was free to pick any value. *)
  note             : string;  (** human-readable, connector-lifted explanation *)
}
(** A concrete violating request, lifted into the connector's vocabulary.
    [route]/[service] are populated by connectors that have that notion; core
    carries them as opaque strings and never depends on any connector. *)

type outcome =
  | Proved                     (** property holds for all requests *)
  | Violated of counterexample (** a concrete request the policy allows but the property forbids *)
  | Unknown of string          (** solver was inconclusive; string is the reason *)

type t = {
  result               : outcome;
  property_name        : string;
  property_description  : string;
}

val to_human : t -> string
(** Multi-line, human-facing rendering (the CLI's default format). *)

val schema_version : int
(** Version of the JSON contract below, emitted as ["schema_version"]. Bumped
    when the shape changes in a way a consumer must notice. *)

val to_json : t -> string
(** The stable, versioned JSON contract:
    {[ { "result": "violated|proved|unknown", "schema_version": 1,
         "property": "...",
         "counterexample": { "principal", "action", "path", "source_ip",
                             "route", "service", "shadowed_route",
                             "shadowed_service" } } ]}
    Every key is emitted unconditionally, [null] when absent, so consumers never
    probe for existence. [counterexample] is [null] for [Proved]; for [Unknown] a
    ["reason"] field carries the explanation. Emitted with a hand-rolled encoder
    (no external JSON dependency) since the schema is small and flat. *)
