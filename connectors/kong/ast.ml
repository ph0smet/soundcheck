(* Minimal Kong (decK) declarative-config AST for v0.
   We model only what the v0 properties need: services, their routes, and the
   plugins attached at either level (to detect authentication). *)

(* [enabled] mirrors Kong's own field, which defaults to true when omitted. A
   plugin with [enabled = false] is configured but NOT enforced by Kong, so it
   must not count as authentication (or as a rate limit) during lowering. *)
type plugin = {
  name    : string;
  enabled : bool;
  protocols : string list;
      (* Entity activation is by Kong subsystem, not exact request scheme. *)
  has_relationships : bool;
      (* Explicit relationships on a nested plugin need separate resolution. *)
  allow   : string list;
      (* ip-restriction's config.allow — IPs or CIDRs. A whitelist: when present,
         anything not listed is refused. Empty for other plugins. *)
  deny    : string list;
      (* ip-restriction's config.deny — checked BEFORE allow, so a listed address
         is refused outright. Empty for other plugins. *)
  trigger : string option;
      (* request-termination's optional header/query trigger. When present the
         plugin is conditional rather than an unconditional denial. *)
  anonymous_fallback : bool;
      (* Authentication plugin [config.anonymous]. Failed authentication is
         proxied as that Consumer rather than rejected. *)
  run_on_preflight : bool;
      (* Key Auth/JWT default this to true. When false, OPTIONS requests bypass
         that plugin's authentication check. *)
}

type route = {
  name           : string;
  paths          : string list;
  methods        : string list;   (* empty = any method *)
  protocols      : string list;   (* schema default: [http; https] *)
  plugins        : plugin list;   (* route-level plugins *)
  hosts          : string list;   (* lowercase exact/wildcard hosts are modeled *)
  hosts_present  : bool;          (* an empty hosts table still affects priority *)
  snis           : string list;
  headers        : (string * string list) list;
      (* Header names and values as authored. Exact values are modeled
         case-insensitively; a sole value beginning [~*] is Kong regex syntax. *)
  has_sources_or_destinations : bool;
      (* stream (TCP/TLS) routing criteria — NOT modelled, and they also count
         toward Kong's category match_weight, so a route carrying them cannot be
         ranked either *)
  regex_priority : int;
      (* Kong's declared tiebreak between REGEX routes (schema default 0); it is
         not consulted for plain-prefix routes. Reading the number the config
         states beats inferring one. *)
  strip_path     : bool;
  path_handling  : string;
}

type service = {
  name    : string;
  enabled : bool;          (* disabled services' routes are absent from router *)
  url     : string option; (* Kong shorthand for the upstream target *)
  protocol : string option;
  host     : string option;
  port     : int option;
  path     : string option;
  routes  : route list;
  plugins : plugin list;   (* service-level plugins (apply to all its routes) *)
}

type scoped_plugin = {
  plugin                : plugin;
  service               : string option;
  route                 : string option;
  consumer_scoped       : bool;
  unsupported_reference : bool;
}

type top_level_route = {
  route                 : route;
  service               : string option;
  unsupported_reference : bool;
}

type config = {
  services       : service list;
  global_plugins : plugin list;
      (* Root-level plugins with no route/service/consumer relationship. *)
  scoped_plugins : scoped_plugin list;
      (* Root-level plugins carrying explicit foreign-key relationships. String
         route/service names are modeled; consumer and non-string references
         remain outside the current identity model. *)
  top_level_routes : top_level_route list;
      (* Routes authored at the document root. String service references are
         also inserted into the matching service's [routes]; a missing service
         becomes a denying route, while non-string references are unsupported. *)
}
