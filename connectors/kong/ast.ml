(* Minimal Kong (decK) declarative-config AST for v0.
   We model only what the v0 properties need: services, their routes, and the
   plugins attached at either level (to detect authentication). *)

(* [enabled] mirrors Kong's own field, which defaults to true when omitted. A
   plugin with [enabled = false] is configured but NOT enforced by Kong, so it
   must not count as authentication (or as a rate limit) during lowering. *)
type plugin = {
  name    : string;
  enabled : bool;
  allow   : string list;
      (* ip-restriction's config.allow — IPs or CIDRs. A whitelist: when present,
         anything not listed is refused. Empty for other plugins. *)
  deny    : string list;
      (* ip-restriction's config.deny — checked BEFORE allow, so a listed address
         is refused outright. Empty for other plugins. *)
}

type route = {
  name           : string;
  paths          : string list;
  methods        : string list;   (* empty = any method *)
  plugins        : plugin list;   (* route-level plugins *)
  hosts          : string list;   (* NOT modelled — see Lower.unmodelled_match *)
  snis           : string list;   (* NOT modelled *)
  has_headers    : bool;          (* NOT modelled *)
  regex_priority : int;
      (* Kong's declared tiebreak between REGEX routes (schema default 0); it is
         not consulted for plain-prefix routes. Reading the number the config
         states beats inferring one. *)
}

type service = {
  name    : string;
  url     : string;        (* upstream the service proxies to *)
  routes  : route list;
  plugins : plugin list;   (* service-level plugins (apply to all its routes) *)
}

type config = { services : service list }
