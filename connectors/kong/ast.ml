(* Minimal Kong (decK) declarative-config AST for v0.
   We model only what the v0 properties need: services, their routes, and the
   plugins attached at either level (to detect authentication). *)

type plugin = { name : string }

type route = {
  name    : string;
  paths   : string list;
  methods : string list;   (* empty = any method *)
  plugins : plugin list;   (* route-level plugins *)
}

type service = {
  name    : string;
  routes  : route list;
  plugins : plugin list;   (* service-level plugins (apply to all its routes) *)
}

type config = { services : service list }
