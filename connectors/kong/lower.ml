(* Lower a Kong config into the shared decision IR.

   Semantics (v0): each route becomes an Allow rule guarded by its path(s),
   method(s), and — if an authentication plugin is attached to the route or its
   service — a [Requires_auth] condition. Unmatched requests fall through to the
   default [Deny]. This models "a request can reach a route iff it matches and
   satisfies that route's auth requirement". *)

open Soundcheck_core

(* Kong authentication plugins: presence means the route is not anonymous. *)
let auth_plugins =
  [ "key-auth"; "key-auth-enc"; "jwt"; "basic-auth"; "oauth2"; "hmac-auth";
    "ldap-auth"; "ldap-auth-advanced"; "openid-connect"; "mtls-auth" ]

let is_auth_plugin (name : string) = List.mem name auth_plugins

let requires_auth (service : Ast.service) (route : Ast.route) : bool =
  let has ps =
    List.exists (fun (p : Ast.plugin) -> p.enabled && is_auth_plugin p.name) ps
  in
  has route.plugins || has service.plugins

(* Kong rate-limiting / throttling plugins. *)
let rate_limit_plugins =
  [ "rate-limiting"; "rate-limiting-advanced"; "response-ratelimiting";
    "graphql-rate-limiting-advanced" ]

let is_rate_limit_plugin (name : string) = List.mem name rate_limit_plugins

let rate_limited (service : Ast.service) (route : Ast.route) : bool =
  let has ps =
    List.exists (fun (p : Ast.plugin) -> p.enabled && is_rate_limit_plugin p.name) ps
  in
  has route.plugins || has service.plugins

(* One route path as an IR condition.

   ANCHORING (established from Kong's router source, and the reason this is not a
   guess): a regex path is anchored at the START but not at the end. The
   traditional router matches with ngx.re's "a" flag (PCRE_ANCHORED), and the
   traditional_compatible translation prepends "^" with a comment saying it does
   so "to match the anchored behavior of the traditional router". So the pattern
   must match a PREFIX of the request path — hence [Star Any] appended, unless the
   author wrote a trailing [$], which pins the end.

   A literal path stays [Path_prefix]: it is provably the same language as the
   equivalent regex (z3: [str.prefixof p path] = [str.in_re path (re.++ p re.all)])
   but [str.prefixof] is the cheaper encoding, and literal paths are the common
   case by a wide margin. *)
let path_condition (p : string) : Ir.condition =
  if not (Fragment.is_regex_path p) then Ir.Path_prefix p
  else
    match Regex.parse (Fragment.pattern_of p) with
    | Error _ ->
      (* {!Fragment.check} runs before lowering and rejects these, so this is
         unreachable; fall back to the sound reading rather than raise. *)
      Ir.True
    | Ok { re; anchored_end } ->
      Ir.Path_regex (if anchored_end then re else Regex.Concat [ re; Regex.Star Regex.Any ])

(* Does a Kong path match a concrete request path? Defined via {!path_condition}
   so counterexample lifting cannot drift from the encoding: a lifter comparing
   prefixes by hand would silently fail to recognise regex routes and report a
   finding with no route attached. *)
let path_matches (kong_path : string) (concrete : string) : bool =
  Ir.matches (path_condition kong_path)
    { Ir.principal = Ir.Anonymous; action = ""; resource = concrete; context = [] }

(* Routing criteria only: which requests this route is a candidate to serve.
   Policy (auth) is deliberately NOT folded in — see {!Ir.rule}. *)
let match_condition (path : string option) (route : Ast.route) : Ir.condition =
  let path_c = match path with None -> Ir.True | Some p -> path_condition p in
  let method_c =
    match route.methods with
    | [] -> Ir.True
    | ms -> Ir.Or (List.map (fun m -> Ir.Method_is m) ms)
  in
  Ir.And [ path_c; method_c ]

let guard_condition (service : Ast.service) (route : Ast.route) : Ir.condition =
  if requires_auth service route then Ir.Requires_auth else Ir.True

(* Kong's traditional router prefers the LONGER prefix, so path length is a
   priority we can justify. Its other ranking inputs (number of match criteria,
   and regex_priority) are NOT modelled: guessing an order we do not know would be
   unsound, whereas leaving rules tied is always safe because ties degrade to a
   union. A route with no paths matches everything and is the weakest candidate. *)
let priority_of_path = function None -> 0 | Some p -> String.length p

(* REGEX PATHS GET NO PRIORITY, AND THAT IS A SOUNDNESS REQUIREMENT, not caution.
   Pattern length says nothing about how Kong ranks a regex route (real Kong uses a
   separate regex_priority field and orders regexes against prefixes by its own
   rules), so any number we invent here is a guess — and a wrong guess is unsound
   in BOTH directions:

   - too high, and the regex route suppresses others, shrinking their [sel] and
     hiding violations reachable through them;
   - too low, and higher-priority prefixes suppress the regex route, hiding
     violations reachable through it.

   Either way a false proof. The only safe assignment when the order is unknown is
   a TIE, and because selection suppresses strictly higher priorities only, tying
   everything degrades that config to the flat union — a sound over-approximation
   that can over-report but never miss. So a config containing any regex path is
   levelled: precision is lost exactly where we lack the facts to be precise. *)
let has_regex_path (cfg : Ast.config) : bool =
  List.exists
    (fun (s : Ast.service) ->
      List.exists
        (fun (r : Ast.route) -> List.exists Fragment.is_regex_path r.paths)
        s.routes)
    cfg.services

(* One IR rule per (route, path) rather than per route. A Kong route may carry
   several paths of different lengths, which would leave a single rule with no
   well-defined priority. Splitting keeps priority exact, and is behaviour-
   preserving under the current flat-OR encoder since (or (or p1 p2)) = (or p1 p2).
   Both rules keep the route's name as [id], so counterexample lifting is
   unaffected. *)
let rules_of_route ~ranked (service : Ast.service) (route : Ast.route) :
    Ir.rule list =
  let paths =
    match route.paths with [] -> [ None ] | ps -> List.map (fun p -> Some p) ps
  in
  let guard = guard_condition service route in
  let rate_limited = rate_limited service route in
  List.map
    (fun path : Ir.rule ->
      { id = route.name;
        match_ = match_condition path route;
        guard;
        priority = (if ranked then priority_of_path path else 0);
        decision = Ir.Allow;
        rate_limited })
    paths

let to_policy (cfg : Ast.config) : Ir.policy =
  let ranked = not (has_regex_path cfg) in
  let rules =
    List.concat_map
      (fun (service : Ast.service) ->
        List.concat_map (rules_of_route ~ranked service) service.routes)
      cfg.services
  in
  { rules; default = Ir.Deny }
