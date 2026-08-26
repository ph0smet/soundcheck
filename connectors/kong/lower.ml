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
    { Ir.principal = Ir.Anonymous; action = ""; resource = concrete;
      context = []; source = 0l }

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

(* Kong's Admin API listens on 8001 (http) and 8444 (https) by default. A service
   whose upstream is that port is proxying the Admin API through the public proxy
   — the classic Kong footgun this property exists to catch.

   Port-based recognition is a known-name lookup in the same spirit as the plugin
   lists, and errs the same way: an unusual admin port is NOT recognised, so such
   a route is treated as ordinary and the property stays quiet about it. That is
   the false-negative direction for THIS property, which is why the port list is
   documented rather than buried. *)
let admin_ports = [ "8001"; "8444" ]

let targets_admin_api (service : Ast.service) : bool =
  let url = service.url in
  (* take the ":port" that follows the host, before any path *)
  let after_scheme =
    match String.index_opt url ':' with
    | Some i when i + 3 <= String.length url && String.sub url i 3 = "://" ->
      String.sub url (i + 3) (String.length url - i - 3)
    | _ -> url
  in
  let authority =
    match String.index_opt after_scheme '/' with
    | Some i -> String.sub after_scheme 0 i
    | None -> after_scheme
  in
  match String.rindex_opt authority ':' with
  | None -> false
  | Some i ->
    let port = String.sub authority (i + 1) (String.length authority - i - 1) in
    List.mem port admin_ports

(* ip-restriction as a policy guard: it runs after routing, so it constrains who
   may be served, not which route serves.

   Kong checks DENY FIRST (a listed address is refused outright), then treats
   ALLOW as a whitelist (when non-empty, anything unlisted is refused). An address
   that fails to parse — IPv6, or malformed — is dropped from the condition, which
   WEAKENS the guard and therefore over-reports rather than proving too much. *)
let cidrs_of (entries : string list) : Ir.condition list =
  List.filter_map
    (fun e -> match Cidr.parse e with Ok c -> Some (Ir.Source_in c) | Error _ -> None)
    entries

let ip_restriction_condition (service : Ast.service) (route : Ast.route) :
    Ir.condition =
  let plugins =
    List.filter
      (fun (p : Ast.plugin) -> p.enabled && p.name = "ip-restriction")
      (route.plugins @ service.plugins)
  in
  let conds =
    List.concat_map
      (fun (p : Ast.plugin) ->
        let denied = cidrs_of p.deny in
        let allowed = cidrs_of p.allow in
        (if denied = [] then [] else [ Ir.Not (Ir.Or denied) ])
        @ if allowed = [] then [] else [ Ir.Or allowed ])
      plugins
  in
  match conds with [] -> Ir.True | cs -> Ir.And cs

let guard_condition (service : Ast.service) (route : Ast.route) : Ir.condition =
  let auth = if requires_auth service route then Ir.Requires_auth else Ir.True in
  match
    List.filter (fun c -> c <> Ir.True) [ auth; ip_restriction_condition service route ]
  with
  | [] -> Ir.True
  | [ c ] -> c
  | cs -> Ir.And cs

(* Route ranking, read off Kong's own comparator (kong/router/traditional.lua
   [sort_routes]) rather than guessed:

     submatch_weight DESC  >  header count DESC  >  regex_priority DESC
       >  max_uri_length DESC  >  created_at ASC

   and [MATCH_SUBRULES] has only three flags — HAS_REGEX_URI, PLAIN_HOSTS_ONLY,
   HAS_WILDCARD_HOST_PORT. Two concern hosts, which we do not model; the third
   means a REGEX PATH RAISES submatch_weight. Since that term is compared first,
   a regex route outranks every plain-prefix route no matter how long the prefix
   is — surprising, but it is what the source says. Methods contribute nothing to
   submatch_weight, so they cannot disturb prefix ordering.

   Hence [tier]: regex routes sit above prefix routes. Within regex routes the
   declared [regex_priority] is the rank (Kong consults it only for regex routes).
   Within prefix routes the rank is path length, which is [max_uri_length].

   [shape] carries what we still cannot order. Kong groups routes into CATEGORIES
   by which criteria they use and iterates categories in an order we have not
   modelled, so a route constraining methods and one not constraining them are
   left incomparable rather than ranked against each other. Equal regex_priority
   also leaves two regex routes tied, since the next tiebreak (max_uri_length over
   a pattern) is not something we can justify. *)
(* Routing criteria Kong matches on that we do NOT model: hosts, SNIs, headers.
   Ignoring them makes [match_] an OVER-approximation, which is safe where it
   appears positively but NOT where it appears negated, in the suppression term
   of {!Ir.selected}. Over-approximating a suppressor's match shrinks everything
   below it and can hide a violation — a false proof, demonstrated on a config
   where a host-scoped guarded route suppressed an open one.

   So a rule carrying an unmodelled routing constraint is given a UNIQUE shape,
   making it incomparable with every other rule: it neither suppresses nor is
   suppressed, and the encoding degrades to the sound union around it. Precision
   is lost exactly where the config says something we cannot read. *)
let unmodelled_match (route : Ast.route) : bool =
  route.hosts <> [] || route.snis <> [] || route.has_headers

let priority_of ~(regex_priority : int) ~(index : int) (route : Ast.route)
    (path : string option) : Ir.priority =
  let shape =
    if unmodelled_match route then -(index + 1)
    else if route.methods = [] then 0
    else 1
  in
  match path with
  | None -> { Ir.shape; tier = 0; rank = 0 }
  | Some p when Fragment.is_regex_path p ->
    { Ir.shape; tier = 1; rank = regex_priority }
  | Some p -> { Ir.shape; tier = 0; rank = String.length p }

(* One IR rule per (route, path) rather than per route. A Kong route may carry
   several paths of different lengths, which would leave a single rule with no
   well-defined priority. Splitting keeps priority exact, and is behaviour-
   preserving under the current flat-OR encoder since (or (or p1 p2)) = (or p1 p2).
   Both rules keep the route's name as [id], so counterexample lifting is
   unaffected. *)
let rules_of_route ~(index : int) (service : Ast.service) (route : Ast.route) :
    Ir.rule list =
  let paths =
    match route.paths with [] -> [ None ] | ps -> List.map (fun p -> Some p) ps
  in
  let guard = guard_condition service route in
  let rate_limited = rate_limited service route in
  let targets_admin = targets_admin_api service in
  List.map
    (fun path : Ir.rule ->
      { id = route.name;
        match_ = match_condition path route;
        guard;
        priority = priority_of ~regex_priority:route.regex_priority ~index route path;
        decision = Ir.Allow;
        rate_limited;
        targets_admin })
    paths

let to_policy (cfg : Ast.config) : Ir.policy =
  (* [index] is a config-wide route counter, used only to hand unmodelled-match
     routes a shape nothing else shares. *)
  let index = ref (-1) in
  let rules =
    List.concat_map
      (fun (service : Ast.service) ->
        List.concat_map
          (fun route -> incr index; rules_of_route ~index:!index service route)
          service.routes)
      cfg.services
  in
  { rules; default = Ir.Deny }
