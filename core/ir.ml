type principal =
  | Anonymous
  | Authenticated of string

type action = string
type resource = string
type context = (string * string) list

type request = {
  principal : principal;
  action    : action;
  resource  : resource;
  context   : context;
}

type decision = Allow | Deny

type condition =
  | True
  | Path_prefix of string
  | Path_exact  of string
  | Method_is   of string
  | Is_anonymous
  | Requires_auth
  | Not of condition
  | And of condition list
  | Or  of condition list

type rule = {
  id           : string;
  match_       : condition;
  guard        : condition;
  priority     : int;
  decision     : decision;
  rate_limited : bool;
}

type policy = {
  rules   : rule list;
  default : decision;
}

let starts_with ~prefix s =
  let lp = String.length prefix in
  String.length s >= lp && String.sub s 0 lp = prefix

let rec matches (c : condition) (r : request) : bool =
  match c with
  | True -> true
  | Path_prefix p -> starts_with ~prefix:p r.resource
  | Path_exact p -> r.resource = p
  | Method_is m -> r.action = m
  | Is_anonymous -> (match r.principal with Anonymous -> true | Authenticated _ -> false)
  | Requires_auth -> (match r.principal with Authenticated _ -> true | Anonymous -> false)
  | Not c -> not (matches c r)
  | And cs -> List.for_all (fun c -> matches c r) cs
  | Or cs -> List.exists (fun c -> matches c r) cs

let applies_when (r : rule) : condition = And [ r.match_; r.guard ]

let evaluate (p : policy) (r : request) : decision =
  let matching = List.filter (fun rule -> matches (applies_when rule) r) p.rules in
  if List.exists (fun rule -> rule.decision = Deny) matching then Deny
  else if List.exists (fun rule -> rule.decision = Allow) matching then Allow
  else p.default

let string_of_decision = function Allow -> "Allow" | Deny -> "Deny"

let string_of_principal = function
  | Anonymous -> "anonymous"
  | Authenticated s -> Printf.sprintf "authenticated(%s)" s
