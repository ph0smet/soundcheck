type principal =
  | Anonymous
  | Authenticated_unknown
  | Authenticated of string

type action = string
type resource = string
type context = (string * string) list

type object_request = {
  namespace : string;
  resource_kind : string;
  name : string;
}

type object_field = Object_namespace | Object_kind | Object_name

type request = {
  principal : principal;
  action    : action;
  resource  : resource;
  context   : context;
  source    : int32;   (* IPv4 source address of the connection *)
  host      : string;  (* request Host, already lowercased by the server *)
  scheme    : string;  (* normalized request scheme, e.g. http / https *)
  sni       : string;  (* TLS server name, empty when absent *)
  object_request : object_request option;
}

type decision = Allow | Deny

type condition =
  | True
  | Path_prefix of string
  | Path_exact  of string
  | Path_regex  of Regex.t
  | Method_is   of string
  | Is_anonymous
  | Requires_auth
  | Principal_is of string
  | Has_object_request
  | Object_is of object_field * string
  | Object_matches of object_field * Regex.t
  | Object_length_at_most of object_field * int
  | Source_in   of Cidr.t
  | Host_matches of Regex.t
  | Scheme_is of string
  | Sni_is of string
  | Header_has of string * string
  | Not of condition
  | And of condition list
  | Or  of condition list

type priority = {
  comparable : bool;
  key        : int list;
}

(* Lexicographic, higher wins, first difference decides. Keys of differing length
   are treated as unordered rather than padded — a length mismatch means the
   connector built them from different rules and no comparison is meaningful. *)
let rec lex_gt (xs : int list) (ys : int list) : bool =
  match (xs, ys) with
  | [], [] -> false
  | x :: xs', y :: ys' -> if x <> y then x > y else lex_gt xs' ys'
  | _ -> false

(* Strictly outranks. An INCOMPARABLE rule neither outranks nor is outranked by
   anything, so it never suppresses and is never suppressed, and the encoding
   degrades to the sound union around it. Connectors mark a rule incomparable
   when they cannot model one of its match criteria: ignoring a criterion makes
   [match_] an over-approximation, which is harmless where it appears positively
   but hides violations where it appears negated in the suppression term. *)
let outranks (a : priority) (b : priority) : bool =
  a.comparable && b.comparable && List.length a.key = List.length b.key
  && lex_gt a.key b.key

type rule = {
  id           : string;
  match_       : condition;
  match_complete : bool;
  guard        : condition;
  guard_complete : bool;
  priority     : priority;
  decision      : decision;
  rate_limited  : bool;
  targets_admin : bool;
}

let must_guard (rule : rule) = if rule.guard_complete then rule.guard else Or []

type policy = {
  request_domain : condition;
  rules          : rule list;
  default        : decision;
}

let starts_with ~prefix s =
  let lp = String.length prefix in
  String.length s >= lp && String.sub s 0 lp = prefix

let object_value field (object_request : object_request) =
  match field with
  | Object_namespace -> object_request.namespace
  | Object_kind -> object_request.resource_kind
  | Object_name -> object_request.name

let rec matches (c : condition) (r : request) : bool =
  match c with
  | True -> true
  | Path_prefix p -> starts_with ~prefix:p r.resource
  | Path_exact p -> r.resource = p
  | Path_regex re -> Regex.matches_full re r.resource
  | Method_is m -> r.action = m
  | Is_anonymous -> r.principal = Anonymous
  | Requires_auth -> r.principal <> Anonymous
  | Principal_is name ->
    (match r.principal with Authenticated actual -> actual = name | _ -> false)
  | Has_object_request -> Option.is_some r.object_request
  | Object_is (field, value) ->
    Option.fold ~none:false ~some:(fun object_request -> object_value field object_request = value)
      r.object_request
  | Object_matches (field, regex) ->
    Option.fold ~none:false
      ~some:(fun object_request -> Regex.matches_full regex (object_value field object_request))
      r.object_request
  | Object_length_at_most (field, limit) ->
    Option.fold ~none:false
      ~some:(fun object_request -> String.length (object_value field object_request) <= limit)
      r.object_request
  | Source_in c -> Cidr.contains c r.source
  | Host_matches re -> Regex.matches_full re r.host
  | Scheme_is scheme -> r.scheme = scheme
  | Sni_is sni -> r.sni = sni
  | Header_has (name, value) ->
    List.exists
      (fun (candidate_name, candidate_value) ->
        String.lowercase_ascii candidate_name = name
        && String.lowercase_ascii candidate_value = value)
      r.context
  | Not c -> not (matches c r)
  | And cs -> List.for_all (fun c -> matches c r) cs
  | Or cs -> List.exists (fun c -> matches c r) cs

(* Winner-takes-all selection, mirroring {!Smt_encode.selected}: [rule] serves
   [r] when its routing criteria match and no STRICTLY higher-priority rule's do.
   Ties stay simultaneously selectable, degrading to a union over the tied set. *)
let selected (p : policy) (r : request) (rule : rule) : bool =
  matches rule.match_ r
  && not
       (List.exists
          (fun (o : rule) ->
            o.match_complete && outranks o.priority rule.priority && matches o.match_ r)
          p.rules)

let possibly_allows ?(reach_via = fun _ -> true) (p : policy) (r : request) =
  matches p.request_domain r
  && (List.exists
        (fun rule ->
          rule.decision = Allow && reach_via rule && selected p r rule
          && matches rule.guard r)
        p.rules
      || (p.default = Allow
          && not (List.exists
                    (fun rule -> rule.match_complete && matches rule.match_ r)
                    p.rules)))

let evaluate p r = if possibly_allows p r then Allow else Deny

let definitely_allows (p : policy) (r : request) : bool =
  matches p.request_domain r
  && match List.filter (selected p r) p.rules with
     | [] -> p.default = Allow
     | possible_winners ->
       List.for_all
         (fun rule ->
           rule.match_complete
           && rule.decision = Allow
           && matches (must_guard rule) r)
         possible_winners

let string_of_decision = function Allow -> "Allow" | Deny -> "Deny"

let string_of_principal = function
  | Anonymous -> "anonymous"
  | Authenticated_unknown -> "authenticated"
  | Authenticated s -> Printf.sprintf "authenticated(%s)" s
