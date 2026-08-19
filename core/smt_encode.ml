(* SMT-LIB2 string literals escape a double-quote by doubling it. Our inputs are
   paths/methods, so this is sufficient. *)
let smt_str s =
  let b = Buffer.create (String.length s + 2) in
  Buffer.add_char b '"';
  String.iter
    (fun c -> if c = '"' then Buffer.add_string b "\"\"" else Buffer.add_char b c)
    s;
  Buffer.add_char b '"';
  Buffer.contents b

(* A condition becomes a boolean SMT-LIB2 expression over the symbolic request
   fields [path], [method], [is_anon]. *)
let rec cond (c : Ir.condition) : string =
  match c with
  | Ir.True -> "true"
  | Ir.Path_prefix p -> Printf.sprintf "(str.prefixof %s path)" (smt_str p)
  | Ir.Path_exact p -> Printf.sprintf "(= path %s)" (smt_str p)
  | Ir.Method_is m -> Printf.sprintf "(= method %s)" (smt_str m)
  | Ir.Is_anonymous -> "is_anon"
  | Ir.Requires_auth -> "(not is_anon)"
  | Ir.Not c -> Printf.sprintf "(not %s)" (cond c)
  | Ir.And [] -> "true"
  | Ir.And cs -> Printf.sprintf "(and %s)" (String.concat " " (List.map cond cs))
  | Ir.Or [] -> "false"
  | Ir.Or cs -> Printf.sprintf "(or %s)" (String.concat " " (List.map cond cs))

(* [selected] encodes "this rule is the one that SERVES the request": its routing
   criteria match, and no strictly higher-priority rule's do. Real gateways are
   winner-takes-all — one route is chosen on routing criteria alone, and only its
   policy then applies — so a request that fails the winner's guard is denied, NOT
   re-routed to something more permissive.

   Two deliberate choices:

   - Strict [>], so rules of EQUAL priority remain simultaneously selectable.
     Equal priority means the connector could not establish an order (see
     {!Ir.rule}); over such a tied set this degrades to exactly the old union,
     which is a sound over-approximation rather than a guess.

   - The suppression set ranges over ALL rules, not only those passing
     [reach_via]. A higher-priority route really does take the request even when
     a structural property is not counting it as a "reaching" rule; filtering it
     here would let us claim reachability via a route that is in fact shadowed. *)
let selected (all : Ir.rule list) (r : Ir.rule) : string =
  match List.filter (fun (o : Ir.rule) -> o.priority > r.priority) all with
  | [] -> cond r.match_
  | higher ->
    Printf.sprintf "(and %s %s)" (cond r.match_)
      (String.concat " "
         (List.map
            (fun (o : Ir.rule) -> Printf.sprintf "(not %s)" (cond o.match_))
            higher))

(* The policy's "allowed" predicate (mirrors {!Ir.evaluate}):
     allowed = (not matched_deny) and (matched_allow or default)
   where a rule counts as matched when it both SERVES the request (selected) and
   PERMITS it (guard). [reach_via] filters which Allow rules count as reaching
   (the Deny side is unfiltered) — this is how a structural property (e.g.
   rate-limit-on-public) asks "reachable specifically via a rule of this kind". *)
let allowed_formula ~reach_via (p : Ir.policy) : string =
  let matched (want : Ir.decision) =
    let keep (r : Ir.rule) =
      r.decision = want && (match want with Ir.Allow -> reach_via r | Ir.Deny -> true)
    in
    let rs = List.filter keep p.rules in
    match rs with
    | [] -> "false"
    | _ ->
      Printf.sprintf "(or %s)"
        (String.concat " "
           (List.map
              (fun (r : Ir.rule) ->
                Printf.sprintf "(and %s %s)" (selected p.rules r) (cond r.guard))
              rs))
  in
  let a = matched Ir.Allow in
  let d = matched Ir.Deny in
  let def = match p.default with Ir.Allow -> "true" | Ir.Deny -> "false" in
  Printf.sprintf "(and (not %s) (or %s %s))" d a def

let preamble b title =
  Buffer.add_string b "; Soundcheck SMT-LIB2 query\n";
  Buffer.add_string b title;
  Buffer.add_string b "(set-logic ALL)\n";
  Buffer.add_string b "(declare-const path String)\n";
  Buffer.add_string b "(declare-const method String)\n";
  Buffer.add_string b "(declare-const is_anon Bool)\n"

let epilogue b =
  Buffer.add_string b "(check-sat)\n";
  Buffer.add_string b "(get-value (path method is_anon))\n";
  Buffer.contents b

let to_smtlib (p : Ir.policy) (prop : Property.t) : string =
  let b = Buffer.create 512 in
  preamble b (Printf.sprintf "; property: %s — %s\n" prop.name prop.description);
  Buffer.add_string b "; the request is in the property's forbidden class:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond prop.forbidden_when));
  Buffer.add_string b "; ... yet the policy would allow it:\n";
  Buffer.add_string b
    (Printf.sprintf "(assert %s)\n" (allowed_formula ~reach_via:prop.reach_via p));
  epilogue b

(* One shadowing pair:  selected_i ∧ match_k ∧ guard_i ∧ ¬guard_k.

   A request the SHADOWING rule serves and permits, which the SHADOWED rule was
   written to handle and would have denied. [selected] is shared with
   {!allowed_formula}, so shadowing and reachability agree by construction about
   which rule serves a request. *)
let shadowing_query (p : Ir.policy) (pair : Shadowing.pair) : string =
  let i = pair.shadowing and k = pair.shadowed in
  let b = Buffer.create 512 in
  preamble b
    (Printf.sprintf "; property: %s — route %S shadowed by route %S\n"
       Shadowing.name k.Ir.id i.Ir.id);
  Buffer.add_string b "; the higher-priority route serves the request:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (selected p.rules i));
  Buffer.add_string b "; the shadowed route was written to handle it:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond k.Ir.match_));
  Buffer.add_string b "; the server lets it through ...\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond i.Ir.guard));
  Buffer.add_string b "; ... where the shadowed route would have stopped it:\n";
  Buffer.add_string b (Printf.sprintf "(assert (not %s))\n" (cond k.Ir.guard));
  epilogue b
