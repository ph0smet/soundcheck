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

let hex s =
  s |> String.to_seq
  |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
  |> List.of_seq |> String.concat ""

let header_symbol name value =
  Printf.sprintf "header_%s_%s" (hex name) (hex value)

(* A condition becomes a boolean SMT-LIB2 expression over the symbolic request
   fields [path], [method], [is_anon]. *)
let rec cond (c : Ir.condition) : string =
  match c with
  | Ir.True -> "true"
  | Ir.Path_prefix p -> Printf.sprintf "(str.prefixof %s path)" (smt_str p)
  | Ir.Path_exact p -> Printf.sprintf "(= path %s)" (smt_str p)
  | Ir.Path_regex re -> Printf.sprintf "(str.in_re path %s)" (Regex.to_smt re)
  | Ir.Method_is m -> Printf.sprintf "(= method %s)" (smt_str m)
  | Ir.Is_anonymous -> "is_anon"
  | Ir.Requires_auth -> "(not is_anon)"
  | Ir.Source_in c -> Cidr.to_smt ~var:"src_ip" c
  | Ir.Host_matches re -> Printf.sprintf "(str.in_re host %s)" (Regex.to_smt re)
  | Ir.Scheme_is scheme -> Printf.sprintf "(= scheme %s)" (smt_str scheme)
  | Ir.Sni_is sni -> Printf.sprintf "(= sni %s)" (smt_str sni)
  | Ir.Header_has (name, value) ->
    header_symbol name value
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

   - Only STRICT {!Ir.outranks} suppresses, so rules the connector could not order
     — equal or incomparable — remain simultaneously selectable. Over such a set
     this degrades to exactly the old union, a sound over-approximation rather
     than a guess.

   - The suppression set ranges over ALL rules, not only those passing
     [reach_via]. A higher-priority route really does take the request even when
     a structural property is not counting it as a "reaching" rule; filtering it
     here would let us claim reachability via a route that is in fact shadowed. *)
let selected (all : Ir.rule list) (r : Ir.rule) : string =
  match List.filter (fun (o : Ir.rule) -> Ir.outranks o.priority r.priority) all with
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

let rec header_atoms = function
  | Ir.Header_has (name, value) -> [ (name, value) ]
  | Ir.Not condition -> header_atoms condition
  | Ir.And conditions | Ir.Or conditions ->
    List.concat_map header_atoms conditions
  | _ -> []

let unique_headers conditions =
  conditions |> List.concat_map header_atoms |> List.sort_uniq compare

let policy_conditions (policy : Ir.policy) =
  policy.request_domain
  :: List.concat_map
       (fun (rule : Ir.rule) -> [ rule.match_; rule.guard ])
       policy.rules

let preamble b title headers =
  Buffer.add_string b "; Soundcheck SMT-LIB2 query\n";
  Buffer.add_string b title;
  Buffer.add_string b "(set-logic ALL)\n";
  Buffer.add_string b "(declare-const path String)\n";
  Buffer.add_string b "(declare-const method String)\n";
  Buffer.add_string b "(declare-const is_anon Bool)\n";
  (* A bitvector, so CIDR membership is a mask-and-compare rather than string
     arithmetic. Declared for every query; unused by properties that ignore it. *)
  Buffer.add_string b "(declare-const src_ip (_ BitVec 32))\n";
  Buffer.add_string b "(declare-const host String)\n";
  Buffer.add_string b "(declare-const scheme String)\n";
  Buffer.add_string b "(declare-const sni String)\n";
  List.iter
    (fun (name, value) ->
      Buffer.add_string b
        (Printf.sprintf "(declare-const %s Bool)\n"
           (header_symbol name value)))
    headers

let epilogue b headers =
  Buffer.add_string b "(check-sat)\n";
  Buffer.add_string b
    "; Conditional SAT observation: Soundcheck replays get-value only after sat.\n";
  let header_symbols =
    headers |> List.map (fun (name, value) -> header_symbol name value)
    |> String.concat " "
  in
  Buffer.add_string b
    (Printf.sprintf "(get-value (path method is_anon src_ip host scheme sni%s%s))\n"
       (if header_symbols = "" then "" else " ") header_symbols);
  Buffer.contents b

let assert_domain b domain =
  Buffer.add_string b "; the request belongs to the connector's valid domain:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond domain))

let condition_query ?(domain = Ir.True) ~name ~description condition =
  let b = Buffer.create 256 in
  let headers = unique_headers [ domain; condition ] in
  preamble b (Printf.sprintf "; property preflight: %s — %s\n" name description)
    headers;
  assert_domain b domain;
  Buffer.add_string b "; the property's forbidden request class is inhabited:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond condition));
  epilogue b headers

let overlap_query ?(domain = Ir.True) left right =
  let left_class = Contract.request_class left in
  let right_class = Contract.request_class right in
  condition_query ~domain
    ~name:(Contract.name left ^ "/" ^ Contract.name right)
    ~description:"safety/functionality request-class overlap"
    (Ir.And [ left_class; right_class ])

(* A functionality proof needs the opposite approximation from a safety proof.
   [selected] may name several possible winners when the connector cannot prove
   their order. Safety asks whether ANY possible winner allows; functionality
   must establish that EVERY possible winner allows. Requiring every selected
   rule to be an Allow whose guard holds deliberately turns routing uncertainty
   into a possible false violation rather than a false proof. *)
let definitely_allowed_formula (p : Ir.policy) : string =
  let possibilities = List.map (fun r -> (r, selected p.rules r)) p.rules in
  let any_selected =
    match possibilities with
    | [] -> "false"
    | _ ->
      Printf.sprintf "(or %s)"
        (String.concat " " (List.map (fun (_, selected) -> selected) possibilities))
  in
  let every_possible_winner_allows =
    match possibilities with
    | [] -> "true"
    | _ ->
      Printf.sprintf "(and %s)"
        (String.concat " "
           (List.map
              (fun (r, selected) ->
                let allows =
                  match r.Ir.decision with
                  | Ir.Allow when r.Ir.match_complete -> cond r.Ir.guard
                  | Ir.Allow -> "false"
                  | Ir.Deny -> "false"
                in
                Printf.sprintf "(=> %s %s)" selected allows)
              possibilities))
  in
  let default_allows = match p.default with Ir.Allow -> "true" | Ir.Deny -> "false" in
  Printf.sprintf "(and %s (or %s (and (not %s) %s)))"
    every_possible_winner_allows any_selected any_selected default_allows

let contract_clause_query (p : Ir.policy) (clause : Contract.clause) : string =
  let b = Buffer.create 512 in
  let headers =
    unique_headers
      (Contract.request_class clause :: policy_conditions p)
  in
  preamble b
    (Printf.sprintf "; contract clause: %s — %s\n"
       (Contract.name clause) (Contract.description clause))
    headers;
  assert_domain b p.request_domain;
  Buffer.add_string b "; the request is in the clause's request class:\n";
  Buffer.add_string b
    (Printf.sprintf "(assert %s)\n" (cond (Contract.request_class clause)));
  (match clause with
   | Contract.Must_deny c ->
     Buffer.add_string b "; ... yet the policy would allow it:\n";
     Buffer.add_string b
       (Printf.sprintf "(assert %s)\n"
          (allowed_formula ~reach_via:c.reach_via p))
   | Contract.Must_allow _ ->
     Buffer.add_string b "; ... yet the policy does not definitely allow it:\n";
     Buffer.add_string b
       (Printf.sprintf "(assert (not %s))\n" (definitely_allowed_formula p)));
  epilogue b headers

let to_smtlib (p : Ir.policy) (prop : Property.t) : string =
  let b = Buffer.create 512 in
  let headers =
    unique_headers (prop.forbidden_when :: policy_conditions p)
  in
  preamble b (Printf.sprintf "; property: %s — %s\n" prop.name prop.description)
    headers;
  assert_domain b p.request_domain;
  Buffer.add_string b "; the request is in the property's forbidden class:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond prop.forbidden_when));
  Buffer.add_string b "; ... yet the policy would allow it:\n";
  Buffer.add_string b
    (Printf.sprintf "(assert %s)\n" (allowed_formula ~reach_via:prop.reach_via p));
  epilogue b headers

(* One shadowing pair:  selected_i ∧ match_k ∧ guard_i ∧ ¬guard_k.

   A request the SHADOWING rule serves and permits, which the SHADOWED rule was
   written to handle and would have denied. [selected] is shared with
   {!allowed_formula}, so shadowing and reachability agree by construction about
   which rule serves a request. *)
let shadowing_query (p : Ir.policy) (pair : Shadowing.pair) : string =
  let i = pair.shadowing and k = pair.shadowed in
  let b = Buffer.create 512 in
  let headers = unique_headers (policy_conditions p) in
  preamble b
    (Printf.sprintf "; property: %s — route %S shadowed by route %S\n"
       Shadowing.name k.Ir.id i.Ir.id)
    headers;
  assert_domain b p.request_domain;
  Buffer.add_string b "; the higher-priority route serves the request:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (selected p.rules i));
  Buffer.add_string b "; the shadowed route was written to handle it:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond k.Ir.match_));
  Buffer.add_string b "; the server lets it through ...\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond i.Ir.guard));
  Buffer.add_string b "; ... where the shadowed route would have stopped it:\n";
  Buffer.add_string b (Printf.sprintf "(assert (not %s))\n" (cond k.Ir.guard));
  epilogue b headers

let decision_equivalence_query ?(when_ = Ir.True) (left : Ir.policy)
    (right : Ir.policy) : string =
  let b = Buffer.create 768 in
  let headers =
    unique_headers (when_ :: policy_conditions left @ policy_conditions right)
  in
  preamble b "; decision equivalence: find a request where policies disagree\n"
    headers;
  let left_allows =
    Printf.sprintf "(and %s %s)" (cond left.request_domain)
      (allowed_formula ~reach_via:(fun _ -> true) left)
  in
  let right_allows =
    Printf.sprintf "(and %s %s)" (cond right.request_domain)
      (allowed_formula ~reach_via:(fun _ -> true) right)
  in
  Buffer.add_string b "; at least one connector admits the request:\n";
  Buffer.add_string b
    (Printf.sprintf "(assert (or %s %s))\n"
       (cond left.request_domain) (cond right.request_domain));
  Buffer.add_string b "; the request is inside the comparison scope:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond when_));
  Buffer.add_string b "; the policy decisions differ:\n";
  Buffer.add_string b
    (Printf.sprintf "(assert (xor %s %s))\n" left_allows right_allows);
  epilogue b headers

type string_term =
  | Request_path
  | Literal of string
  | Concat of string_term list
  | Drop_prefix of int
  | If of string_test * string_term * string_term

and string_test =
  | Equal of string_term * string_term
  | Starts_with of string_term * string
  | Ends_with of string_term * string
  | Length_greater_than of string_term * int

let rec string_term = function
  | Request_path -> "path"
  | Literal value -> smt_str value
  | Concat [] -> smt_str ""
  | Concat [ term ] -> string_term term
  | Concat terms ->
    Printf.sprintf "(str.++ %s)"
      (String.concat " " (List.map string_term terms))
  | Drop_prefix count ->
    Printf.sprintf "(str.substr path %d (- (str.len path) %d))" count count
  | If (test, yes, no) ->
    Printf.sprintf "(ite %s %s %s)" (string_test test) (string_term yes)
      (string_term no)

and string_test = function
  | Equal (left, right) ->
    Printf.sprintf "(= %s %s)" (string_term left) (string_term right)
  | Starts_with (term, prefix) ->
    Printf.sprintf "(str.prefixof %s %s)" (smt_str prefix) (string_term term)
  | Ends_with (term, suffix) ->
    Printf.sprintf "(str.suffixof %s %s)" (smt_str suffix) (string_term term)
  | Length_greater_than (term, length) ->
    Printf.sprintf "(> (str.len %s) %d)" (string_term term) length

let rec eval_string_term ~path = function
  | Request_path -> path
  | Literal value -> value
  | Concat terms ->
    terms |> List.map (eval_string_term ~path) |> String.concat ""
  | Drop_prefix count ->
    if count >= String.length path then ""
    else String.sub path count (String.length path - count)
  | If (test, yes, no) ->
    eval_string_term ~path (if eval_string_test ~path test then yes else no)

and eval_string_test ~path = function
  | Equal (left, right) ->
    eval_string_term ~path left = eval_string_term ~path right
  | Starts_with (term, prefix) ->
    String.starts_with ~prefix (eval_string_term ~path term)
  | Ends_with (term, suffix) ->
    String.ends_with ~suffix (eval_string_term ~path term)
  | Length_greater_than (term, length) ->
    String.length (eval_string_term ~path term) > length

let route_equivalence_query ?(when_ = Ir.True) ?left_value ?right_value
    ~left_label ~right_label (left : Ir.policy) (right : Ir.policy) : string =
  let b = Buffer.create 1024 in
  let headers =
    unique_headers (when_ :: policy_conditions left @ policy_conditions right)
  in
  preamble b
    "; route/service equivalence: find a request where decision or selection differs\n"
    headers;
  let allows policy =
    Printf.sprintf "(and %s %s)" (cond policy.Ir.request_domain)
      (allowed_formula ~reach_via:(fun _ -> true) policy)
  in
  let labels =
    List.map left_label left.rules @ List.map right_label right.rules
    |> List.sort_uniq String.compare
  in
  let selected_label policy label_of label =
    let rules =
      List.filter (fun rule -> label_of rule = label) policy.Ir.rules
    in
    let selection =
      match rules with
      | [] -> "false"
      | _ ->
        Printf.sprintf "(or %s)"
          (String.concat " " (List.map (selected policy.rules) rules))
    in
    Printf.sprintf "(and %s %s)" (cond policy.request_domain) selection
  in
  let differences =
    Printf.sprintf "(xor %s %s)" (allows left) (allows right)
    :: List.map
         (fun label ->
           Printf.sprintf "(xor %s %s)"
             (selected_label left left_label label)
             (selected_label right right_label label))
         labels
  in
  let differences =
    match left_value, right_value with
    | Some left_value, Some right_value ->
      let value_differences =
        List.concat_map
          (fun left_rule ->
            List.map
              (fun right_rule ->
                Printf.sprintf "(and %s %s (not (= %s %s)))"
                  (Printf.sprintf "(and %s %s)" (cond left.request_domain)
                     (selected left.rules left_rule))
                  (Printf.sprintf "(and %s %s)" (cond right.request_domain)
                     (selected right.rules right_rule))
                  (string_term (left_value left_rule))
                  (string_term (right_value right_rule)))
              right.rules)
          left.rules
      in
      differences @ value_differences
    | None, None -> differences
    | _ -> invalid_arg "route_equivalence_query requires both value callbacks"
  in
  Buffer.add_string b "; at least one connector admits the request:\n";
  Buffer.add_string b
    (Printf.sprintf "(assert (or %s %s))\n"
       (cond left.request_domain) (cond right.request_domain));
  Buffer.add_string b "; the request is inside the comparison scope:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond when_));
  Buffer.add_string b "; the decision or selected route/service differs:\n";
  Buffer.add_string b
    (Printf.sprintf "(assert (or %s))\n" (String.concat " " differences));
  epilogue b headers
