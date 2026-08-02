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

(* The policy's "allowed" predicate under deny-overrides semantics (mirrors
   {!Ir.evaluate}):  allowed = (not matched_deny) and (matched_allow or default) *)
let allowed_formula (p : Ir.policy) : string =
  let matched (want : Ir.decision) =
    let rs = List.filter (fun (r : Ir.rule) -> r.decision = want) p.rules in
    match rs with
    | [] -> "false"
    | _ ->
      Printf.sprintf "(or %s)"
        (String.concat " " (List.map (fun (r : Ir.rule) -> cond r.when_) rs))
  in
  let a = matched Ir.Allow in
  let d = matched Ir.Deny in
  let def = match p.default with Ir.Allow -> "true" | Ir.Deny -> "false" in
  Printf.sprintf "(and (not %s) (or %s %s))" d a def

let to_smtlib (p : Ir.policy) (prop : Property.t) : string =
  let b = Buffer.create 512 in
  Buffer.add_string b "; Soundcheck SMT-LIB2 query\n";
  Buffer.add_string b
    (Printf.sprintf "; property: %s — %s\n" prop.name prop.description);
  Buffer.add_string b "(set-logic ALL)\n";
  Buffer.add_string b "(declare-const path String)\n";
  Buffer.add_string b "(declare-const method String)\n";
  Buffer.add_string b "(declare-const is_anon Bool)\n";
  Buffer.add_string b "; the request is in the property's forbidden class:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (cond prop.forbidden_when));
  Buffer.add_string b "; ... yet the policy would allow it:\n";
  Buffer.add_string b (Printf.sprintf "(assert %s)\n" (allowed_formula p));
  Buffer.add_string b "(check-sat)\n";
  Buffer.add_string b "(get-value (path method is_anon))\n";
  Buffer.contents b
