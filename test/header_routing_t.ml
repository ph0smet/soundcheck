open Soundcheck_core
open Soundcheck_kong

let exact_config =
  {|services:
  - name: admin-api
    routes:
    - name: role-route
      paths: [/admin]
      headers:
        X-Role: [Admin, Operator]
|}

let parse config =
  match Parse.parse_string config with
  | Ok parsed -> parsed
  | Error error -> failwith error

let only_rule config =
  match (Lower.to_policy (parse config)).Ir.rules with
  | [ rule ] -> rule
  | _ -> failwith "expected exactly one lowered route"

let request context : Ir.request =
  { principal = Anonymous;
    action = "GET";
    resource = "/admin";
    context;
    source = 0l;
    host = "";
    scheme = "http";
    sni = "" }

let () =
  let rule = only_rule exact_config in
  if not rule.match_complete then
    failwith "exact header route must have a complete match";
  if not (Ir.matches rule.match_ (request [ ("x-role", "operator") ])) then
    failwith "one of several configured header values must match";
  if not (Ir.matches rule.match_ (request [ ("X-ROLE", "ADMIN") ])) then
    failwith "header names and exact values must match case-insensitively";
  if Ir.matches rule.match_ (request []) then
    failwith "missing required header must not match";

  let ranked =
    parse
      {|services:
  - name: api
    routes:
    - name: one-header
      paths: [/admin]
      headers: {x-role: [admin]}
    - name: two-headers
      paths: [/admin]
      headers: {x-role: [admin], x-region: [west]}
|}
    |> Lower.to_policy
  in
  let find name =
    match List.find_opt (fun (candidate : Ir.rule) -> candidate.id = name) ranked.rules with
    | Some found -> found
    | None -> failwith ("missing lowered route " ^ name)
  in
  (* Both routers account for headers, but their interactions with regex and
     category selection differ. Heterogeneous non-path predicates therefore
     retain possible winners; pinned conformance asserts actual target order. *)
  if Ir.outranks (find "two-headers").priority (find "one-header").priority
     || Ir.outranks (find "one-header").priority (find "two-headers").priority
  then failwith "shared header precedence must remain conservative";

  (match Verify.run ~property:(Verify.No_anonymous_access "/admin") exact_config with
   | Ok { result = Report.Violated counterexample; _ } ->
     if
       not
         (List.exists
            (fun pair -> pair = ("x-role", "admin") || pair = ("x-role", "operator"))
            counterexample.headers)
     then failwith "counterexample omitted the required exact header"
   | Ok _ -> failwith "open exact-header route must produce a violation"
   | Error error -> failwith error);

  let regex =
    {|services:
  - name: api
    routes:
    - name: regex-header
      paths: [/admin]
      headers: {x-role: ['~*^admin']}
|}
  in
  let regex_rule = only_rule regex in
  if regex_rule.match_complete then
    failwith "regex header route must remain conservatively incomplete";
  (match (Assurance.assess (parse regex)).findings with
  | [ { code = "route-header-regex"; _ } ] -> ()
  | _ -> failwith "regex header route must carry an assurance finding");

  (* Kong 3.9.3 traditional.lua recognizes singleton ~* lists only; compatible
     transform.lua recognizes each value. administrator matches the regex in
     the compatible router even in this mixed list. Literal-only lowering
     would omit that possible winner and falsely prove no shadowing. *)
  let mixed =
    {|services:
  - name: api
    routes:
    - name: mixed-open
      paths: [/admin]
      headers: {x-role: ['~*^admin', guest]}
    - name: exact-guarded
      paths: [/admin]
      headers: {x-role: [administrator]}
      plugins: [{name: key-auth}]
|}
  in
  let mixed_policy = Lower.to_policy (parse mixed) in
  let open_rule = List.find (fun (r : Ir.rule) -> r.id = "mixed-open") mixed_policy.rules in
  if open_rule.match_complete
     || not (Ir.matches open_rule.match_ (request ["x-role", "administrator"]))
  then failwith "mixed regex header list omitted compatible-router candidates";
  (match Verify.run ~property:Verify.No_shadowed_routes mixed with
   | Ok { result = Report.Violated _; _ } -> ()
   | Ok _ -> failwith "mixed regex header overlap must not prove absence of shadowing"
   | Error error -> failwith error)
