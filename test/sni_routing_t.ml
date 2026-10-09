open Soundcheck_core
open Soundcheck_kong

let config plugins =
  Printf.sprintf
    {|services:
  - name: secure-api
    routes:
    - name: secure-sni
      protocols: [https]
      paths: [/admin]
      snis: [api.example.]
      plugins: %s
|}
    plugins

let parse source =
  match Parse.parse_string source with
  | Ok parsed -> parsed
  | Error error -> failwith error

let request ~scheme ~sni : Ir.request =
  { principal = Anonymous;
    action = "GET";
    resource = "/admin";
    context = [];
    source = 0l;
    host = "";
    scheme;
    sni }

let valid_blocked_authenticated_request policy (ce : Report.counterexample) =
  let request : Ir.request =
    { principal = Authenticated "subject";
      action = ce.action;
      resource = ce.path;
      context = ce.headers;
      source = ce.source_ip;
      host = ce.host;
      scheme = ce.scheme;
      sni = ce.sni }
  in
  ce.principal = "authenticated"
  && String.starts_with ~prefix:"/admin" ce.path
  && Ir.matches policy.Ir.request_domain request
  && not (Ir.definitely_allows policy request)
  && Ir.evaluate policy request = Deny

let contains haystack needle =
  let haystack_length = String.length haystack in
  let needle_length = String.length needle in
  let rec search offset =
    if offset + needle_length > haystack_length then false
    else if String.sub haystack offset needle_length = needle then true
    else search (offset + 1)
  in
  search 0

let () =
  let policy = Lower.to_policy (parse (config "[]")) in
  if List.length policy.rules <> 2 then
    failwith "SNI route must lower to HTTP-bypass and HTTPS variants";
  if Ir.evaluate policy (request ~scheme:"http" ~sni:"") <> Deny then
    failwith "HTTPS-only route must reject an HTTP request after selection";
  if Ir.evaluate policy (request ~scheme:"https" ~sni:"api.example") <> Allow then
    failwith "normalized exact SNI must match HTTPS";
  if Ir.evaluate policy (request ~scheme:"https" ~sni:"other.example") <> Deny then
    failwith "wrong HTTPS SNI must not match";

  (match
     Verify.run ~property:(Verify.No_anonymous_access "/admin") (config "[]")
   with
   | Ok { result = Report.Violated counterexample; _ }
     when counterexample.scheme = "https"
          && counterexample.sni = "api.example"
          && contains counterexample.note "over https with SNI api.example" -> ()
   | Ok _ -> failwith "SNI violation omitted its HTTPS/SNI witness"
   | Error error -> failwith error);

  let guarded = config "[{name: key-auth}]" in
  let guarded_policy = Lower.to_policy (parse guarded) in
  (match
     Verify.run
       ~property:
         (Verify.Authenticated_access
            { path_prefix = "/admin"; method_ = None; host = None })
       guarded
   with
   | Ok
       { result = Report.Violated counterexample;
         clause =
           Some
             { name = "authenticated-access-allowed";
               kind = Report.Must_allow;
               _ };
         _ } ->
     let valid = valid_blocked_authenticated_request guarded_policy in
     if not (valid counterexample) then
       failwith "functionality witness must be authenticated, in scope, and blocked";
     (* Either HTTP or HTTPS with absent/wrong SNI can witness this failure. *)
     List.iter
       (fun (scheme, sni) ->
         if not (valid { counterexample with path = "/admin/status"; scheme; sni })
         then failwith "functionality check rejected a valid blocked witness")
       [ "http", ""; "https", ""; "https", "other.example" ];
     List.iter
       (fun invalid ->
         if valid invalid then
           failwith "functionality check accepted an invalid witness")
       [ { counterexample with principal = "anonymous" };
         { counterexample with path = "/public" };
         { counterexample with scheme = "ftp" };
         { counterexample with scheme = "https"; sni = "api.example" } ]
   | Ok _ ->
     failwith
       "HTTPS-only route must not prove all-scheme authenticated functionality"
   | Error error -> failwith error);

  let wildcard =
    parse
      {|services:
  - name: api
    routes:
    - name: wildcard-sni
      protocols: [https]
      snis: ['*.example']
|}
  in
  let wildcard_policy = Lower.to_policy wildcard in
  if List.for_all (fun (rule : Ir.rule) -> rule.match_complete) wildcard_policy.rules
  then failwith "wildcard SNI must remain conservatively incomplete";
  (match (Assurance.assess wildcard).findings with
   | [ { code = "wildcard-sni"; _ } ] -> ()
   | _ -> failwith "wildcard SNI must carry an assurance finding");

  let expect_invalid source fragment =
    match Verify.run ~property:(Verify.No_anonymous_access "/admin") source with
    | Error error when String.starts_with ~prefix:fragment error -> ()
    | Error error -> failwith ("unexpected protocol validation error: " ^ error)
    | Ok _ -> failwith "invalid Kong protocol configuration was accepted"
  in
  expect_invalid
    "services: [{name: api, routes: [{name: mixed, protocols: [http, tcp], paths: [/admin]}]}]"
    "invalid Kong config: route \"mixed\" (service \"api\") has unknown or incompatible protocols";
  expect_invalid
    "services: [{name: api, routes: [{name: insecure-sni, protocols: [http], snis: [api.example], paths: [/admin]}]}]"
    "invalid Kong config: route \"insecure-sni\" (service \"api\") snis require secure protocols"
