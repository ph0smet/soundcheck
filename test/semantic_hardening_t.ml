open Soundcheck_core
open Soundcheck_kong

let expect_shadowing config ~serving ~shadowed ~valid =
  match Verify.run ~property:Verify.No_shadowed_routes config with
  | Ok { Report.result = Report.Violated witness; _ }
    when witness.route = Some serving && witness.shadowed_route = Some shadowed
         && valid witness -> ()
  | Ok report -> failwith ("expected valid shadowing witness: " ^ Report.to_json report)
  | Error error -> failwith error

(* Kong routes before applying access plugins. A longer literal prefix wins
   within this identical criterion category in both pinned 3.9.3 routers.
   Neither guard's constraint set contains the other: authenticated traffic
   outside the private network is allowed by the winner and denied by the
   intended lower-priority route. Static syntactic subset tests cannot exclude
   this pair. This expectation follows directly from the property obligation,
   not from Soundcheck's candidate selection. *)
let () =
  let trusted = match Cidr.parse "10.0.0.0/8" with Ok cidr -> cidr | Error e -> failwith e in
  expect_shadowing
    {|services:
  - name: api
    routes:
      - name: network-only
        paths: [/admin]
        plugins:
          - name: ip-restriction
            config: {allow: [10.0.0.0/8]}
      - name: authenticated-only
        paths: [/admin/reports]
        plugins: [{name: key-auth}]
|}
    ~serving:"authenticated-only" ~shadowed:"network-only"
    ~valid:(fun witness ->
      witness.Report.principal = "authenticated"
      && String.starts_with ~prefix:"/admin/reports" witness.path
      && not (Cidr.contains trusted witness.source_ip));
  expect_shadowing
    {|services:
  - name: api
    routes:
      - name: network-a
        paths: [/admin]
        plugins:
          - name: ip-restriction
            config: {allow: [10.0.0.0/8]}
      - name: network-b
        paths: [/admin/reports]
        plugins:
          - name: ip-restriction
            config: {allow: [192.168.0.0/16]}
|}
    ~serving:"network-b" ~shadowed:"network-a"
    ~valid:(fun witness ->
      let other = match Cidr.parse "192.168.0.0/16" with Ok c -> c | Error e -> failwith e in
      Cidr.contains other witness.Report.source_ip
      && String.starts_with ~prefix:"/admin/reports" witness.path
      && not (Cidr.contains trusted witness.source_ip));
  let outside = match Cidr.parse "10.0.0.0/8" with Ok c -> c | Error e -> failwith e in
  List.iter
    (fun target ->
      let source =
        "services: [{name: admin-upstream, " ^ target
        ^ ", routes: [{name: admin-proxy, paths: [/admin]}]}]"
      in
      match Verify.run ~property:(Verify.Admin_api_not_reachable outside) source with
      | Ok { Report.result = Report.Violated witness; _ }
        when witness.route = Some "admin-proxy"
             && witness.service = Some "admin-upstream"
             && witness.principal = "anonymous"
             && String.starts_with ~prefix:"/admin" witness.path
             && not (Cidr.contains outside witness.source_ip) -> ()
      | Ok report -> failwith ("explicit Admin API target missed: " ^ Report.to_json report)
      | Error error -> failwith error)
    [ "protocol: http, host: localhost, port: 8001";
      "protocol: https, host: localhost, port: 8444";
      "url: 'http://localhost:08001'";
      "url: 'http://localhost:8001/?x=1'";
      "url: '//localhost:8001'";
      "url: 'https://localhost:8444#section'" ];
  (* Kong's non-deprecated URL shorthand overrides explicit target fields.
     services.lua produces the fields; schema/init.lua applies those values. *)
  List.iter
    (fun (target, expected) ->
      match Parse.parse_string ("services: [{name: api, " ^ target ^ "}]") with
      | Ok { Ast.services = [ service ]; _ }
        when Lower.targets_admin_api service = expected -> ()
      | _ -> failwith ("Admin API target precedence: " ^ target))
    [ ("protocol: https, host: localhost", false);
      ("url: http://localhost:8001, port: 8080", true);
      ("url: http://localhost:8080, port: 8001", false);
      ("url: http://localhost, port: 8001", false);
      ("url: https://localhost, port: 8444", false) ];
  (* Numeric CIDR containment is a semantic implication even when the syntax
     differs; retaining the pair must not invent a shadowing violation. *)
  (match Verify.run ~property:Verify.No_shadowed_routes
    {|services:
  - name: api
    routes:
      - name: broader
        paths: [/admin]
        plugins: [{name: ip-restriction, config: {allow: [10.0.0.0/8]}}]
      - name: narrower
        paths: [/admin/reports]
        plugins: [{name: ip-restriction, config: {allow: [10.1.0.0/16]}}]
|} with
   | Ok { Report.result = Report.Proved; _ } -> ()
   | Ok report -> failwith ("CIDR implication: " ^ Report.to_json report)
   | Error error -> failwith error);
  (* Kong accepts unnamed entities. Until stable internal route identities are
     represented, shared display names must not discard all candidate pairs. *)
  (match Verify.run ~property:Verify.No_shadowed_routes
    {|services:
  - name: api
    routes:
      - paths: [/admin]
        plugins: [{name: key-auth}]
      - paths: [/admin/reports]
|} with
   | Ok { Report.result = Report.Unknown _; _ } -> ()
   | Ok report -> failwith ("ambiguous route identity: " ^ Report.to_json report)
   | Error error -> failwith error);
  print_endline "semantic hardening checks passed"
