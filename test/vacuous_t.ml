open Soundcheck_core
open Soundcheck_kong

let config =
  {|_format_version: "3.0"
services:
  - name: kong-admin
    url: http://127.0.0.1:8001
    routes:
      - name: admin-proxy
        paths: [/kong-admin]
|}

let trusted =
  match Cidr.parse "0.0.0.0/0" with
  | Ok cidr -> cidr
  | Error e -> failwith e

let () =
  match Verify.run ~property:(Verify.Admin_api_not_reachable trusted) config with
  | Error e -> failwith e
  | Ok report ->
    (match report.Report.result with
     | Report.Vacuous -> ()
     | _ -> failwith "expected a vacuous result for an empty forbidden class");
    let expected_human =
      "VACUOUS  admin-api-not-reachable\n\
      \         The admin API must not be reachable, unauthenticated, from outside 0.0.0.0/0\n\
      \         The property's forbidden request class is empty; no config was verified."
    in
    let got_human = Report.to_human report in
    if got_human <> expected_human then
      failwith
        (Printf.sprintf "unexpected human report\nexpected: %s\ngot:      %s"
           expected_human got_human);
    let expected =
      {|{"result":"vacuous","schema_version":5,"property":"admin-api-not-reachable","clause":null,"counterexample":null}|}
    in
    let got = Report.to_json report in
    if got <> expected then
      failwith (Printf.sprintf "unexpected JSON\nexpected: %s\ngot:      %s" expected got)
