open Soundcheck_kong

let parse source =
  match Contract_spec.parse_string source with
  | Ok spec -> spec
  | Error error -> failwith error

let expect_error label source fragment =
  match Contract_spec.parse_string source with
  | Ok _ -> failwith (label ^ ": expected rejection")
  | Error error ->
    if not (String.starts_with ~prefix:fragment error) then
      failwith (Printf.sprintf "%s: unexpected error %S" label error)

let () =
  let spec =
    parse
      {|schema_version: 1
kind: authenticated-access
scope:
  path_prefix: /admin
  method: GET
  host: ADMIN.EXAMPLE
|}
  in
  if spec.path_prefix <> "/admin" || spec.method_ <> Some "GET"
     || spec.host <> Some "admin.example"
  then failwith "contract scope did not parse or normalize";
  let expected =
    {|{"schema_version":1,"kind":"authenticated-access","scope":{"path_prefix":"/admin","method":"GET","host":"admin.example"}}|}
  in
  if Contract_spec.canonical_json spec <> expected then
    failwith "canonical contract identity changed";
  let identity = Contract_spec.report_identity spec in
  if identity.schema_version <> 1 || identity.kind <> "authenticated-access"
     || identity.canonical <> expected
  then failwith "report identity does not preserve the frozen artifact";

  expect_error "unknown top-level field"
    "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin}\nproperty: weaker\n"
    "contract: unknown field";
  expect_error "unknown scope field"
    "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, methods: GET}\n"
    "contract.scope: unknown field";
  expect_error "unsupported version"
    "schema_version: 2\nkind: authenticated-access\nscope: {path_prefix: /admin}\n"
    "unsupported contract schema_version";
  expect_error "unsupported kind"
    "schema_version: 1\nkind: no-anonymous-access\nscope: {path_prefix: /admin}\n"
    "unsupported contract kind";
  expect_error "missing explicit scope"
    "schema_version: 1\nkind: authenticated-access\nscope: {}\n"
    "contract.scope.path_prefix is required"
