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
  let control =
    parse
      "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: \"/admin\\u0001\"}\n"
  in
  (match Yaml.of_string (Contract_spec.canonical_json control) with
   | Ok (`O fields) ->
     (match List.assoc_opt "scope" fields with
      | Some (`O scope) when List.assoc_opt "path_prefix" scope = Some (`String "/admin\001") -> ()
      | _ -> failwith "canonical contract changed a control byte")
   | _ -> failwith "canonical contract did not escape JSON control bytes");
  let identity = Contract_spec.report_identity spec in
  if identity.schema_version <> 1 || identity.kind <> "authenticated-access"
     || identity.canonical <> expected
  then failwith "report identity does not preserve the frozen artifact";
  let report : Soundcheck_core.Report.t =
    { result = Soundcheck_core.Report.Proved;
      property_name = "authenticated-access";
      property_description = "frozen";
      assurance = None;
      clause = None;
      frozen_spec = None }
  in
  let bound = Contract_spec.bind_report spec report in
  (match bound.frozen_spec with
   | Some frozen when frozen.canonical = expected -> ()
   | _ -> failwith "binding omitted frozen contract provenance");
  if not (String.ends_with ~suffix:("Frozen spec: " ^ expected)
            (Soundcheck_core.Report.to_human bound))
  then failwith "human report omitted frozen contract provenance";

  let network =
    parse
      {|schema_version: 1
kind: network-restricted-access
scope:
  path_prefix: /internal
  method: GET
  host: INTERNAL.EXAMPLE
  trusted_cidr: 10.1.2.3/8
assumptions:
  source_ip_integrity: externally-enforced
|}
  in
  if Contract_spec.kind_name network.kind <> "network-restricted-access"
     || network.path_prefix <> "/internal"
  then failwith "network contract kind or scope did not parse";
  let expected_network =
    {|{"schema_version":1,"kind":"network-restricted-access","scope":{"path_prefix":"/internal","method":"GET","host":"internal.example","trusted_cidr":"10.0.0.0/8"},"assumptions":{"source_ip_integrity":"externally-enforced"}}|}
  in
  if Contract_spec.canonical_json network <> expected_network then
    failwith "canonical network contract identity changed";
  (match Contract_spec.to_property network with
   | Verify.Network_restricted_access { trusted_cidr; _ }
     when Soundcheck_core.Cidr.to_string trusted_cidr = "10.0.0.0/8" -> ()
   | _ -> failwith "network contract did not become a typed verifier property");

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
    "contract.scope.path_prefix is required";
  expect_error "network missing trusted CIDR"
    "schema_version: 1\nkind: network-restricted-access\nscope: {path_prefix: /internal}\nassumptions: {source_ip_integrity: externally-enforced}\n"
    "contract.scope.trusted_cidr is required";
  expect_error "network missing source assumption"
    "schema_version: 1\nkind: network-restricted-access\nscope: {path_prefix: /internal, trusted_cidr: 10.0.0.0/8}\n"
    "contract.assumptions is required";
  expect_error "network unacknowledged source assumption"
    "schema_version: 1\nkind: network-restricted-access\nscope: {path_prefix: /internal, trusted_cidr: 10.0.0.0/8}\nassumptions: {source_ip_integrity: verified-by-soundcheck}\n"
    "contract.assumptions.source_ip_integrity must be";
  expect_error "non-normalized contract scope"
    "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin/../secret}\n"
    "contract.scope.path_prefix \"/admin/../secret\" is not normalized; use \"/secret\"";
  List.iter
    (fun (label, source, where) -> expect_error label source (where ^ ": duplicate field"))
    [ ("duplicate schema version",
       "schema_version: 1\nschema_version: 2\nkind: authenticated-access\nscope: {path_prefix: /admin}\n",
       "contract");
      ("duplicate kind",
       "schema_version: 1\nkind: authenticated-access\nkind: network-restricted-access\nscope: {path_prefix: /admin}\n",
       "contract");
      ("duplicate scope",
       "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin}\nscope: {path_prefix: /public}\n",
       "contract");
      ("duplicate path prefix",
       "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, path_prefix: /public}\n",
       "contract.scope");
      ("duplicate optional scope",
       "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, method: GET, method: POST}\n",
       "contract.scope");
      ("duplicate source assumption",
       "schema_version: 1\nkind: network-restricted-access\nscope: {path_prefix: /admin, trusted_cidr: 10.0.0.0/8}\nassumptions: {source_ip_integrity: externally-enforced, source_ip_integrity: ignored}\n",
       "contract.assumptions");
      ("recursive duplicate before field lookup",
       "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, host: [{nested: {key: one, key: two}}]}\n",
       "contract.scope.host[0].nested") ];
  expect_error "second contract document"
    "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin}\n---\nschema_version: 2\n"
    "contract YAML: expected a single document";
  expect_error "tagged contract scalar"
    "schema_version: !!str 1\nkind: authenticated-access\nscope: {path_prefix: /admin}\n"
    "contract YAML: explicit tags are unsupported";
  expect_error "contract merge"
    "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, <<: {method: GET}}\n"
    "contract.scope: YAML merge keys are unsupported"
