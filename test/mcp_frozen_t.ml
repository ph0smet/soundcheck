open Soundcheck_kong

let contract =
  match
    Contract_spec.parse_string
      "schema_version: 1\nkind: authenticated-access\nscope: {path_prefix: /admin, method: GET}\n"
  with
  | Ok contract -> contract
  | Error error -> failwith error

let contains haystack needle =
  let haystack_length = String.length haystack in
  let needle_length = String.length needle in
  let rec search offset =
    offset + needle_length <= haystack_length
    && (String.sub haystack offset needle_length = needle || search (offset + 1))
  in
  needle_length = 0 || search 0

let response request =
  match Soundcheck_mcp.Server.handle_line ~contract request with
  | Some response -> response
  | None -> failwith "expected an MCP response"

let () =
  let discovery =
    response {|{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}|}
  in
  if contains discovery "path_prefix" || contains discovery "\"property\"" then
    failwith "frozen tool schema exposed mutable specification inputs";
  if not (contains discovery "\"additionalProperties\":false") then
    failwith "frozen tool schema permits undeclared inputs";

  let secure =
    response
      {|{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"verify","arguments":{"config":"{services: [{name: admin, routes: [{name: admin-get, paths: [/admin], methods: [GET], plugins: [{name: key-auth}]}]}]}"}}}|}
  in
  if not (contains secure "\"result\":\"proved\"")
     || not (contains secure "\"frozen_spec\":{")
  then failwith "frozen verification omitted verdict or provenance";

  let override =
    response
      {|{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"verify","arguments":{"config":"{services: []}","property":"no-anonymous-access"}}}|}
  in
  if not (contains override "\"isError\":true")
     || not (contains override "accepts only config")
  then failwith "frozen MCP accepted a property substitution";

  let deny_all =
    response
      {|{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"verify","arguments":{"config":"{services: []}"}}}|}
  in
  if not (contains deny_all "\"result\":\"violated\"")
     || not (contains deny_all "\"kind\":\"must_allow\"")
     || not (contains deny_all "\\\"method\\\":\\\"GET\\\"")
  then failwith "frozen MCP did not reuse the contract for deny-all repair"
