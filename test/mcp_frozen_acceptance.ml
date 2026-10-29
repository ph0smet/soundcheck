open Soundcheck_kong

let fail format = Printf.ksprintf failwith format

let read_file path =
  let channel = open_in_bin path in
  let length = in_channel_length channel in
  let source = really_input_string channel length in
  close_in channel;
  source

let escape_json value =
  let buffer = Buffer.create (String.length value) in
  String.iter
    (function
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | character -> Buffer.add_char buffer character)
    value;
  Buffer.contents buffer

let json_string value = "\"" ^ escape_json value ^ "\""

let call id fields =
  Printf.sprintf
    {|{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"verify","arguments":{%s}}}|}
    id fields

let config_call id config = call id ("\"config\":" ^ json_string config)

let field name = function
  | `O fields -> List.assoc_opt name fields
  | _ -> None

let require_field where name value =
  match field name value with
  | Some found -> found
  | None -> fail "%s omitted field %S" where name

let require_string where name value =
  match require_field where name value with
  | `String found -> found
  | _ -> fail "%s field %S was not a string" where name

let parse_response line =
  match Yaml.of_string line with
  | Ok value -> value
  | Error (`Msg message) -> fail "invalid JSON-RPC response: %s" message

let result response = require_field "response" "result" response

let structured_report response =
  result response |> require_field "tool result" "structuredContent"

let assert_frozen_report ~canonical ~verdict ?clause response =
  let report = structured_report response in
  let actual_verdict = require_string "report" "result" report in
  if actual_verdict <> verdict then
    fail "expected verdict %s, got %s" verdict actual_verdict;
  let frozen = require_field "report" "frozen_spec" report in
  let actual_canonical = require_string "frozen_spec" "canonical" frozen in
  if actual_canonical <> canonical then
    fail "frozen contract identity changed across repair attempts";
  match clause with
  | None -> report
  | Some expected ->
    let clause = require_field "report" "clause" report in
    let actual = require_string "clause" "kind" clause in
    if actual <> expected then fail "expected clause %s, got %s" expected actual;
    report

let assert_counterexample ~principal ~route report =
  let counterexample = require_field "report" "counterexample" report in
  let actual_principal = require_string "counterexample" "principal" counterexample in
  if actual_principal <> principal then
    fail "expected principal %s, got %s" principal actual_principal;
  match (route, require_field "counterexample" "route" counterexample) with
  | Some expected, `String actual when actual = expected -> ()
  | None, `Null -> ()
  | _ -> fail "counterexample selected an unexpected route"

let assert_discovery response =
  let tools = require_field "tools/list result" "tools" (result response) in
  let tool = match tools with `A (tool :: _) -> tool | _ -> fail "verify tool missing" in
  let schema = require_field "verify tool" "inputSchema" tool in
  let properties = require_field "input schema" "properties" schema in
  (match properties with
   | `O [ ("config", _) ] -> ()
   | _ -> fail "frozen tool exposed inputs other than config");
  match require_field "input schema" "additionalProperties" schema with
  | `Bool false -> ()
  | _ -> fail "frozen tool permits additional properties"

let assert_override_rejected response =
  let tool_result = result response in
  (match require_field "tool result" "isError" tool_result with
   | `Bool true -> ()
   | _ -> fail "property substitution was not a tool error");
  let content = require_field "tool result" "content" tool_result in
  match content with
  | `A (message :: _) ->
    let text = require_string "tool error" "text" message in
    if not (String.starts_with ~prefix:"frozen verify accepts only config" text)
    then fail "unexpected substitution error: %s" text
  | _ -> fail "property substitution error omitted content"

let read_responses channel =
  let rec loop lines =
    match input_line channel with
    | line -> loop (parse_response line :: lines)
    | exception End_of_file -> List.rev lines
  in
  loop []

let () =
  if Array.length Sys.argv <> 6 && Array.length Sys.argv <> 7 then
    fail "usage: mcp_frozen_acceptance SOUNDCHECK CONTRACT UNSAFE REPAIRED DENY_ALL [UNSAFE_ROUTE]";
  let soundcheck = Sys.argv.(1) in
  let contract_path = Sys.argv.(2) in
  let unsafe = read_file Sys.argv.(3) in
  let repaired = read_file Sys.argv.(4) in
  let deny_all = read_file Sys.argv.(5) in
  let unsafe_route = if Array.length Sys.argv = 7 then Sys.argv.(6) else "admin-get" in
  let contract =
    match Contract_spec.read_file contract_path with
    | Ok contract -> contract
    | Error message -> fail "contract fixture: %s" message
  in
  let requests =
    [ {|{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}|};
      config_call 2 unsafe;
      config_call 3 repaired;
      config_call 4 deny_all;
      call 5
        ("\"config\":" ^ json_string repaired
       ^ ",\"property\":\"no-anonymous-access\"") ]
  in
  let input = Filename.temp_file "soundcheck-frozen-mcp" ".jsonl" in
  let channel = open_out_bin input in
  List.iter (fun request -> output_string channel request; output_char channel '\n') requests;
  close_out channel;
  let command =
    Printf.sprintf "%s mcp --contract %s < %s" (Filename.quote soundcheck)
      (Filename.quote contract_path) (Filename.quote input)
  in
  let output = Unix.open_process_in command in
  let responses = read_responses output in
  let status = Unix.close_process_in output in
  Sys.remove input;
  (match status with
   | Unix.WEXITED 0 -> ()
   | _ -> fail "frozen MCP process did not exit successfully");
  match responses with
  | [ discovery; unsafe; repaired; deny_all; override ] ->
    let canonical = Contract_spec.canonical_json contract in
    assert_discovery discovery;
    let unsafe_report =
      assert_frozen_report ~canonical ~verdict:"violated" ~clause:"must_deny" unsafe
    in
    assert_counterexample ~principal:"anonymous" ~route:(Some unsafe_route) unsafe_report;
    ignore (assert_frozen_report ~canonical ~verdict:"proved" repaired);
    let deny_all_report =
      assert_frozen_report ~canonical ~verdict:"violated" ~clause:"must_allow" deny_all
    in
    assert_counterexample ~principal:"authenticated" ~route:None deny_all_report;
    assert_override_rejected override
  | _ -> fail "expected five MCP responses, got %d" (List.length responses)
