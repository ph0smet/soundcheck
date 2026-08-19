(* Minimal MCP (Model Context Protocol) server over stdio.

   A thin adapter that exposes Soundcheck's verifier as an MCP [verify] tool, so
   an in-loop AI agent (Claude Code, Cursor, a custom agent) can call it *while*
   generating a Kong config and self-correct from the counterexample before
   delivering. This is the soft / in-loop enforcement layer; the hard guarantee
   is still the CLI in CI. MCP is an adapter here, not a new agent framework.

   Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP stdio
   transport — one message per line, no embedded newlines). Diagnostics go to
   stderr so they never corrupt the protocol stream.

   All verification logic stays in the shared {!Soundcheck_kong.Verify}, which
   emits the same {!Soundcheck_core.Report} JSON contract the CLI emits — this
   adapter only speaks protocol. *)

open Soundcheck_core
open Soundcheck_kong

let protocol_version = "2024-11-05"
let server_name = "soundcheck"
let server_version = "0.1.0"

(* --- JSON emit: single-line, hand-rolled, dep-free (mirrors core's Report). ---
   Values are already-serialized JSON text, so everything composes by string
   concatenation. *)
module J = struct
  (* RFC 8259 string escaping. *)
  let escape s =
    let buf = Buffer.create (String.length s + 2) in
    String.iter
      (fun c ->
        match c with
        | '"'  -> Buffer.add_string buf "\\\""
        | '\\' -> Buffer.add_string buf "\\\\"
        | '\n' -> Buffer.add_string buf "\\n"
        | '\r' -> Buffer.add_string buf "\\r"
        | '\t' -> Buffer.add_string buf "\\t"
        | c when Char.code c < 0x20 ->
          Buffer.add_string buf (Printf.sprintf "\\u%04x" (Char.code c))
        | c -> Buffer.add_char buf c)
      s;
    Buffer.contents buf

  let str s = "\"" ^ escape s ^ "\""

  (* [obj]/[arr] take already-serialized JSON values. *)
  let obj fields =
    "{" ^ String.concat "," (List.map (fun (k, v) -> str k ^ ":" ^ v) fields) ^ "}"

  let arr items = "[" ^ String.concat "," items ^ "]"
end

(* --- JSON *parsing* of incoming requests ---
   JSON is valid YAML and the [yaml] library is already in the dependency tree
   (the Kong connector uses it), so we reuse it rather than pull in a JSON dep.
   We only read a handful of known, typed fields, so YAML's looser typing never
   comes into play. *)
let field k (v : Yaml.value) : Yaml.value option =
  match v with `O kvs -> List.assoc_opt k kvs | _ -> None

let string_field k v = match field k v with Some (`String s) -> Some s | _ -> None

(* Serialize a parsed value back to JSON text — used to echo the request [id]
   verbatim (number / string / null) in the response, per JSON-RPC. *)
let rec yaml_to_json (v : Yaml.value) : string =
  match v with
  | `Null -> "null"
  | `Bool b -> if b then "true" else "false"
  | `Float f ->
    (* JSON-RPC ids are integers in practice; keep them integral when they are. *)
    if Float.is_integer f && Float.abs f < 1e15 then Printf.sprintf "%.0f" f
    else Printf.sprintf "%g" f
  | `String s -> J.str s
  | `A xs -> J.arr (List.map yaml_to_json xs)
  | `O kvs -> "{" ^ String.concat ","
                      (List.map (fun (k, v) -> J.str k ^ ":" ^ yaml_to_json v) kvs)
              ^ "}"

(* --- envelopes --- *)

let result_envelope ~id ~result =
  J.obj [ "jsonrpc", J.str "2.0"; "id", id; "result", result ]

let error_envelope ~id ~code ~msg =
  J.obj
    [ "jsonrpc", J.str "2.0";
      "id", id;
      "error", J.obj [ "code", string_of_int code; "message", J.str msg ] ]

(* --- method results --- *)

let initialize_result () =
  J.obj
    [ "protocolVersion", J.str protocol_version;
      "capabilities", J.obj [ "tools", J.obj [] ];
      "serverInfo",
      J.obj [ "name", J.str server_name; "version", J.str server_version ] ]

let verify_tool () =
  let input_schema =
    J.obj
      [ "type", J.str "object";
        "properties",
        J.obj
          [ "config",
            J.obj
              [ "type", J.str "string";
                "description",
                J.str "decK (Kong declarative) config YAML to verify." ];
            "property",
            J.obj
              [ "type", J.str "string";
                "enum",
                J.arr
                  [ J.str "no-anonymous-access"; J.str "rate-limit-on-public";
                    J.str "no-shadowed-routes" ];
                "description",
                J.str
                  "Invariant to verify (default no-anonymous-access): \
                   no-anonymous-access = no anonymous request allowed under \
                   path_prefix; rate-limit-on-public = every anonymous-reachable \
                   route has a rate-limiting plugin; no-shadowed-routes = no \
                   route's guard is bypassed by a more permissive route that \
                   outranks it (needs no path_prefix; note that shadowing is \
                   occasionally intentional, e.g. a deliberately public health \
                   endpoint under an authenticated prefix)." ];
            "path_prefix",
            J.obj
              [ "type", J.str "string";
                "description",
                J.str
                  "For no-anonymous-access: the path prefix that must require \
                   authentication (default /admin)." ] ];
        "required", J.arr [ J.str "config" ] ]
  in
  J.obj
    [ "name", J.str "verify";
      "description",
      J.str
        "Verify a Kong decK config against a security property \
         (no-anonymous-access, rate-limit-on-public, or no-shadowed-routes). \
         Returns the stable JSON result contract: result = proved | violated | \
         unknown, with a concrete counterexample (principal / method / path / \
         route / service, plus shadowed_route for shadowing findings) when \
         violated — use it to correct the config and re-verify.";
      "inputSchema", input_schema ]

let tools_list_result () = J.obj [ "tools", J.arr [ verify_tool () ] ]

(* An MCP tool result. A verification outcome (proved/violated/unknown) is a
   *successful* tool call — the report is returned both as text (for clients that
   read [content]) and as [structuredContent] (raw object, for clients that
   consume it directly). [isError] is reserved for tool-execution failures (bad
   arguments, unparseable config), NOT for a "violated" verdict. *)
let tool_ok report_json =
  J.obj
    [ "content", J.arr [ J.obj [ "type", J.str "text"; "text", J.str report_json ] ];
      "structuredContent", report_json ]

let tool_error msg =
  J.obj
    [ "content", J.arr [ J.obj [ "type", J.str "text"; "text", J.str msg ] ];
      "isError", "true" ]

let tool_call json =
  let params = match field "params" json with Some p -> p | None -> `O [] in
  let name = string_field "name" params in
  let args = match field "arguments" params with Some a -> a | None -> `O [] in
  match name with
  | Some "verify" -> (
    match string_field "config" args with
    | None -> tool_error "missing required argument: config"
    | Some config ->
      let path_prefix =
        match string_field "path_prefix" args with Some p -> p | None -> "/admin"
      in
      let prop_name =
        match string_field "property" args with
        | Some p -> p
        | None -> "no-anonymous-access"
      in
      let property =
        match prop_name with
        | "no-anonymous-access" -> Some (Verify.No_anonymous_access path_prefix)
        | "rate-limit-on-public" -> Some Verify.Rate_limit_on_public
        | "no-shadowed-routes" -> Some Verify.No_shadowed_routes
        | _ -> None
      in
      (match property with
       | None ->
         tool_error
           ("unknown property: " ^ prop_name
          ^ " (expected \
             no-anonymous-access|rate-limit-on-public|no-shadowed-routes)")
       | Some property -> (
         match Verify.run ~property config with
         | Error e -> tool_error ("config parse error: " ^ e)
         | Ok report -> tool_ok (Report.to_json report))))
  | Some other -> tool_error ("unknown tool: " ^ other)
  | None -> tool_error "missing tool name"

(* Dispatch one parsed message. A request (has [id]) gets a response line; a
   notification (no [id], e.g. notifications/initialized) is acknowledged with
   no reply. *)
let handle json : string option =
  let meth = match field "method" json with Some (`String m) -> m | _ -> "" in
  match field "id" json with
  | None -> None (* notification *)
  | Some idv ->
    let id = yaml_to_json idv in
    let ok result = Some (result_envelope ~id ~result) in
    (match meth with
     | "initialize" -> ok (initialize_result ())
     | "tools/list" -> ok (tools_list_result ())
     | "tools/call" -> ok (tool_call json)
     | "ping" -> ok "{}"
     | _ -> Some (error_envelope ~id ~code:(-32601) ~msg:("method not found: " ^ meth)))

let handle_line line : string option =
  match Yaml.of_string line with
  | Ok json -> handle json
  | Error (`Msg m) ->
    (* Unparseable line → JSON-RPC parse error, id null. *)
    Some (error_envelope ~id:"null" ~code:(-32700) ~msg:("parse error: " ^ m))

(* Serve until stdin closes. One line in, at most one line out. *)
let run () =
  set_binary_mode_in stdin true;
  set_binary_mode_out stdout true;
  let rec loop () =
    match input_line stdin with
    | exception End_of_file -> ()
    | line ->
      let line = String.trim line in
      if line <> "" then (
        match handle_line line with
        | Some response ->
          print_string response;
          print_char '\n';
          flush stdout
        | None -> ());
      loop ()
  in
  loop ()
