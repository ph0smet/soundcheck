open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input
module J = Server.J

type phase = New | Initializing | Ready
type t = {
  contract : K.Contract_spec.t;
  baseline : string option;
  mutable phase : phase;
}

let create ~contract ?baseline () =
  match baseline with
  | Some source -> (match K.Snapshot.of_string source with
      | Error reason -> Error ("unsupported RBAC baseline: " ^ reason)
      | Ok _ -> Ok {contract;baseline;phase=New})
  | None -> Ok {contract;baseline;phase=New}

let max_message_bytes = 16 * 1024 * 1024

let tool name description =
  J.obj ["name",J.str name;"description",J.str description;
    "inputSchema",J.obj ["type",J.str "object";
      "properties",J.obj ["config",J.obj ["type",J.str "string";
        "description",J.str "Replacement complete static RBAC snapshot as one strict JSON Kubernetes v1/List."]];
      "required",J.arr [J.str "config"];"additionalProperties","false"]]

let tools state =
  let verify = tool "verify"
      "Verify the candidate against the frozen RBAC contract and identity context loaded at startup. This does not check preservation against a baseline." in
  let compare = match state.baseline with
    | None -> []
    | Some source -> [tool "compare"
        ("Verify the candidate contract and preserve RBAC decisions outside the approved change scope against the immutable startup baseline (SHA-256 "
         ^ Sha256.string source ^ "). Only config may be supplied.")] in
  J.obj ["tools",J.arr (verify::compare)]

exception Rpc_error of int * string
let invalid message = raise (Rpc_error (-32602,message))
let object_fields label = function
  | `O fields -> fields
  | _ -> invalid (label ^ " must be an object")
let string_field label name fields = match List.assoc_opt name fields with
  | Some (`String value) -> value
  | _ -> invalid (label ^ " requires string " ^ name)

let tool_call state params =
  let fields = object_fields "params" params in
  if List.exists (fun (key,_) -> not (List.mem key ["name";"arguments";"_meta"])) fields then
    invalid "tools/call accepts only name, arguments and protocol _meta";
  (match List.assoc_opt "_meta" fields with
   | None | Some (`O _) -> ()
   | _ -> invalid "protocol _meta must be an object");
  let name = string_field "tools/call" "name" fields in
  if name <> "verify" && (name <> "compare" || state.baseline=None) then
    invalid ("unknown tool: " ^ name);
  let config = match List.assoc_opt "arguments" fields with
    | Some (`O ["config",`String config]) -> config
    | _ -> invalid "frozen RBAC tools accept only {config: string}; contract, identity context and baseline are immutable" in
  let report = match name,state.baseline with
    | "compare",Some before -> K.Verify.compare state.contract ~before ~after:config
    | _ -> K.Verify.run state.contract config in
  Report.to_json report |> Server.tool_ok

let dispatch state method_ params =
  match method_ with
  | "initialize" ->
    if state.phase <> New then invalid "server is already initialized";
    let fields = object_fields "initialize params" params in
    ignore (string_field "initialize" "protocolVersion" fields);
    (match List.assoc_opt "capabilities" fields with
     | Some (`O _) -> () | _ -> invalid "initialize requires capabilities object");
    let client = match List.assoc_opt "clientInfo" fields with
      | Some value -> object_fields "clientInfo" value
      | None -> invalid "initialize requires clientInfo" in
    ignore (string_field "clientInfo" "name" client);
    ignore (string_field "clientInfo" "version" client);
    state.phase <- Initializing;
    Server.initialize_result ()
  | "ping" -> "{}"
  | _ when state.phase <> Ready -> invalid "initialize and notifications/initialized are required before tool requests"
  | "tools/list" ->
    let fields = object_fields "tools/list params" params in
    (match List.assoc_opt "cursor" fields with
     | None -> () | _ -> invalid "this tool list has no pagination cursor");
    tools state
  | "tools/call" -> tool_call state params
  | _ -> raise (Rpc_error (-32601,"method not found: " ^ method_))

let request_id = function
  | `String _ as value -> Some (I.json value)
  | `Number value when String.for_all (function '0'..'9'|'-' -> true | _ -> false) value -> Some value
  | _ -> None

let parse_error reason = Server.error_envelope ~id:"null" ~code:(-32700) ~msg:reason

let handle_line state line =
  match I.protect (fun () -> I.parse line) with
  | Error reason -> Some (parse_error reason)
  | Ok value ->
    let id = ref "null" in
    try
      let fields = match value with
        | `O fields -> fields
        | _ -> raise (Rpc_error (-32600,"request must be a JSON object")) in
      (match List.assoc_opt "id" fields with
       | None -> ()
       | Some value -> (match request_id value with
           | Some value -> id:=value
           | None -> raise (Rpc_error (-32600,"request id must be a string or decimal integer"))));
      if List.exists (fun (key,_) -> not (List.mem key ["jsonrpc";"id";"method";"params"])) fields then
        raise (Rpc_error (-32600,"unsupported request envelope field"));
      if List.assoc_opt "jsonrpc" fields <> Some (`String "2.0") then
        raise (Rpc_error (-32600,"jsonrpc must be 2.0"));
      let method_ = match List.assoc_opt "method" fields with
        | Some (`String value) -> value
        | _ -> raise (Rpc_error (-32600,"request method must be a string")) in
      let params = Option.value ~default:(`O []) (List.assoc_opt "params" fields) in
      if not (List.mem_assoc "id" fields) then begin
        if method_="notifications/initialized" && state.phase=Initializing
           && (match params with `O _ -> true | _ -> false) then state.phase<-Ready;
        None
      end else begin
        ignore (object_fields "params" params);
        Some (Server.result_envelope ~id:!id ~result:(dispatch state method_ params))
      end
    with Rpc_error (code,msg) -> Some (Server.error_envelope ~id:!id ~code ~msg)

let read_frame channel =
  let buffer = Buffer.create 4096 in
  let oversized = ref false in
  let rec read () = match input_char channel with
    | '\n' -> Some (if !oversized then Error "MCP message exceeds 16 MiB" else Ok (Buffer.contents buffer))
    | character ->
      if Buffer.length buffer < max_message_bytes then Buffer.add_char buffer character
      else oversized:=true;
      read ()
    | exception End_of_file ->
      if Buffer.length buffer=0 && not !oversized then None
      else Some (if !oversized then Error "MCP message exceeds 16 MiB" else Ok (Buffer.contents buffer)) in
  read ()

let run state =
  set_binary_mode_in stdin true;
  set_binary_mode_out stdout true;
  let rec loop () = match read_frame stdin with
    | None -> ()
    | Some frame ->
      let response = match frame with
        | Error reason -> Some (parse_error reason)
        | Ok line when String.trim line="" -> None
        | Ok line -> handle_line state line in
      Option.iter (fun line -> print_endline line;flush stdout) response;
      loop () in
  loop ()
