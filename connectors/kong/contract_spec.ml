type t = {
  schema_version : int;
  kind           : string;
  path_prefix    : string;
  method_        : string option;
  host           : string option;
}

let allowed_fields where allowed fields =
  match List.find_opt (fun (name, _) -> not (List.mem name allowed)) fields with
  | None -> Ok ()
  | Some (name, _) -> Error (Printf.sprintf "%s: unknown field %S" where name)

let required_string where name fields =
  match List.assoc_opt name fields with
  | Some (`String value) -> Ok value
  | Some _ -> Error (Printf.sprintf "%s.%s must be a string" where name)
  | None -> Error (Printf.sprintf "%s.%s is required" where name)

let optional_string where name fields =
  match List.assoc_opt name fields with
  | None | Some `Null -> Ok None
  | Some (`String value) -> Ok (Some value)
  | Some _ -> Error (Printf.sprintf "%s.%s must be a string" where name)

let schema_version fields =
  match List.assoc_opt "schema_version" fields with
  | Some (`Float version) when version = 1.0 -> Ok 1
  | Some (`Float version) ->
    Error
      (Printf.sprintf "unsupported contract schema_version %.15g (expected 1)"
         version)
  | Some _ -> Error "contract.schema_version must be the number 1"
  | None -> Error "contract.schema_version is required"

let parse_value = function
  | `O fields ->
    (match allowed_fields "contract" [ "schema_version"; "kind"; "scope" ] fields with
     | Error _ as error -> error
     | Ok () ->
       match schema_version fields with
       | Error _ as error -> error
       | Ok schema_version ->
         match required_string "contract" "kind" fields with
         | Error _ as error -> error
         | Ok kind when kind <> "authenticated-access" ->
           Error (Printf.sprintf "unsupported contract kind %S" kind)
         | Ok kind ->
           match List.assoc_opt "scope" fields with
           | None -> Error "contract.scope is required"
           | Some (`O scope) ->
             (match allowed_fields "contract.scope" [ "path_prefix"; "method"; "host" ] scope with
              | Error _ as error -> error
              | Ok () ->
                match required_string "contract.scope" "path_prefix" scope with
                | Error _ as error -> error
                | Ok path_prefix ->
                  match optional_string "contract.scope" "method" scope with
                  | Error _ as error -> error
                  | Ok method_ ->
                    match optional_string "contract.scope" "host" scope with
                    | Error _ as error -> error
                    | Ok host ->
                      Ok
                        { schema_version;
                          kind;
                          path_prefix;
                          method_;
                          host = Option.map String.lowercase_ascii host })
           | Some _ -> Error "contract.scope must be an object")
  | _ -> Error "contract artifact must be an object"

let parse_string source =
  match Yaml.of_string source with
  | Ok value -> parse_value value
  | Error (`Msg message) -> Error ("contract YAML: " ^ message)

let read_file path =
  try
    let channel = open_in_bin path in
    let length = in_channel_length channel in
    let source = really_input_string channel length in
    close_in channel;
    parse_string source
  with Sys_error message -> Error message

let to_property spec =
  Verify.Authenticated_access
    { path_prefix = spec.path_prefix; method_ = spec.method_; host = spec.host }

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
let json_option = function None -> "null" | Some value -> json_string value

let canonical_json spec =
  Printf.sprintf
    "{\"schema_version\":%d,\"kind\":%s,\"scope\":{\"path_prefix\":%s,\"method\":%s,\"host\":%s}}"
    spec.schema_version (json_string spec.kind) (json_string spec.path_prefix)
    (json_option spec.method_) (json_option spec.host)
