type source_ip_integrity = Externally_enforced

type kind =
  | Authenticated_access
  | Network_restricted_access of {
      trusted_cidr       : Soundcheck_core.Cidr.t;
      source_ip_integrity : source_ip_integrity;
    }

type t = {
  schema_version : int;
  kind           : kind;
  path_prefix    : string;
  method_        : string option;
  host           : string option;
}

let kind_name = function
  | Authenticated_access -> "authenticated-access"
  | Network_restricted_access _ -> "network-restricted-access"

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

let parse_scope fields allowed =
  match List.assoc_opt "scope" fields with
  | None -> Error "contract.scope is required"
  | Some (`O scope) ->
    (match allowed_fields "contract.scope" allowed scope with
     | Error _ as error -> error
     | Ok () ->
       match required_string "contract.scope" "path_prefix" scope with
       | Error _ as error -> error
       | Ok path_prefix
         when not (Path_normalization.is_normalized_literal path_prefix) ->
         Error
           (Printf.sprintf
              "contract.scope.path_prefix %S is not normalized; use %S"
              path_prefix (Path_normalization.normalize_literal path_prefix))
       | Ok path_prefix ->
         match optional_string "contract.scope" "method" scope with
         | Error _ as error -> error
         | Ok method_ ->
           match optional_string "contract.scope" "host" scope with
           | Error _ as error -> error
           | Ok host ->
             Ok (scope, path_prefix, method_, Option.map String.lowercase_ascii host))
  | Some _ -> Error "contract.scope must be an object"

let parse_source_ip_assumption fields =
  match List.assoc_opt "assumptions" fields with
  | None -> Error "contract.assumptions is required for network-restricted-access"
  | Some (`O assumptions) ->
    (match allowed_fields "contract.assumptions" [ "source_ip_integrity" ] assumptions with
     | Error _ as error -> error
     | Ok () ->
       match required_string "contract.assumptions" "source_ip_integrity" assumptions with
       | Ok "externally-enforced" -> Ok Externally_enforced
       | Ok value ->
         Error
           (Printf.sprintf
              "contract.assumptions.source_ip_integrity must be %S, got %S"
              "externally-enforced" value)
       | Error _ as error -> error)
  | Some _ -> Error "contract.assumptions must be an object"

let parse_value = function
  | `O fields ->
    (match
       allowed_fields "contract"
         [ "schema_version"; "kind"; "scope"; "assumptions" ] fields
     with
     | Error _ as error -> error
     | Ok () ->
       match schema_version fields with
       | Error _ as error -> error
       | Ok schema_version ->
         match required_string "contract" "kind" fields with
         | Error _ as error -> error
         | Ok "authenticated-access" ->
           if List.mem_assoc "assumptions" fields then
             Error "contract.assumptions is not valid for authenticated-access"
           else
             (match parse_scope fields [ "path_prefix"; "method"; "host" ] with
              | Error _ as error -> error
              | Ok (_, path_prefix, method_, host) ->
                Ok
                  { schema_version;
                    kind = Authenticated_access;
                    path_prefix;
                    method_;
                    host })
         | Ok "network-restricted-access" ->
           (match
              parse_scope fields
                [ "path_prefix"; "method"; "host"; "trusted_cidr" ]
            with
            | Error _ as error -> error
            | Ok (scope, path_prefix, method_, host) ->
              match required_string "contract.scope" "trusted_cidr" scope with
              | Error _ as error -> error
              | Ok raw_cidr ->
                (match Soundcheck_core.Cidr.parse raw_cidr with
                 | Error error ->
                   Error
                     (Printf.sprintf "contract.scope.trusted_cidr: %s" error)
                 | Ok trusted_cidr ->
                   match parse_source_ip_assumption fields with
                   | Error _ as error -> error
                   | Ok source_ip_integrity ->
                     Ok
                       { schema_version;
                         kind =
                           Network_restricted_access
                             { trusted_cidr; source_ip_integrity };
                         path_prefix;
                         method_;
                         host }))
         | Ok kind -> Error (Printf.sprintf "unsupported contract kind %S" kind))
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
  match spec.kind with
  | Authenticated_access ->
    Verify.Authenticated_access
      { path_prefix = spec.path_prefix; method_ = spec.method_; host = spec.host }
  | Network_restricted_access { trusted_cidr; _ } ->
    Verify.Network_restricted_access
      { path_prefix = spec.path_prefix;
        method_ = spec.method_;
        host = spec.host;
        trusted_cidr }

let scope_condition spec =
  Soundcheck_core.Ir.And
    ([ Soundcheck_core.Ir.Path_prefix spec.path_prefix ]
     @ Option.to_list
         (Option.map (fun method_ -> Soundcheck_core.Ir.Method_is method_)
            spec.method_)
     @ Option.to_list
         (Option.map
            (fun host ->
              Soundcheck_core.Ir.Host_matches
                (Soundcheck_core.Regex.Lit (String.lowercase_ascii host)))
            spec.host))

let escape_json value =
  let buffer = Buffer.create (String.length value) in
  String.iter
    (function
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | character when Char.code character < 0x20 ->
        Buffer.add_string buffer (Printf.sprintf "\\u%04x" (Char.code character))
      | character -> Buffer.add_char buffer character)
    value;
  Buffer.contents buffer

let json_string value = "\"" ^ escape_json value ^ "\""
let json_option = function None -> "null" | Some value -> json_string value

let canonical_json spec =
  let scope_fields =
    Printf.sprintf "\"path_prefix\":%s,\"method\":%s,\"host\":%s"
      (json_string spec.path_prefix) (json_option spec.method_)
      (json_option spec.host)
  in
  match spec.kind with
  | Authenticated_access ->
    Printf.sprintf
      "{\"schema_version\":%d,\"kind\":%s,\"scope\":{%s}}"
      spec.schema_version (json_string (kind_name spec.kind)) scope_fields
  | Network_restricted_access { trusted_cidr; source_ip_integrity = Externally_enforced } ->
    Printf.sprintf
      "{\"schema_version\":%d,\"kind\":%s,\"scope\":{%s,\"trusted_cidr\":%s},\"assumptions\":{\"source_ip_integrity\":\"externally-enforced\"}}"
      spec.schema_version (json_string (kind_name spec.kind)) scope_fields
      (json_string (Soundcheck_core.Cidr.to_string trusted_cidr))

let report_identity spec : Soundcheck_core.Report.frozen_spec =
  { schema_version = spec.schema_version;
    kind = kind_name spec.kind;
    canonical = canonical_json spec }

let bind_report spec (report : Soundcheck_core.Report.t) =
  { report with frozen_spec = Some (report_identity spec) }
