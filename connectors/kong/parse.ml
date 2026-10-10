(* Parse a decK YAML document into {!Ast.config} using the [yaml] library.
   Unmodelled keys remain outside this structural validator, but a malformed
   field that we consume must never disappear or acquire a permissive default.
   This is not a substitute for Kong's full deployment/schema validation. *)

let ( let* ) = Result.bind

(* [Yaml.of_string] returns after the first node: it neither consumes trailing
   documents/syntax nor interprets explicit tags. Check the complete stream
   before conversion so neither can silently change the policy being checked.
   Aliases are rejected during conversion; merge keys are rejected below rather
   than being mistaken for an irrelevant extension field. *)
let check_yaml_stream source =
  let* parser = Yaml.Stream.parser source in
  let rec consume documents =
    let* event, _ = Yaml.Stream.do_parse parser in
    let open Yaml.Stream.Event in
    match event with
    | Stream_end -> Ok ()
    | Document_start _ when documents <> 0 ->
      Error (`Msg "expected a single document")
    | Document_start _ -> consume (documents + 1)
    | Scalar { tag = Some _; _ }
    | Mapping_start { tag = Some _; _ }
    | Sequence_start { tag = Some _; _ } ->
      Error (`Msg "explicit tags are unsupported")
    | _ -> consume documents
  in
  consume 0

(* Check recursively before any [List.assoc_opt]. Even a duplicate under an
   otherwise rejected/ignored field must not be interpreted first-wins by this
   reader while a downstream reader interprets it last-wins. *)
let rec check_unique_fields where (value : Yaml.value) =
  match value with
  | `O fields ->
    let seen = Hashtbl.create (List.length fields) in
    let rec check = function
      | [] -> Ok ()
      | (name, value) :: rest ->
        if name = "<<" then
          Error (where ^ ": YAML merge keys are unsupported")
        else if Hashtbl.mem seen name then
          Error (Printf.sprintf "%s: duplicate field %S" where name)
        else begin
          Hashtbl.add seen name ();
          let* () = check_unique_fields (where ^ "." ^ name) value in
          check rest
        end
    in
    check fields
  | `A values ->
    let rec check index = function
      | [] -> Ok ()
      | value :: rest ->
        let* () = check_unique_fields (Printf.sprintf "%s[%d]" where index) value in
        check (index + 1) rest
    in
    check 0 values
  | _ -> Ok ()

let digit = function '0' .. '9' -> true | _ -> false
let hex_digit = function
  | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true
  | _ -> false

let unsigned value =
  if String.length value > 0 && (value.[0] = '+' || value.[0] = '-') then
    String.sub value 1 (String.length value - 1)
  else value

(* A deliberately bounded grammar, checked before [float_of_string], whose own
   grammar is wider than Kong's. Decimal: optional sign, digits with an optional
   fraction (or a leading dot with digits), then an optional signed exponent;
   octal: sign? '0' [0-7]+; hexadecimal:
   sign? '0x' hex+. No separators, binary, sexagesimal, or hexadecimal floats.
   Ambiguous numeric-looking forms outside this subset are rejected, not guessed.

   Kong 3.9.3 pins LYAML 6.2.8. Its resolver tries octal BEFORE decimal and its
   bool table does NOT include y/Y/n/N. We use the raw scalar's style because
   quoted and block-style values remain strings in LYAML.
   https://github.com/gvvaughan/lyaml/blob/v6.2.8/lib/lyaml/implicit.lua
   https://github.com/gvvaughan/lyaml/blob/v6.2.8/lib/lyaml/init.lua#L62 *)
let decimal_literal value =
  let length = String.length value in
  let rec digits index =
    if index < length && digit value.[index] then digits (index + 1) else index
  in
  let start =
    if length > 0 && (value.[0] = '+' || value.[0] = '-') then 1 else 0
  in
  let integer_end = digits start in
  let fraction_end =
    if integer_end < length && value.[integer_end] = '.' then digits (integer_end + 1)
    else integer_end
  in
  let has_digits = integer_end > start || fraction_end > integer_end + 1 in
  if not has_digits then false
  else if fraction_end = length then true
  else if value.[fraction_end] = 'e' || value.[fraction_end] = 'E' then
    let exponent_start = fraction_end + 1 in
    let exponent_start =
      if exponent_start < length
         && (value.[exponent_start] = '+' || value.[exponent_start] = '-')
      then exponent_start + 1 else exponent_start
    in
    let finish = digits exponent_start in
    finish > exponent_start && finish = length
  else false

let prefixed_digits prefix test value =
  let length = String.length prefix in
  String.starts_with ~prefix value && String.length value > length
  && String.for_all test (String.sub value length (String.length value - length))

let sexagesimal_like value =
  match String.index_opt value ':' with
  | None | Some 0 -> false
  | Some separator ->
    String.for_all digit (String.sub value 0 separator)
    && String.for_all (fun c -> digit c || c = ':' || c = '.') value

let hex_float_like value =
  (String.starts_with ~prefix:"0x" value || String.starts_with ~prefix:"0X" value)
  && String.for_all
       (fun c -> hex_digit c || List.mem c [ 'x'; 'X'; '.'; 'p'; 'P'; '+'; '-' ])
       value

let plain_scalar where value =
  let number_value = unsigned value in
  let unsupported () =
    Error
      (Printf.sprintf
         "%s: unsupported plain numeric scalar %S; use an unseparated decimal number or quote intended text"
         where value)
  in
  let numeric_shape value =
    let value = unsigned value in
    decimal_literal value || hex_float_like value
    || prefixed_digits "0b" (fun c -> c = '0' || c = '1') value
    || prefixed_digits "0B" (fun c -> c = '0' || c = '1') value
    || sexagesimal_like value
  in
  match value with
  | "" | "~" | "null" | "Null" | "NULL" -> Ok `Null
  | "true" | "True" | "TRUE" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" ->
    Ok (`Bool true)
  | "false" | "False" | "FALSE" | "no" | "No" | "NO" | "off" | "Off" | "OFF" ->
    Ok (`Bool false)
  | ".nan" | ".NaN" | ".NAN" -> Ok (`Float nan)
  | ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" -> Ok (`Float infinity)
  | "-.inf" | "-.Inf" | "-.INF" -> Ok (`Float neg_infinity)
  | _ when String.contains value '_'
           && numeric_shape (String.concat "" (String.split_on_char '_' value)) ->
    unsupported ()
  | _ when String.length number_value > 1 && number_value.[0] = '0'
           && String.for_all (fun c -> c >= '0' && c <= '7') number_value ->
    let number =
      String.fold_left (fun number c -> number *. 8. +. float_of_int (Char.code c - Char.code '0'))
        0. number_value
    in
    Ok (`Float (if value.[0] = '-' then -. number else number))
  | _ when decimal_literal value || prefixed_digits "0x" hex_digit number_value ->
    (match float_of_string_opt value with
     | Some number -> Ok (`Float number)
     | None -> unsupported ())
  | _ when numeric_shape value -> unsupported ()
  | _ -> Ok (`String value)

let rec value_of_yaml where : Yaml.yaml -> (Yaml.value, string) result = function
  | `Scalar { style = `Plain; value; _ } -> plain_scalar where value
  | `Scalar { value; _ } -> Ok (`String value)
  | `Alias _ -> Error (where ^ ": YAML aliases are unsupported")
  | `A { s_members; _ } ->
    let rec convert index = function
      | [] -> Ok []
      | value :: rest ->
        let* value = value_of_yaml (Printf.sprintf "%s[%d]" where index) value in
        let* rest = convert (index + 1) rest in
        Ok (value :: rest)
    in
    let* values = convert 0 s_members in
    Ok (`A values)
  | `O { m_members; _ } ->
    let rec convert = function
      | [] -> Ok []
      | (key, value) :: rest ->
        let* key = value_of_yaml (where ^ " key") key in
        (match key with
         | `String key ->
           let* value = value_of_yaml (where ^ "." ^ key) value in
           let* rest = convert rest in
           Ok ((key, value) :: rest)
         | _ -> Error (where ^ ": mapping keys must be strings"))
    in
    let* fields = convert m_members in
    Ok (`O fields)

let yaml_value ~where source =
  match check_yaml_stream source with
  | Error (`Msg message) -> Error (where ^ " YAML: " ^ message)
  | Ok () ->
    (match Yaml.yaml_of_string source with
     | Error (`Msg message) -> Error (where ^ " YAML: " ^ message)
     | Ok raw ->
       let* value = value_of_yaml where raw in
       let* () = check_unique_fields where value in
       Ok value)

exception Invalid_config of string

let invalid where expected =
  raise (Invalid_config (where ^ " must be " ^ expected))

let object_at where = function
  | `O fields -> fields
  | _ -> invalid where "an object"

let string_at where = function
  | `String value when value <> "" -> ()
  | _ -> invalid where "a non-empty string"

let bool_at where = function
  | `Bool _ -> ()
  | _ -> invalid where "a boolean"

let array_at check where = function
  | `A values ->
    List.iteri (fun index value -> check (Printf.sprintf "%s[%d]" where index) value)
      values
  | _ -> invalid where "an array"

let field_at ?(nullable = true) check where name fields =
  match List.assoc_opt name fields with
  | None -> ()
  | Some `Null when nullable -> ()
  | Some value -> check (where ^ "." ^ name) value

(* Kong's integer validator requires a finite integral number; quoted numbers
   are strings, not integer fields. Check the OCaml conversion bounds as well:
   [float_of_int max_int] rounds up on 64-bit hosts and is not a safe <= bound. *)
let integer_at ?bounds where = function
  | `Float value
    when Float.is_finite value && Float.floor value = value ->
    if value < float_of_int min_int || value >= -. float_of_int min_int then
      raise (Invalid_config (where ^ " is outside Soundcheck's integer range"));
    (match bounds with
     | Some (minimum, maximum)
       when value < float_of_int minimum || value > float_of_int maximum ->
       raise
         (Invalid_config
            (Printf.sprintf "%s must be between %d and %d" where minimum maximum))
     | _ -> ())
  | _ -> invalid where "a finite integer"

let port_at = integer_at ~bounds:(0, 65535)
let string_array_at = array_at string_at

let headers_at where value =
  let fields = object_at where value in
  List.iter
    (fun (name, values) ->
      string_at (where ^ " header name") (`String name);
      string_array_at (where ^ "." ^ name) values)
    fields

let endpoint_at where value =
  let fields = object_at where value in
  field_at string_at where "ip" fields;
  field_at port_at where "port" fields;
  if List.for_all
       (fun name ->
         match List.assoc_opt name fields with None | Some `Null -> true | _ -> false)
       [ "ip"; "port" ]
  then raise (Invalid_config (where ^ " requires ip or port"))

(* Validate only modelled settings for their owning plugin. An unrelated custom
   plugin may legitimately use the same key with a different schema. *)
let plugin_at where value =
  let fields = object_at where value in
  let name =
    match List.assoc_opt "name" fields with
    | None -> raise (Invalid_config (where ^ ".name is required"))
    | Some value ->
      string_at (where ^ ".name") value;
      (match value with `String name -> name | _ -> assert false)
  in
  field_at ~nullable:false bool_at where "enabled" fields;
  field_at ~nullable:false
    (array_at (fun where value ->
       string_at where value;
       match value with
       | `String ("http" | "https" | "grpc" | "grpcs" | "tcp" | "tls" | "udp" | "tls_passthrough") -> ()
       | _ -> invalid where "a known Kong protocol"))
    where "protocols" fields;
  let config_at where value =
    let fields = object_at where value in
    (match name with
     | "ip-restriction" ->
       List.iter (fun key -> field_at string_array_at where key fields)
         [ "allow"; "deny" ]
     | "request-termination" -> field_at string_at where "trigger" fields
     | "key-auth" | "key-auth-enc" | "jwt" | "basic-auth" | "oauth2"
     | "hmac-auth" | "ldap-auth" | "ldap-auth-advanced" | "openid-connect"
     | "mtls-auth" ->
       field_at string_at where "anonymous" fields;
       if name = "key-auth" || name = "jwt" then
         field_at ~nullable:false bool_at where "run_on_preflight" fields
     | _ -> ())
  in
  field_at ~nullable:false config_at where "config" fields

let route_at where value =
  let fields = object_at where value in
  field_at string_at where "name" fields;
  List.iter (fun key -> field_at string_array_at where key fields)
    [ "paths"; "methods"; "hosts"; "snis" ];
  field_at ~nullable:false string_array_at where "protocols" fields;
  field_at headers_at where "headers" fields;
  List.iter (fun key -> field_at (array_at endpoint_at) where key fields)
    [ "sources"; "destinations" ];
  field_at ~nullable:false integer_at where "regex_priority" fields;
  field_at ~nullable:false bool_at where "strip_path" fields;
  field_at ~nullable:false string_at where "path_handling" fields;
  field_at (array_at plugin_at) where "plugins" fields

let service_at where value =
  let fields = object_at where value in
  field_at ~nullable:false bool_at where "enabled" fields;
  List.iter (fun key -> field_at string_at where key fields)
    [ "name"; "path" ];
  List.iter (fun key -> field_at ~nullable:false string_at where key fields)
    [ "url"; "protocol"; "host" ];
  field_at ~nullable:false port_at where "port" fields;
  field_at (array_at route_at) where "routes" fields;
  field_at (array_at plugin_at) where "plugins" fields

let check_structure value =
  try
    let fields = object_at "config" value in
    field_at ~nullable:false
      (fun where value ->
        string_at where value;
        match value with
        | `String ("1.1" | "2.1" | "3.0") -> ()
        | _ -> invalid where "one of \"1.1\", \"2.1\", or \"3.0\"")
      "config" "_format_version" fields;
    field_at (array_at service_at) "config" "services" fields;
    field_at (array_at route_at) "config" "routes" fields;
    field_at (array_at plugin_at) "config" "plugins" fields;
    List.iter
      (fun collection ->
        field_at
          (array_at (fun where value ->
             let fields = object_at where value in
             field_at (array_at plugin_at) where "plugins" fields))
          "config" collection fields)
      [ "consumers"; "consumer_groups" ];
    Ok ()
  with Invalid_config message -> Error message

(* --- helpers over Yaml.value ([`O]/[`A]/[`String]/...) --- *)

let member key (v : Yaml.value) : Yaml.value option =
  match v with `O kvs -> List.assoc_opt key kvs | _ -> None

let to_string = function `String s -> Some s | _ -> None

let string_list (v : Yaml.value option) : string list =
  match v with Some (`A xs) -> List.filter_map to_string xs | _ -> []

let headers_of (v : Yaml.value option) : (string * string list) list =
  match v with
  | Some (`O fields) ->
    List.map (fun (name, values) -> (name, string_list (Some values))) fields
  | _ -> []

(* Types have been checked before extraction. Only an absent [enabled] field
   uses Kong's true default; invalid values must not reach this point. *)
let enabled_of (v : Yaml.value) : bool =
  match member "enabled" v with Some (`Bool b) -> b | _ -> true

let bool_in key value ~default =
  match member key value with Some (`Bool boolean) -> boolean | _ -> default

let plugin_of x =
  match member "name" x with
  | Some (`String name) ->
    let cfg = member "config" x in
    let list_in key =
      match cfg with Some value -> string_list (member key value) | None -> []
    in
    Some
      ({ name; enabled = enabled_of x;
         protocols =
           (match member "protocols" x with
            | None -> [ "http"; "https" ]
            | value -> string_list value);
         has_relationships =
           List.exists
             (fun key ->
               match member key x with None | Some `Null -> false | Some _ -> true)
             [ "route"; "service"; "consumer"; "consumer_group" ];
         allow = list_in "allow"; deny = list_in "deny";
         trigger =
           (match cfg with
            | Some value -> Option.bind (member "trigger" value) to_string
            | None -> None);
         anonymous_fallback =
           (match cfg with
            | Some value ->
              (match member "anonymous" value with
               | None | Some `Null -> false
               | Some _ -> true)
            | None -> false);
         run_on_preflight =
           (match cfg with
            | Some value -> bool_in "run_on_preflight" value ~default:true
            | None -> true) }
        : Ast.plugin)
  | _ -> None

let plugins_of = function
  | Some (`A values) -> List.filter_map plugin_of values
  | _ -> []

let has_relationship value =
  List.exists
    (fun key ->
      match member key value with None | Some `Null -> false | Some _ -> true)
    [ "route"; "service"; "consumer"; "consumer_group" ]

let relationship_name key value =
  match member key value with
  | None | Some `Null -> (None, false)
  | Some (`String name) -> (Some name, false)
  | Some _ -> (None, true)

let relationship_present key value =
  match member key value with None | Some `Null -> false | Some _ -> true

let root_plugins_of = function
  | Some (`A values) ->
    List.fold_right
      (fun value (global, scoped) ->
        match plugin_of value with
        | None -> (global, scoped)
        | Some plugin when has_relationship value ->
          let service, unsupported_service =
            relationship_name "service" value
          in
          let route, unsupported_route = relationship_name "route" value in
          let scoped_plugin : Ast.scoped_plugin =
            { plugin;
              service;
              route;
              consumer_scoped =
                relationship_present "consumer" value
                || relationship_present "consumer_group" value;
              unsupported_reference =
                unsupported_service || unsupported_route }
          in
          (global, scoped_plugin :: scoped)
        | Some plugin -> (plugin :: global, scoped))
      values ([], [])
  | _ -> ([], [])

let name_of v ~default =
  match member "name" v with Some (`String s) -> s | _ -> default

(* YAML numbers arrive as floats; Kong's schema default is 0 when absent. *)
let int_field key v ~default =
  match member key v with
  | Some (`Float f) -> int_of_float f
  | _ -> default

let optional_int_field key v =
  match member key v with
  | Some (`Float f) -> Some (int_of_float f)
  | _ -> None

let optional_string_field key v = Option.bind (member key v) to_string

let route_of (v : Yaml.value) : Ast.route =
  {
    name = name_of v ~default:"<unnamed-route>";
    paths = string_list (member "paths" v);
    methods = string_list (member "methods" v);
    protocols =
      (match member "protocols" v with
       | None -> [ "http"; "https" ]
       | some -> string_list some);
    plugins = plugins_of (member "plugins" v);
    hosts = string_list (member "hosts" v);
    hosts_present = (match member "hosts" v with Some (`A _) -> true | _ -> false);
    snis = string_list (member "snis" v);
    headers = headers_of (member "headers" v);
    has_sources_or_destinations =
      (match (member "sources" v, member "destinations" v) with
       | Some (`A (_ :: _)), _ | _, Some (`A (_ :: _)) -> true
       | _ -> false);
    regex_priority = int_field "regex_priority" v ~default:0;
    strip_path = bool_in "strip_path" v ~default:true;
    path_handling =
      Option.value ~default:"v0" (optional_string_field "path_handling" v);
  }

let service_of (v : Yaml.value) : Ast.service =
  {
    name = name_of v ~default:"<unnamed-service>";
    enabled = enabled_of v;
    url = optional_string_field "url" v;
    protocol = optional_string_field "protocol" v;
    host = optional_string_field "host" v;
    port = optional_int_field "port" v;
    path = optional_string_field "path" v;
    routes =
      (match member "routes" v with Some (`A xs) -> List.map route_of xs | _ -> []);
    plugins = plugins_of (member "plugins" v);
  }

let top_level_route_of value : Ast.top_level_route =
  let service, unsupported_reference = relationship_name "service" value in
  { route = route_of value; service; unsupported_reference }

let config_of (v : Yaml.value) : Ast.config =
  let migrate_route (route : Ast.route) =
    match member "_format_version" v with
    | Some (`String ("1.1" | "2.1")) ->
      { route with paths = List.map Path_normalization.migrate_legacy_path route.paths }
    | _ -> route
  in
  let global_plugins, scoped_plugins = root_plugins_of (member "plugins" v) in
  (* Declarative nesting is a foreign-key scope, not an unrelated opaque entity.
     Consumers/credentials themselves remain outside the identity abstraction,
     but nested plugins must reach the existing fail-closed scope boundary. *)
  let consumer_plugins =
    [ "consumers"; "consumer_groups" ]
    |> List.concat_map (fun collection ->
         match member collection v with
         | Some (`A values) ->
           List.concat_map (fun value -> plugins_of (member "plugins" value)) values
         | _ -> [])
    |> List.map (fun plugin : Ast.scoped_plugin ->
         { plugin; service = None; route = None; consumer_scoped = true;
           unsupported_reference = false })
  in
  let scoped_plugins = scoped_plugins @ consumer_plugins in
  let top_level_routes =
    match member "routes" v with
    | Some (`A values) ->
      List.map
        (fun value ->
          let top = top_level_route_of value in
          { top with route = migrate_route top.route })
        values
    | _ -> []
  in
  let services =
    match member "services" v with
    | Some (`A values) ->
      List.map
        (fun value ->
          let service = service_of value in
          { service with routes = List.map migrate_route service.routes })
        values
    | _ -> []
  in
  let services =
    List.map
      (fun (service : Ast.service) ->
        let referenced_routes =
          List.filter_map
            (fun (top : Ast.top_level_route) ->
              if
                not top.unsupported_reference
                && top.service = Some service.name
              then Some top.route
              else None)
            top_level_routes
        in
        { service with routes = service.routes @ referenced_routes })
      services
  in
  {
    services;
    global_plugins;
    scoped_plugins;
    top_level_routes;
  }

let parse_string (s : string) : (Ast.config, string) result =
  let result =
    let* value = yaml_value ~where:"config" s in
    let* () = check_structure value in
    Ok (config_of value)
  in
  Result.map_error (fun message -> "invalid Kong config: " ^ message) result

(* Read a file to a string. File I/O is kept separate from parsing so adapters
   (the CLI) can read a path and hand the text to the shared {!Verify.run}, while
   {!parse_string} stays the entry for already-in-memory config (the MCP tool). *)
let read_file (path : string) : (string, string) result =
  try
    let ic = open_in_bin path in
    let n = in_channel_length ic in
    let s = really_input_string ic n in
    close_in ic;
    Ok s
  with Sys_error e -> Error e

let parse_file (path : string) : (Ast.config, string) result =
  match read_file path with Ok s -> parse_string s | Error e -> Error e
