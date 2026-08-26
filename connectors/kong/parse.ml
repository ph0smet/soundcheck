(* Parse a decK YAML document into {!Ast.config} using the [yaml] library.
   Unknown keys are ignored; missing keys default to empty. *)

(* --- helpers over Yaml.value ([`O]/[`A]/[`String]/...) --- *)

let member key (v : Yaml.value) : Yaml.value option =
  match v with `O kvs -> List.assoc_opt key kvs | _ -> None

let to_string = function `String s -> Some s | _ -> None

let string_list (v : Yaml.value option) : string list =
  match v with Some (`A xs) -> List.filter_map to_string xs | _ -> []

(* Kong treats a plugin as enabled unless it says otherwise, so an absent or
   non-boolean [enabled] key means true. Only an explicit [false] disables. *)
let enabled_of (v : Yaml.value) : bool =
  match member "enabled" v with Some (`Bool b) -> b | _ -> true

let plugins_of (v : Yaml.value option) : Ast.plugin list =
  match v with
  | Some (`A xs) ->
    List.filter_map
      (fun x ->
        match member "name" x with
        | Some (`String n) -> Some ({ name = n; enabled = enabled_of x } : Ast.plugin)
        | _ -> None)
      xs
  | _ -> []

let name_of v ~default =
  match member "name" v with Some (`String s) -> s | _ -> default

(* YAML numbers arrive as floats; Kong's schema default is 0 when absent. *)
let int_field key v ~default =
  match member key v with
  | Some (`Float f) -> int_of_float f
  | Some (`String s) -> (try int_of_string (String.trim s) with _ -> default)
  | _ -> default

let route_of (v : Yaml.value) : Ast.route =
  {
    name = name_of v ~default:"<unnamed-route>";
    paths = string_list (member "paths" v);
    methods = string_list (member "methods" v);
    plugins = plugins_of (member "plugins" v);
    regex_priority = int_field "regex_priority" v ~default:0;
  }

let service_of (v : Yaml.value) : Ast.service =
  {
    name = name_of v ~default:"<unnamed-service>";
    routes =
      (match member "routes" v with Some (`A xs) -> List.map route_of xs | _ -> []);
    plugins = plugins_of (member "plugins" v);
  }

let config_of (v : Yaml.value) : Ast.config =
  {
    services =
      (match member "services" v with
       | Some (`A xs) -> List.map service_of xs
       | _ -> []);
  }

let parse_string (s : string) : (Ast.config, string) result =
  match Yaml.of_string s with
  | Ok v -> Ok (config_of v)
  | Error (`Msg m) -> Error m

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
