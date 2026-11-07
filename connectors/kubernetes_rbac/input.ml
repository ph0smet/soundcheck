exception Unsupported of string
let reject path message = raise (Unsupported (path ^ ": " ^ message))
let group = "rbac.authorization.k8s.io"
let api_version = group ^ "/v1"

(* Read Unicode scalar values, rejecting malformed or noncanonical UTF-8. *)
let unicode_scalars path s f =
  let length = String.length s in
  let rec go i =
    if i < length then (
      let byte j = Char.code s.[j] in
      let a = byte i in
      let count, initial, minimum =
        if a < 0x80 then (1, a, 0)
        else if a >= 0xc2 && a <= 0xdf then (2, a land 0x1f, 0x80)
        else if a >= 0xe0 && a <= 0xef then (3, a land 0x0f, 0x800)
        else if a >= 0xf0 && a <= 0xf4 then (4, a land 0x07, 0x10000)
        else reject path "invalid UTF-8"
      in
      if i + count > length then reject path "truncated UTF-8";
      let value = ref initial in
      for j = i + 1 to i + count - 1 do
        let b = byte j in
        if b land 0xc0 <> 0x80 then reject path "invalid UTF-8 continuation";
        value := (!value lsl 6) lor (b land 0x3f)
      done;
      if !value < minimum || !value > 0x10ffff
         || (!value >= 0xd800 && !value <= 0xdfff)
      then reject path "invalid Unicode scalar";
      f !value;
      go (i + count))
  in
  go 0

let obj path allowed = function
  | `O fields ->
      let seen = Hashtbl.create (List.length fields) in
      List.iter
        (fun (key, _) ->
          if Hashtbl.mem seen key then reject path ("duplicate field " ^ key);
          Hashtbl.add seen key ();
          if not (List.mem key allowed) then
            reject path ("unsupported field " ^ key))
        fields;
      fields
  | _ -> reject path "expected object"

let field path key fields =
  match List.assoc_opt key fields with
  | Some value -> value
  | None -> reject path ("missing field " ^ key)

let str path = function
  | `String value ->
      unicode_scalars path value (fun _ -> ());
      value
  | _ -> reject path "expected string"

let string_field path key fields = str (path ^ "." ^ key) (field path key fields)
let optional_string path key fields =
  match List.assoc_opt key fields with
  | None -> ""
  | Some value -> str (path ^ "." ^ key) value

let arr path = function
  | `A values -> values
  | _ -> reject path "expected array"

let strings path value =
  arr path value |> List.mapi (fun i -> str (Printf.sprintf "%s[%d]" path i))

let optional_list path key fields =
  match List.assoc_opt key fields with
  | None | Some `Null -> []
  | Some value -> arr (path ^ "." ^ key) value

let optional_strings path key fields =
  optional_list path key fields
  |> List.mapi (fun i -> str (Printf.sprintf "%s.%s[%d]" path key i))

let require_equal path actual expected =
  if actual <> expected then reject path ("expected " ^ expected)

let nonempty path value =
  if value = "" then reject path "must not be empty";
  value

let alnum = function 'a' .. 'z' | '0' .. '9' -> true | _ -> false
let dns_part s =
  let n = String.length s in
  n > 0 && alnum s.[0] && alnum s.[n - 1]
  && String.for_all (fun c -> alnum c || c = '-') s

let dns_label s = String.length s <= 63 && dns_part s
let dns_subdomain s =
  String.length s <= 253 && s <> ""
  && List.for_all dns_part (String.split_on_char '.' s)

let namespace path s =
  if not (dns_label s) then reject path "expected DNS1123 label, 1..63 characters";
  s

(* RBAC object names are path segments, not DNS labels. *)
let rbac_name path s =
  ignore (nonempty path s);
  if s = "." || s = ".." || String.contains s '/' || String.contains s '%'
  then reject path "invalid RBAC path-segment name";
  if String.exists (fun c -> Char.code c < 0x20 || Char.code c = 0x7f) s then
    reject path "control bytes in RBAC names are outside this profile";
  s

let string_map path = function
  | `O fields ->
      let seen = Hashtbl.create (List.length fields) in
      List.iter
        (fun (key, value) ->
          unicode_scalars path key (fun _ -> ());
          if Hashtbl.mem seen key then reject path ("duplicate field " ^ key);
          Hashtbl.add seen key ();
          ignore (str (path ^ "." ^ key) value))
        fields
  | _ -> reject path "expected string map"

let qualified_part s =
  let alnum c = alnum (Char.lowercase_ascii c) in
  let n = String.length s in
  n > 0 && n <= 63 && alnum s.[0] && alnum s.[n - 1]
  && String.for_all (fun c -> alnum c || List.mem c ['-'; '_'; '.']) s

let qualified_name s =
  match String.split_on_char '/' s with
  | [name] -> qualified_part name
  | [prefix; name] -> dns_subdomain prefix && qualified_part name
  | _ -> false

(* Validate every accepted metadata field against the pinned API's constraints.
   Other ObjectMeta fields stay unsupported; API validation is not delegated to
   a future cluster apply or merely inferred from the conformance samples. *)
let metadata_map path ~annotations value =
  string_map path value;
  let fields = match value with `O fields -> fields | _ -> assert false in
  let size = ref 0 in
  List.iter (fun (key, value) ->
      let value = str path value in
      let checked_key = if annotations then String.lowercase_ascii key else key in
      if not (qualified_name checked_key) then reject path "invalid qualified metadata key";
      if not annotations && value <> "" && not (qualified_part value) then
        reject path "invalid label value";
      size := !size + String.length key + String.length value) fields;
  if annotations && !size > 256 * 1024 then reject path "annotations exceed 256 KiB"


let parse source =
  if String.length source > 16 * 1024 * 1024 then reject "input" "exceeds 16 MiB limit";
  try Strict_json.parse source with Strict_json.Error reason -> reject "input" reason

let protect f = try Ok (f ()) with Unsupported reason -> Error reason

let json_string value =
  let buffer = Buffer.create (String.length value + 2) in
  Buffer.add_char buffer '"';
  String.iter (function
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | c when Char.code c < 0x20 ->
        Buffer.add_string buffer (Printf.sprintf "\\u%04x" (Char.code c))
      | c -> Buffer.add_char buffer c) value;
  Buffer.add_char buffer '"'; Buffer.contents buffer

let rec json : Strict_json.value -> string = function
  | `Null -> "null"
  | `Bool true -> "true" | `Bool false -> "false"
  | `Number n -> n
  | `String s -> json_string s
  | `A values -> "[" ^ String.concat "," (List.map json values) ^ "]"
  | `O fields ->
    "{" ^ String.concat "," (List.map (fun (key,value) -> json_string key ^ ":" ^ json value) fields) ^ "}"
