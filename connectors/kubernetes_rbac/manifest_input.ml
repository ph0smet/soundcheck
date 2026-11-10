(* Explicit preparation input only. Verification still reads Strict_json.
   Read the whole stream without YAML's float conversion or alias expansion. *)
open Input

type format = Json | Yaml
let format_name = function Json -> "json" | Yaml -> "yaml"

let decimal value =
  let length = String.length value in
  let start = if length > 0 && value.[0] = '-' then 1 else 0 in
  value = "0" || (start < length && value.[start] >= '1' && value.[start] <= '9'
    && String.for_all (function '0'..'9' -> true | _ -> false)
      (String.sub value start (length - start)))

(* Classify complete alternative numeric spellings, not arbitrary digit-leading
   text such as 100m, 1.2.3 or RFC3339 timestamps. Kubernetes strips underscores
   before trying its numeric resolvers. Reject instead of rounding or coercing. *)
let numeric_like value =
  let value = String.concat "" (String.split_on_char '_' value) in
  let length = String.length value in
  let start = if length > 0 && List.mem value.[0] ['+';'-'] then 1 else 0 in
  let tail = String.sub value start (length - start) in
  let based =
    if String.length tail < 3 || tail.[0] <> '0' then false else
    let digit = match tail.[1] with
      | 'x' | 'X' -> (function '0'..'9' | 'a'..'f' | 'A'..'F' -> true | _ -> false)
      | 'b' | 'B' -> (function '0' | '1' -> true | _ -> false)
      | 'o' | 'O' -> (function '0'..'7' -> true | _ -> false)
      | _ -> (fun _ -> false) in
    String.for_all digit (String.sub tail 2 (String.length tail - 2)) in
  (* go-yaml v2 also tries ParseInt after stripping a lowercase 0b prefix.
     That fallback surprisingly accepts a sign AFTER the prefix: 0b-1/0b+1.
     Do not let those target numbers become permission strings here. *)
  let binary_fallback =
    String.starts_with ~prefix:"0b" value && length > 3
    && List.mem value.[2] ['+';'-']
    && String.for_all (function '0'|'1' -> true | _ -> false)
      (String.sub value 3 (length - 3)) in
  let index = ref start in
  let digits () =
    let first = !index in
    while !index < length && value.[!index] >= '0' && value.[!index] <= '9' do incr index done;
    !index - first in
  let before = digits () in
  let after = if !index < length && value.[!index] = '.' then (incr index;digits ()) else 0 in
  let exponent =
    if !index < length && List.mem value.[!index] ['e';'E'] then begin
      incr index;
      if !index < length && List.mem value.[!index] ['+';'-'] then incr index;
      digits () > 0
    end else true in
  based || binary_fallback || ((before > 0 || after > 0) && exponent && !index = length)
  || List.mem value [".nan";".NaN";".NAN";".inf";".Inf";".INF";
    "+.inf";"+.Inf";"+.INF";"-.inf";"-.Inf";"-.INF"]

let plain path value : Strict_json.value =
  match value with
  | "" | "~" | "null" | "Null" | "NULL" -> `Null
  | "y" | "Y" | "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" -> `Bool true
  | "n" | "N" | "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" -> `Bool false
  | value when decimal value && Int64.of_string_opt value <> None -> `Number value
  | value when numeric_like value ->
    reject path "unsupported YAML numeric spelling or range; use canonical decimal int64, or quote intended text"
  | value -> `String value

(* libyaml marks count Unicode characters, not bytes. The OCaml binding reads
   scalar values as C strings and loses everything after a decoded NUL. Guard
   the original source span before trusting any double-quoted value. *)
let source_characters source =
  let buffer = Buffer.create (String.length source) and first = ref true in
  unicode_scalars "YAML input" source (fun scalar ->
    if scalar = 0 then reject "YAML input" "NUL characters are unsupported";
    if not (!first && scalar = 0xfeff) then
      Buffer.add_char buffer (if scalar < 128 then Char.chr scalar else '\255');
    first := false);
  Buffer.contents buffer

let check_quoted characters (position : Yaml.Stream.Event.pos) =
  let first = position.start_mark.index and stop = position.end_mark.index in
  if first < 0 || stop > String.length characters || first >= stop
     || characters.[first] <> '"' || characters.[stop - 1] <> '"' then
    reject "YAML input" "cannot validate double-quoted source span";
  let zeros index count = index + count <= stop - 1
    && String.for_all ((=) '0') (String.sub characters index count) in
  let rec scan index =
    if index < stop - 1 then
      if characters.[index] <> '\\' then scan (index + 1)
      else if index + 1 >= stop - 1 then reject "YAML input" "invalid quoted escape"
      else begin
        let nul = match characters.[index + 1] with
          | '0' -> true | 'x' -> zeros (index + 2) 2
          | 'u' -> zeros (index + 2) 4 | 'U' -> zeros (index + 2) 8 | _ -> false in
        if nul then reject "YAML input" "NUL escapes are unsupported";
        scan (index + 2)
      end in
  scan (first + 1)

let yaml source =
  let characters = source_characters source in
  let unwrap = function Ok value -> value | Error (`Msg reason) -> reject "YAML input" reason in
  let parser = unwrap (Yaml.Stream.parser source) in
  let open Yaml.Stream.Event in
  let next () =
    let event,position =
      try unwrap (Yaml.Stream.do_parse parser)
      with Invalid_argument _ -> reject "YAML input" "unsupported YAML directive" in
    (match event with
     | Scalar {anchor=Some _;_} | Mapping_start {anchor=Some _;_}
     | Sequence_start {anchor=Some _;_} | Alias _ -> reject "YAML input" "anchors and aliases are unsupported"
     | Scalar {tag=Some _;_} | Mapping_start {tag=Some _;_}
     | Sequence_start {tag=Some _;_} -> reject "YAML input" "explicit tags are unsupported"
     | Scalar {style=`Double_quoted;_} -> check_quoted characters position
     | Document_start {version=Some `V1_2;_} -> reject "YAML input" "only YAML 1.1 resolution is supported"
     | _ -> ());
    event,position in
  let nodes = ref 0 in
  let rec node depth path (event,_) : Strict_json.value =
    incr nodes;
    if depth > 128 then reject path "YAML nesting exceeds limit of 128";
    if !nodes > 250000 then reject path "YAML node count exceeds 250000";
    match event with
    | Scalar scalar -> if scalar.style = `Plain then plain path scalar.value else `String scalar.value
    | Sequence_start _ ->
      let rec items index acc = match next () with
        | Sequence_end,_ -> `A (List.rev acc)
        | event ->
          let value = node (depth + 1) (Printf.sprintf "%s[%d]" path index) event in
          items (index + 1) (value :: acc) in
      items 0 []
    | Mapping_start _ ->
      let seen = Hashtbl.create 16 in
      let rec fields acc = match next () with
        | Mapping_end,_ -> `O (List.rev acc)
        | event ->
          let key = match node (depth + 1) path event with
            | `String key -> key
            | _ -> reject path "YAML mapping keys must be strings (quote intended text)" in
          if key = "<<" then reject path "YAML merge keys are unsupported";
          if Hashtbl.mem seen key then reject path ("duplicate field " ^ key);
          Hashtbl.add seen key ();
          let value = node (depth + 1) (path ^ "." ^ key) (next ()) in
          fields ((key,value) :: acc) in
      fields []
    | _ -> reject path "expected YAML value" in
  (match next () with Stream_start {encoding=`Utf8},_ -> ()
    | _ -> reject "YAML input" "expected UTF-8 stream");
  let rec documents index acc = match next () with
    | Stream_end,_ -> List.rev acc
    | Document_start _,_ ->
      if index >= 4096 then reject "YAML input" "document count exceeds 4096";
      let event,position = next () in
      let empty = match event with
        | Scalar {style=`Plain;value="";_} -> position.start_mark.index = position.end_mark.index
        | _ -> false in
      let value = node 0 (Printf.sprintf "documents[%d]" index) (event,position) in
      (match next () with Document_end _,_ -> () | _ -> reject "YAML input" "expected document end");
      documents (index + 1) ((if empty then None else Some value) :: acc)
    | _ -> reject "YAML input" "expected document start" in
  documents 0 []

let parse format source =
  if String.length source > 16 * 1024 * 1024 then reject "input" "exceeds 16 MiB limit";
  match format with Json -> [Some (Input.parse source)] | Yaml -> yaml source
