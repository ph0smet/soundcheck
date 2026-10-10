open Soundcheck_core

let reserved = "!*'();:@&=+$,/?%#[]"

let hex_value = function
  | '0' .. '9' as c -> Some (Char.code c - Char.code '0')
  | 'a' .. 'f' as c -> Some (10 + Char.code c - Char.code 'a')
  | 'A' .. 'F' as c -> Some (10 + Char.code c - Char.code 'A')
  | _ -> None

let normalize_percent path =
  let length = String.length path in
  let output = Buffer.create length in
  let rec loop index =
    if index >= length then ()
    else if path.[index] = '%' && index + 2 < length then
      match hex_value path.[index + 1], hex_value path.[index + 2] with
      | Some high, Some low ->
        let decoded = Char.chr ((high lsl 4) lor low) in
        if String.contains reserved decoded then
          Buffer.add_string output (Printf.sprintf "%%%02X" (Char.code decoded))
        else
          Buffer.add_char output decoded;
        loop (index + 3)
      | _ ->
        Buffer.add_char output path.[index];
        loop (index + 1)
    else begin
      Buffer.add_char output path.[index];
      loop (index + 1)
    end
  in
  loop 0;
  Buffer.contents output

let normalize_literal path =
  let path = normalize_percent path in
  let absolute = String.starts_with ~prefix:"/" path in
  let trailing =
    String.ends_with ~suffix:"/" path
    || String.ends_with ~suffix:"/." path
    || String.ends_with ~suffix:"/.." path
  in
  let segments = String.split_on_char '/' path in
  let normalized =
    List.fold_left
      (fun stack segment ->
        match segment with
        | "" | "." -> stack
        | ".." -> (match stack with [] -> [] | _ :: rest -> rest)
        | value -> value :: stack)
      [] segments
    |> List.rev
  in
  let body = String.concat "/" normalized in
  let base = if absolute then "/" ^ body else body in
  if trailing && base <> "" && base <> "/" then base ^ "/"
  else if base = "" && absolute then "/"
  else base

(* Kong 3.9.3 declarative/migrations/route_path.lua migrates explicit 1.1/2.1
   input before routing. This is migrate_path_280_300's bounded path transform:
   ordinary paths receive URI normalization, implicit regex paths get '~' and
   one final percent decode with metacharacters escaped. Modern route regexes
   do NOT receive this transformation. *)
let migrate_legacy_path path =
  let plain = function
    | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9'
    | '.' | '-' | '_' | '~' | '/' | '%' -> true
    | _ -> false
  in
  (* The migration's PCRE '$' also accepts one final LF. Preserve that exact
     classification; a second LF is not accepted by its plain-character class. *)
  let plain_path =
    String.for_all plain path
    || (String.ends_with ~suffix:"\n" path
        && String.for_all plain (String.sub path 0 (String.length path - 1)))
  in
  if plain_path then normalize_literal path
  else
    let output = Buffer.create (String.length path + 1) in
    Buffer.add_char output '~';
    let rec loop index =
      if index >= String.length path then ()
      else if path.[index] = '%' && index + 2 < String.length path then
        match hex_value path.[index + 1], hex_value path.[index + 2] with
        | Some high, Some low ->
          let decoded = Char.chr ((high lsl 4) lor low) in
          if String.contains reserved decoded then
            Buffer.add_string output (Printf.sprintf "%%%02X" (Char.code decoded))
          else begin
            if String.contains ".^-{}\\|" decoded then Buffer.add_char output '\\';
            Buffer.add_char output decoded
          end;
          loop (index + 3)
        | _ -> Buffer.add_char output path.[index]; loop (index + 1)
      else begin
        Buffer.add_char output path.[index];
        loop (index + 1)
      end
    in
    loop 0;
    Buffer.contents output

let has_valid_percent_encoding path =
  let length = String.length path in
  let rec loop index =
    if index >= length then true
    else if path.[index] <> '%' then loop (index + 1)
    else
      index + 2 < length
      && Option.is_some (hex_value path.[index + 1])
      && Option.is_some (hex_value path.[index + 2])
      && loop (index + 3)
  in
  loop 0

let is_normalized_literal path =
  String.starts_with ~prefix:"/" path
  && has_valid_percent_encoding path
  && normalize_literal path = path

let reserved_percent =
  reserved
  |> String.to_seq
  |> List.of_seq
  |> List.map (fun character ->
         Regex.Lit (Printf.sprintf "%%%02X" (Char.code character)))
  |> fun alternatives -> Regex.Alt alternatives

let non_dot_token =
  Regex.Alt
    [ Regex.Class (true, [ ('/', '/'); ('%', '%'); ('.', '.') ]);
      reserved_percent ]

let token = Regex.Alt [ Regex.Lit "."; non_dot_token ]

let segment =
  Regex.Alt
    [ Regex.Concat [ non_dot_token; Regex.Star token ];
      Regex.Concat [ Regex.Lit "."; non_dot_token; Regex.Star token ];
      Regex.Concat [ Regex.Lit ".."; token; Regex.Star token ] ]

let request_path_language =
  Regex.Alt
    [ Regex.Lit "/";
      Regex.Concat
        [ Regex.Lit "/";
          segment;
          Regex.Star (Regex.Concat [ Regex.Lit "/"; segment ]);
          Regex.Opt (Regex.Lit "/") ] ]

let request_domain = Ir.Path_regex request_path_language

let is_normalized_request_path path =
  Regex.matches_full request_path_language path
