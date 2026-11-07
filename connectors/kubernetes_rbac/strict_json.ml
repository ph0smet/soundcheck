(* Deliberately JSON-only. No C-string parser boundary and no YAML coercions. *)
type value =
  [ `Null | `Bool of bool | `Number of string | `String of string
  | `A of value list | `O of (string * value) list ]

exception Error of string

let parse source : value =
  let pos = ref 0 and size = String.length source in
  let error message =
    raise (Error (Printf.sprintf "JSON byte %d: %s" !pos message))
  in
  let peek () = if !pos < size then Some source.[!pos] else None in
  let take expected =
    if peek () <> Some expected then error (Printf.sprintf "expected %C" expected);
    incr pos
  in
  let whitespace () =
    while !pos < size && List.mem source.[!pos] [ ' '; '\t'; '\r'; '\n' ] do
      incr pos
    done
  in
  let valid_utf8 s =
    let n = String.length s in
    let rec scan i =
      if i < n then (
        let a = Char.code s.[i] in
        let count, initial, minimum =
          if a < 0x80 then (1, a, 0)
          else if a >= 0xc2 && a <= 0xdf then (2, a land 0x1f, 0x80)
          else if a >= 0xe0 && a <= 0xef then (3, a land 0x0f, 0x800)
          else if a >= 0xf0 && a <= 0xf4 then (4, a land 0x07, 0x10000)
          else error "invalid UTF-8 leading byte"
        in
        if i + count > n then error "truncated UTF-8";
        let scalar = ref initial in
        for j = i + 1 to i + count - 1 do
          let c = Char.code s.[j] in
          if c land 0xc0 <> 0x80 then error "invalid UTF-8 continuation";
          scalar := (!scalar lsl 6) lor (c land 0x3f)
        done;
        if !scalar < minimum || !scalar > 0x10ffff
           || (!scalar >= 0xd800 && !scalar <= 0xdfff)
        then error "invalid Unicode scalar";
        scan (i + count))
    in
    scan 0
  in
  let emit_utf8 buffer scalar =
    let byte n = Buffer.add_char buffer (Char.chr n) in
    if scalar < 0x80 then byte scalar
    else if scalar < 0x800 then (
      byte (0xc0 lor (scalar lsr 6));
      byte (0x80 lor (scalar land 0x3f)))
    else if scalar < 0x10000 then (
      byte (0xe0 lor (scalar lsr 12));
      byte (0x80 lor ((scalar lsr 6) land 0x3f));
      byte (0x80 lor (scalar land 0x3f)))
    else (
      byte (0xf0 lor (scalar lsr 18));
      byte (0x80 lor ((scalar lsr 12) land 0x3f));
      byte (0x80 lor ((scalar lsr 6) land 0x3f));
      byte (0x80 lor (scalar land 0x3f)))
  in
  let hex4 () =
    let result = ref 0 in
    for _ = 1 to 4 do
      let digit = match peek () with
        | Some ('0' .. '9' as c) -> Char.code c - Char.code '0'
        | Some ('a' .. 'f' as c) -> Char.code c - Char.code 'a' + 10
        | Some ('A' .. 'F' as c) -> Char.code c - Char.code 'A' + 10
        | _ -> error "expected four hexadecimal digits after \\u"
      in
      incr pos;
      result := (!result lsl 4) lor digit
    done;
    !result
  in
  let string () =
    take '"';
    let buffer = Buffer.create 32 in
    let rec chars () =
      match peek () with
      | None -> error "unterminated string"
      | Some '"' ->
          incr pos;
          let result = Buffer.contents buffer in
          valid_utf8 result;
          result
      | Some '\\' ->
          incr pos;
          (match peek () with
           | Some ('"' | '\\' | '/' as c) -> incr pos; Buffer.add_char buffer c
           | Some 'b' -> incr pos; Buffer.add_char buffer '\b'
           | Some 'f' -> incr pos; Buffer.add_char buffer '\012'
           | Some 'n' -> incr pos; Buffer.add_char buffer '\n'
           | Some 'r' -> incr pos; Buffer.add_char buffer '\r'
           | Some 't' -> incr pos; Buffer.add_char buffer '\t'
           | Some 'u' ->
               incr pos;
               let first = hex4 () in
               let scalar =
                 if first >= 0xd800 && first <= 0xdbff then (
                   take '\\'; take 'u';
                   let second = hex4 () in
                   if second < 0xdc00 || second > 0xdfff then
                     error "high surrogate must be followed by a low surrogate";
                   0x10000 + ((first - 0xd800) lsl 10) + second - 0xdc00)
                 else if first >= 0xdc00 && first <= 0xdfff then
                   error "unpaired low surrogate"
                 else first
               in
               emit_utf8 buffer scalar
           | _ -> error "invalid JSON escape");
          chars ()
      | Some c ->
          if Char.code c < 0x20 then error "unescaped control character in string";
          incr pos;
          Buffer.add_char buffer c;
          chars ()
    in
    chars ()
  in
  let digit = function Some ('0' .. '9') -> true | _ -> false in
  let digits () =
    if not (digit (peek ())) then error "expected digit";
    while digit (peek ()) do incr pos done
  in
  let number () =
    let start = !pos in
    if peek () = Some '-' then incr pos;
    (match peek () with
     | Some '0' -> incr pos
     | Some ('1' .. '9') -> digits ()
     | _ -> error "invalid JSON number");
    if peek () = Some '.' then (incr pos; digits ());
    if peek () = Some 'e' || peek () = Some 'E' then (
      incr pos;
      if peek () = Some '+' || peek () = Some '-' then incr pos;
      digits ());
    (* Keep the exact token: schema versions cannot round to 1 through a float. *)
    `Number (String.sub source start (!pos - start))
  in
  let keyword spelling value =
    String.iter take spelling;
    value
  in
  let rec value depth =
    if depth > 128 then error "JSON nesting exceeds profile limit of 128";
    whitespace ();
    match peek () with
    | Some '"' -> `String (string ())
    | Some 'n' -> keyword "null" `Null
    | Some 't' -> keyword "true" (`Bool true)
    | Some 'f' -> keyword "false" (`Bool false)
    | Some ('-' | '0' .. '9') -> number ()
    | Some '[' ->
        incr pos; whitespace ();
        if peek () = Some ']' then (incr pos; `A [])
        else
          let rec elements reversed =
            let item = value (depth + 1) in
            whitespace ();
            match peek () with
            | Some ']' -> incr pos; `A (List.rev (item :: reversed))
            | Some ',' -> incr pos; elements (item :: reversed)
            | _ -> error "expected array comma or closing bracket"
          in
          elements []
    | Some '{' ->
        incr pos; whitespace ();
        if peek () = Some '}' then (incr pos; `O [])
        else
          let seen = Hashtbl.create 8 in
          let rec members reversed =
            whitespace ();
            let key = string () in
            if Hashtbl.mem seen key then error "duplicate object key";
            Hashtbl.add seen key ();
            whitespace (); take ':';
            let item = value (depth + 1) in
            whitespace ();
            match peek () with
            | Some '}' -> incr pos; `O (List.rev ((key, item) :: reversed))
            | Some ',' -> incr pos; members ((key, item) :: reversed)
            | _ -> error "expected object comma or closing brace"
          in
          members []
    | _ -> error "expected JSON value"
  in
  let result = value 0 in
  whitespace ();
  if !pos <> size then error "trailing data after the JSON document";
  result
