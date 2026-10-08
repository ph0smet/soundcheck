type model = {
  path    : string;
  method_ : string;
  is_anon : bool;
  src_ip  : int32;
  host    : string;
  scheme  : string;
  sni     : string;
  headers : (string * string) list;
}

type result =
  | Proved
  | Violated of model
  | Unknown of string

let default_timeout = 10.

let version ?(z3 = "z3") ?(timeout = default_timeout) () =
  let ( let* ) = Result.bind in
  let* deadline = Solver_process.deadline timeout in
  let* output = Solver_process.run ~deadline z3 [ "-version" ] in
  let text = String.trim output in
  if String.starts_with ~prefix:"Z3 version " text
     && String.length text > String.length "Z3 version "
     && not (String.contains text '\n') && not (String.contains text '\r')
  then Ok text
  else Error ("could not determine Z3 version: " ^ text)

let write_file path text =
  let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () ->
      output_string channel text;
      close_out channel)

let decode_hex value =
  let digit = function
    | '0' .. '9' as c -> Some (Char.code c - Char.code '0')
    | 'a' .. 'f' as c -> Some (10 + Char.code c - Char.code 'a')
    | 'A' .. 'F' as c -> Some (10 + Char.code c - Char.code 'A')
    | _ -> None
  in
  let length = String.length value in
  if length mod 2 <> 0 then None
  else
    let output = Buffer.create (length / 2) in
    let rec loop index =
      if index = length then Some (Buffer.contents output)
      else
        match digit value.[index], digit value.[index + 1] with
        | Some high, Some low ->
          Buffer.add_char output (Char.chr ((high lsl 4) lor low));
          loop (index + 2)
        | _ -> None
    in
    loop 0

let model bindings =
  let open Solver_protocol in
  let malformed name = raise (Invalid ("missing or malformed model field: " ^ name)) in
  let string name =
    match List.assoc_opt name bindings with Some (String text) -> text | _ -> malformed name
  in
  let boolean name =
    match List.assoc_opt name bindings with
    | Some (Atom "true") -> true
    | Some (Atom "false") -> false
    | _ -> malformed name
  in
  let src_ip =
    match List.assoc_opt "src_ip" bindings with
    | Some (Atom value) ->
      let valid_digits base start =
        let rec check index =
          index = String.length value
          || ((match value.[index] with
               | '0' .. '1' -> true
               | '2' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> base = 16
               | _ -> false) && check (index + 1))
        in
        check start
      in
      let prefix =
        if String.length value = 10 && String.starts_with ~prefix:"#x" value
           && valid_digits 16 2 then "0x"
        else if String.length value = 34 && String.starts_with ~prefix:"#b" value
                && valid_digits 2 2 then "0b"
        else malformed "src_ip"
      in
      (try
         Int64.of_string (prefix ^ String.sub value 2 (String.length value - 2))
         |> Int64.to_int32
       with Failure _ -> malformed "src_ip")
    | _ -> malformed "src_ip"
  in
  let headers =
    List.filter_map
      (fun (name, _) ->
        if not (String.starts_with ~prefix:"header_" name) then None
        else
          let enabled = boolean name in
          let encoded = String.sub name 7 (String.length name - 7) in
          match String.index_opt encoded '_' with
          | None -> malformed name
          | Some separator ->
            let key = String.sub encoded 0 separator in
            let value =
              String.sub encoded (separator + 1) (String.length encoded - separator - 1)
            in
            (match decode_hex key, decode_hex value with
             | Some key, Some value -> if enabled then Some (key, value) else None
             | _ -> malformed name))
      bindings
    |> List.sort_uniq compare
  in
  (* SMT string escaping beyond doubled quotes, and validation of the lifted
     request against its obligation, remain separate semantic work. *)
  { path = string "path"; method_ = string "method"; is_anon = boolean "is_anon";
    src_ip; host = string "host"; scheme = string "scheme"; sni = string "sni";
    headers }

let check ?(z3 = "z3") ?(timeout = default_timeout) ?emit_smt smtlib =
  try
    Option.iter (fun path -> write_file path smtlib) emit_smt;
    let query = Solver_protocol.query smtlib in
    let run deadline text =
      let file = Filename.temp_file "soundcheck-solver-" ".smt2" in
      Fun.protect ~finally:(fun () -> Sys.remove file) (fun () ->
          write_file file text;
          Solver_process.run ~deadline z3 [ "-smt2"; file ])
    in
    let decode parse text =
      try Ok (parse text) with Solver_protocol.Invalid reason ->
        let excerpt = if String.length text <= 2048 then text
          else String.sub text 0 2048 ^ " [truncated]" in
        Error (reason ^ "; stdout: " ^ String.trim excerpt)
    in
    let ( let* ) = Result.bind in
    let result =
      let* deadline = Solver_process.deadline timeout in
      let* output = run deadline query.check in
      let* status = decode Solver_protocol.status output in
      match status with
      | `Unsat -> Ok Proved
      | `Unknown -> Ok (Unknown "solver returned unknown")
      | `Sat when query.observation = None -> Error "SAT without requested model values"
      | `Sat ->
        (* Replay the complete unchanged plan only once SAT establishes that
           the observation is applicable. Both processes share this deadline. *)
        let* output = run deadline smtlib in
        decode
          (fun text ->
            match Solver_protocol.response query.fields text with
            | `Sat bindings -> Violated (model bindings)
            | `Unsat -> Unknown "solver changed SAT to UNSAT during model replay"
            | `Unknown -> Unknown "solver returned unknown during model replay")
          output
    in
    match result with
    | Ok result -> result
    | Error reason -> Unknown reason
  with
  | Solver_protocol.Invalid reason -> Unknown ("unsupported SMT query: " ^ reason)
  | Sys_error reason -> Unknown reason
  | Unix.Unix_error (error, operation, argument) ->
    Unknown (Printf.sprintf "%s(%s): %s" operation argument (Unix.error_message error))

let string_of_result = function
  | Proved -> "PROVED (no violating request exists)"
  | Violated m ->
    Printf.sprintf
      "VIOLATED — counterexample: principal=%s method=%S path=%S"
      (if m.is_anon then "anonymous" else "authenticated")
      m.method_ m.path
  | Unknown s -> Printf.sprintf "UNKNOWN (%s)" s
