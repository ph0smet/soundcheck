type model = {
  path    : string;
  method_ : string;
  is_anon : bool;
  src_ip  : int32;
  host    : string;
}

type result =
  | Proved
  | Violated of model
  | Unknown of string

let run_capture (cmd : string) : string =
  let ic = Unix.open_process_in cmd in
  let b = Buffer.create 256 in
  (try
     while true do
       Buffer.add_string b (input_line ic);
       Buffer.add_char b '\n'
     done
   with End_of_file -> ());
  ignore (Unix.close_process_in ic);
  Buffer.contents b

let write_file path s =
  let oc = open_out path in
  output_string oc s;
  close_out oc

(* --- tiny SMT-LIB2 (get-value ...) output parser ------------------------- *)

let find_sub hay needle =
  let hl = String.length hay and nl = String.length needle in
  let rec go i =
    if i + nl > hl then None
    else if String.sub hay i nl = needle then Some i
    else go (i + 1)
  in
  go 0

let skip_ws hay i =
  let n = String.length hay in
  let rec go i =
    if i < n && (hay.[i] = ' ' || hay.[i] = '\n' || hay.[i] = '\t') then go (i + 1)
    else i
  in
  go i

(* Parse an SMT-LIB2 string literal starting at the opening quote [start].
   A doubled quote ("") denotes a literal quote. *)
let parse_quoted hay start =
  let n = String.length hay in
  let b = Buffer.create 16 in
  let rec go i =
    if i >= n then Buffer.contents b
    else if hay.[i] = '"' then
      if i + 1 < n && hay.[i + 1] = '"' then (Buffer.add_char b '"'; go (i + 2))
      else Buffer.contents b
    else (Buffer.add_char b hay.[i]; go (i + 1))
  in
  go (start + 1)

let extract_string hay key =
  let tag = "(" ^ key ^ " " in
  match find_sub hay tag with
  | None -> None
  | Some i ->
    let j = skip_ws hay (i + String.length tag) in
    if j < String.length hay && hay.[j] = '"' then Some (parse_quoted hay j)
    else None

let extract_bool hay key =
  let tag = "(" ^ key ^ " " in
  match find_sub hay tag with
  | None -> None
  | Some i ->
    let j = skip_ws hay (i + String.length tag) in
    let n = String.length hay in
    if j + 4 <= n && String.sub hay j 4 = "true" then Some true
    else if j + 5 <= n && String.sub hay j 5 = "false" then Some false
    else None

(* A bitvector value from [get-value]. z3 prints these as #x0a000001 or, for
   widths that are not a multiple of four, #b0101... — both are handled. *)
let extract_bv hay key =
  let tag = "(" ^ key ^ " " in
  match find_sub hay tag with
  | None -> None
  | Some i ->
    let j = skip_ws hay (i + String.length tag) in
    let n = String.length hay in
    if j + 2 < n && hay.[j] = '#' && (hay.[j + 1] = 'x' || hay.[j + 1] = 'b') then begin
      let base = if hay.[j + 1] = 'x' then 16 else 2 in
      let k = ref (j + 2) in
      let acc = ref 0L in
      let digit c =
        if c >= '0' && c <= '9' then Some (Char.code c - Char.code '0')
        else if c >= 'a' && c <= 'f' then Some (Char.code c - Char.code 'a' + 10)
        else if c >= 'A' && c <= 'F' then Some (Char.code c - Char.code 'A' + 10)
        else None
      in
      let ok = ref true in
      while !k < n && (match digit hay.[!k] with
                       | Some d when d < base -> acc := Int64.add (Int64.mul !acc (Int64.of_int base)) (Int64.of_int d); true
                       | _ -> false) do incr k done;
      if !k = j + 2 then ok := false;
      if !ok then Some (Int64.to_int32 !acc) else None
    end
    else None

(* Is the first non-whitespace token exactly [word]? *)
let first_token_is hay word =
  let i = skip_ws hay 0 in
  let n = String.length hay and wl = String.length word in
  i + wl <= n && String.sub hay i wl = word

(* With [emit_smt] the query is written to that path and KEPT, so the proof
   obligation survives the run as an inspectable artifact: it is plain SMT-LIB2
   and can be re-checked by any solver that speaks it, independently of us.
   Without it we use a temp file and clean up. *)
let check ?(z3 = "z3") ?emit_smt (smtlib : string) : result =
  let file, keep =
    match emit_smt with
    | Some path -> (path, true)
    | None -> (Filename.temp_file "soundcheck" ".smt2", false)
  in
  write_file file smtlib;
  let cmd = Printf.sprintf "%s -smt2 %s" (Filename.quote z3) (Filename.quote file) in
  let out = run_capture cmd in
  if not keep then (try Sys.remove file with _ -> ());
  if first_token_is out "unsat" then Proved
  else if first_token_is out "sat" then
    let path = Option.value ~default:"" (extract_string out "path") in
    let method_ = Option.value ~default:"" (extract_string out "method") in
    let is_anon = Option.value ~default:false (extract_bool out "is_anon") in
    let src_ip = Option.value ~default:0l (extract_bv out "src_ip") in
    let host = Option.value ~default:"" (extract_string out "host") in
    Violated { path; method_; is_anon; src_ip; host }
  else Unknown (String.trim out)

let string_of_result = function
  | Proved -> "PROVED (no violating request exists)"
  | Violated m ->
    Printf.sprintf
      "VIOLATED — counterexample: principal=%s method=%S path=%S"
      (if m.is_anon then "anonymous" else "authenticated")
      m.method_ m.path
  | Unknown s -> Printf.sprintf "UNKNOWN (%s)" s
