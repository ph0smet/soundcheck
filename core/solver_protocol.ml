(* Framing only, not an SMT evaluator. Keep strings, comments, quoted symbols,
   and top-level command boundaries distinct so no assertion can be discarded
   when the terminal model observation is withheld after UNSAT or UNKNOWN. *)

type sexp = Atom of string | String of string | List of sexp list
type located = { value : sexp; stop : int }
exception Invalid of string

let whitespace = function ' ' | '\t' | '\r' | '\n' -> true | _ -> false

let parse text =
  let length = String.length text in
  let rec skip index =
    if index = length then index
    else if whitespace text.[index] then skip (index + 1)
    else if text.[index] = ';' then
      match String.index_from_opt text index '\n' with
      | None -> length
      | Some next -> skip (next + 1)
    else index
  in
  let rec value depth index =
    if depth > 512 then raise (Invalid "SMT nesting exceeds the supported limit");
    if index >= length then raise (Invalid "unexpected end of SMT expression");
    match text.[index] with
    | '(' ->
      let rec elements index found =
        let index = skip index in
        if index = length then raise (Invalid "unterminated SMT list")
        else if text.[index] = ')' then (List (List.rev found), index + 1)
        else
          let item, next = value (depth + 1) index in
          elements next (item :: found)
      in
      elements (index + 1) []
    | ')' -> raise (Invalid "unexpected closing SMT parenthesis")
    | '"' ->
      let buffer = Buffer.create 32 in
      let rec string index =
        if index = length then raise (Invalid "unterminated SMT string")
        else if text.[index] = '"' then
          if index + 1 < length && text.[index + 1] = '"' then begin
            Buffer.add_char buffer '"'; string (index + 2)
          end else (String (Buffer.contents buffer), index + 1)
        else begin Buffer.add_char buffer text.[index]; string (index + 1) end
      in
      string (index + 1)
    | '|' ->
      (match String.index_from_opt text (index + 1) '|' with
       | None -> raise (Invalid "unterminated quoted SMT symbol")
       | Some finish -> (Atom (String.sub text index (finish - index + 1)), finish + 1))
    | _ ->
      let rec end_atom next =
        if next = length || whitespace text.[next]
           || List.mem text.[next] [ '('; ')'; ';'; '"'; '|' ] then next
        else end_atom (next + 1)
      in
      let finish = end_atom index in
      if finish = index then raise (Invalid "invalid SMT atom");
      (Atom (String.sub text index (finish - index)), finish)
  in
  let rec values index found =
    let start = skip index in
    if start = length then List.rev found
    else
      let item, stop = value 0 start in
      values stop ({ value = item; stop } :: found)
  in
  values 0 []

type query = { check : string; observation : string option; fields : string list }

let query text =
  let commands = parse text in
  let check, fields, observation, preceding =
    match List.rev commands with
    | { value = List [ Atom "get-value"; List fields ]; _ }
      :: ({ value = List [ Atom "check-sat" ]; _ } as check) :: preceding ->
      let fields =
        List.map (function Atom name -> name | _ ->
            raise (Invalid "get-value must request named request fields")) fields
      in
      if fields = [] || List.sort_uniq String.compare fields <> List.sort String.compare fields
      then raise (Invalid "get-value must request nonempty, distinct fields");
      (check, fields,
       Some (String.sub text check.stop (String.length text - check.stop)), preceding)
    | ({ value = List [ Atom "check-sat" ]; _ } as check) :: preceding ->
      (check, [], None, preceding)
    | _ -> raise (Invalid "expected one terminal check-sat with an optional get-value")
  in
  List.iter
    (fun command ->
      match command.value with
      | List (Atom ("check-sat" | "check-sat-assuming" | "get-value" | "get-model" | "exit") :: _) ->
        raise (Invalid "multiple checks or nonterminal solver observations are unsupported")
      | List (Atom name :: _) when String.starts_with ~prefix:"|" name ->
        raise (Invalid "quoted top-level SMT command names are unsupported")
      | List (Atom _ :: _) -> ()
      | _ -> raise (Invalid "expected an SMT command"))
    preceding;
  { check = String.sub text 0 check.stop ^ "\n"; observation; fields }

let status text =
  match parse text |> List.map (fun item -> item.value) with
  | [ Atom "sat" ] -> `Sat
  | [ Atom "unsat" ] -> `Unsat
  | [ Atom "unknown" ] -> `Unknown
  | _ -> raise (Invalid "invalid solver status response")

let response fields text =
  match parse text |> List.map (fun item -> item.value) with
  | [ Atom "unsat" ] -> `Unsat
  | [ Atom "unknown" ] -> `Unknown
  | [ Atom "sat"; List values ] ->
    let bindings =
      List.map
        (function List [ Atom name; value ] -> (name, value)
          | _ -> raise (Invalid "malformed get-value binding"))
        values
    in
    let names = List.map fst bindings |> List.sort String.compare in
    if fields = [] || names <> List.sort String.compare fields then
      raise (Invalid "get-value reply has missing, duplicate, or unexpected fields");
    `Sat bindings
  | _ -> raise (Invalid "unexpected or malformed solver response")
