(* A small regular-expression AST, its parser, its SMT-LIB translation, and a
   concrete matcher.

   WHY AN AST OF OUR OWN, rather than handing patterns to a regex library:
   verification needs the SAME language understood by two engines — the SMT
   encoder (symbolic) and {!matches_full} (concrete, used to validate
   counterexamples). If one side were a PCRE library and the other SMT-LIB
   regexes, every corner of PCRE semantics would be a place the two could silently
   disagree, and a disagreement here is a wrong verdict. Parsing into an AST we
   define shrinks the agreement surface to this one file, where it can be tested
   directly against the solver.

   THE SUPPORTED SUBSET is deliberately the plainly-regular core: literals, [.],
   character classes, [? * +], bounded repetition, alternation, grouping. Anything
   whose language is not regular, or whose translation we are not sure of, is
   REJECTED by {!parse} with a reason — never approximated:

   - Backreferences ([\1]) recognise non-regular languages. Permanently out.
   - Possessive quantifiers ([a*+]) and atomic groups ([(?>...)]) genuinely CHANGE
     THE ACCEPTED LANGUAGE — not merely which match is found ([a*+a] never matches
     "aa"). Treating them as greedy would quietly alter a route's meaning.
   - Lookaround ([(?=...)]) is regular in principle but needs intersection and
     complement gymnastics; out until it earns the risk.

   LAZY quantifiers ([a*?]) ARE accepted and treated as greedy: they change which
   match is found, never whether one exists, and membership is all we ask. *)

type t =
  | Empty                                (* matches only the empty string *)
  | Any                                  (* [.] *)
  | Lit of string                        (* a literal run of characters *)
  | Class of bool * (char * char) list   (* negated?, ranges — [a-z0-9], [^/] *)
  | Concat of t list
  | Alt of t list
  | Star of t
  | Plus of t
  | Opt of t
  | Repeat of t * int * int option       (* {n}, {n,}, {n,m} *)

(* [anchored_end] records a trailing [$] in the PATTERN. Whether the pattern must
   also cover the rest of the subject is the caller's business (for Kong it does
   not — see the connector), so anchoring is reported separately rather than baked
   into the AST, which stays a pure language. *)
type parsed = { re : t; anchored_end : bool }

exception Unsupported of string

let unsupported fmt = Printf.ksprintf (fun s -> raise (Unsupported s)) fmt

(* --- parser (recursive descent) --- *)

let parse_exn (input : string) : parsed =
  (* Strip anchors up front, so the scanner below sees a pure pattern. A leading
     [^] is redundant (the caller already anchors the start) and a trailing
     unescaped [$] becomes the [anchored_end] flag. *)
  let input = if String.length input > 0 && input.[0] = '^'
              then String.sub input 1 (String.length input - 1) else input in
  let ln = String.length input in
  let src, anchored_end =
    if ln > 0 && input.[ln - 1] = '$' && not (ln > 1 && input.[ln - 2] = '\\')
    then (String.sub input 0 (ln - 1), true)
    else (input, false)
  in
  let n = String.length src in
  let pos = ref 0 in
  let peek () = if !pos < n then Some src.[!pos] else None in
  let eat () = let c = src.[!pos] in incr pos; c in
  let accept c = if !pos < n && src.[!pos] = c then (incr pos; true) else false in

  let shorthand = function
    | 'd' -> Some [ ('0', '9') ]
    | 'w' -> Some [ ('a', 'z'); ('A', 'Z'); ('0', '9'); ('_', '_') ]
    | 's' -> Some [ (' ', ' '); ('\t', '\t'); ('\n', '\n'); ('\r', '\r');
                    ('\012', '\012') ]
    | _ -> None
  in
  let negated_shorthand c =
    match Char.lowercase_ascii c with
    | ('d' | 'w' | 's') when c >= 'A' && c <= 'Z' -> shorthand (Char.lowercase_ascii c)
    | _ -> None
  in

  let parse_escape () =
    if !pos >= n then unsupported "trailing backslash";
    let c = eat () in
    match shorthand c with
    | Some rs -> Class (false, rs)
    | None -> (
      match negated_shorthand c with
      | Some rs -> Class (true, rs)
      | None ->
        if c >= '1' && c <= '9' then
          unsupported "backreference \\%c is not a regular language" c
        else if String.contains "bBAzZG" c then
          unsupported "zero-width assertion \\%c" c
        else Lit (String.make 1 c))
  in

  let parse_class () =
    let negated = accept '^' in
    let ranges = ref [] in
    let first = ref true in
    let rec go () =
      if !pos >= n then unsupported "unterminated character class";
      if src.[!pos] = ']' && not !first then incr pos
      else begin
        first := false;
        let item =
          if accept '\\' then begin
            if !pos >= n then unsupported "trailing backslash in character class";
            let c = eat () in
            match shorthand c with
            | Some rs -> `Ranges rs
            | None -> (
              match negated_shorthand c with
              | Some _ -> unsupported "negated shorthand \\%c inside a class" c
              | None -> `Char c)
          end
          else `Char (eat ())
        in
        (match item with
         | `Ranges rs -> ranges := List.rev_append rs !ranges
         | `Char lo ->
           if !pos + 1 < n && src.[!pos] = '-' && src.[!pos + 1] <> ']' then begin
             incr pos;
             let hi = if accept '\\' then
                        (if !pos >= n then unsupported "trailing backslash" else eat ())
                      else eat () in
             if Char.code hi < Char.code lo then
               unsupported "reversed range %c-%c in character class" lo hi;
             ranges := (lo, hi) :: !ranges
           end
           else ranges := (lo, lo) :: !ranges);
        go ()
      end
    in
    go ();
    Class (negated, List.rev !ranges)
  in

  let skip_group_name () =
    while !pos < n && src.[!pos] <> '>' do incr pos done;
    if not (accept '>') then unsupported "unterminated group name"
  in

  let rec parse_alt () =
    let branches = ref [ parse_concat () ] in
    while accept '|' do branches := parse_concat () :: !branches done;
    match !branches with [ one ] -> one | many -> Alt (List.rev many)

  and parse_concat () =
    let items = ref [] in
    let rec go () =
      match peek () with
      | None | Some '|' | Some ')' -> ()
      | Some _ -> items := parse_repeat () :: !items; go ()
    in
    go ();
    match !items with [] -> Empty | [ one ] -> one | many -> Concat (List.rev many)

  and parse_repeat () =
    let atom = parse_atom () in
    let quantified =
      match peek () with
      | Some '*' -> incr pos; Some (Star atom)
      | Some '+' -> incr pos; Some (Plus atom)
      | Some '?' -> incr pos; Some (Opt atom)
      | Some '{' -> parse_brace atom
      | _ -> None
    in
    match quantified with
    | None -> atom
    | Some q ->
      (* A following [?] is LAZY: same language, so accept it. A following [+] is
         POSSESSIVE: different language, so refuse. *)
      if accept '?' then q
      else if !pos < n && src.[!pos] = '+' then
        unsupported "possessive quantifier changes the accepted language"
      else q

  and parse_brace atom =
    (* Only a well-formed {n}, {n,} or {n,m} is a quantifier; anything else is a
       literal brace, as PCRE treats it. *)
    let save = !pos in
    incr pos;
    let digits () =
      let b = Buffer.create 4 in
      while !pos < n && src.[!pos] >= '0' && src.[!pos] <= '9' do
        Buffer.add_char b (eat ())
      done;
      Buffer.contents b
    in
    let lo = digits () in
    if lo = "" then (pos := save; None)
    else
      let hi =
        if accept ',' then
          let h = digits () in
          if h = "" then Some None else Some (Some (int_of_string h))
        else Some (Some (int_of_string lo))
      in
      match hi with
      | Some h when accept '}' ->
        let lo = int_of_string lo in
        (match h with
         | Some hi when hi < lo -> unsupported "reversed repetition {%d,%d}" lo hi
         | _ -> ());
        Some (Repeat (atom, lo, h))
      | _ -> pos := save; None

  and parse_atom () =
    match peek () with
    | None -> Empty
    | Some '(' ->
      incr pos;
      if accept '?' then begin
        match peek () with
        | Some ':' -> incr pos
        | Some '>' -> unsupported "atomic group (?>...) changes the accepted language"
        | Some '=' -> unsupported "lookahead (?=...)"
        | Some '!' -> unsupported "lookahead (?!...)"
        | Some 'P' -> incr pos;
          if accept '<' then skip_group_name () else unsupported "unsupported (?P group"
        | Some '<' -> incr pos;
          (match peek () with
           | Some '=' -> unsupported "lookbehind (?<=...)"
           | Some '!' -> unsupported "lookbehind (?<!...)"
           | _ -> skip_group_name ())
        | _ -> unsupported "unsupported group modifier"
      end;
      let inner = parse_alt () in
      if not (accept ')') then unsupported "unbalanced (";
      inner
    | Some '[' -> incr pos; parse_class ()
    | Some '.' -> incr pos; Any
    | Some '\\' -> incr pos; parse_escape ()
    | Some '^' -> unsupported "^ anchor in the middle of a pattern"
    | Some '$' -> unsupported "$ anchor in the middle of a pattern"
    | Some ')' -> unsupported "unbalanced )"
    | Some ('*' | '+') -> unsupported "quantifier with nothing to repeat"
    | Some _ -> Lit (String.make 1 (eat ()))
  in

  let re = parse_alt () in
  if !pos <> n then unsupported "unexpected %C" src.[!pos];
  { re; anchored_end }

let parse (src : string) : (parsed, string) result =
  try Ok (parse_exn src) with Unsupported why -> Error why

(* --- SMT-LIB2 translation --- *)

let smt_string s =
  let b = Buffer.create (String.length s + 2) in
  Buffer.add_char b '"';
  String.iter
    (fun c -> if c = '"' then Buffer.add_string b "\"\"" else Buffer.add_char b c)
    s;
  Buffer.add_char b '"';
  Buffer.contents b

(* [re.union] and [re.++] are binary-or-more in SMT-LIB, so a singleton list must
   collapse to the element itself and an empty one to the identity. *)
let nary op identity = function
  | [] -> identity
  | [ x ] -> x
  | xs -> Printf.sprintf "(%s %s)" op (String.concat " " xs)

let rec to_smt (r : t) : string =
  match r with
  | Empty -> "(str.to_re \"\")"
  | Any -> "re.allchar"
  | Lit s -> Printf.sprintf "(str.to_re %s)" (smt_string s)
  | Class (false, rs) -> class_union rs
  | Class (true, rs) -> Printf.sprintf "(re.diff re.allchar %s)" (class_union rs)
  | Concat rs -> nary "re.++" "(str.to_re \"\")" (List.map to_smt rs)
  | Alt rs -> nary "re.union" "re.none" (List.map to_smt rs)
  | Star r -> Printf.sprintf "(re.* %s)" (to_smt r)
  | Plus r -> Printf.sprintf "(re.+ %s)" (to_smt r)
  | Opt r -> Printf.sprintf "(re.opt %s)" (to_smt r)
  | Repeat (r, lo, Some hi) ->
    Printf.sprintf "((_ re.loop %d %d) %s)" lo hi (to_smt r)
  | Repeat (r, lo, None) ->
    (* {n,} has no direct form: n copies followed by a star. *)
    Printf.sprintf "(re.++ ((_ re.loop %d %d) %s) (re.* %s))" lo lo (to_smt r)
      (to_smt r)

and class_union rs =
  nary "re.union" "re.none"
    (List.map
       (fun (lo, hi) ->
         if lo = hi then Printf.sprintf "(str.to_re %s)" (smt_string (String.make 1 lo))
         else
           Printf.sprintf "(re.range %s %s)" (smt_string (String.make 1 lo))
             (smt_string (String.make 1 hi)))
       rs)

(* --- concrete matcher ---
   Continuation-passing so alternation and repetition can backtrack. [k] receives
   the index reached; the whole string must be consumed for a full match. *)
let matches_full (r : t) (s : string) : bool =
  let len = String.length s in
  let rec go r i (k : int -> bool) =
    match r with
    | Empty -> k i
    | Any -> i < len && k (i + 1)
    | Lit l ->
      let n = String.length l in
      i + n <= len && String.sub s i n = l && k (i + n)
    | Class (negated, ranges) ->
      i < len
      && (let c = s.[i] in
          let inside = List.exists (fun (lo, hi) -> lo <= c && c <= hi) ranges in
          if negated then not inside else inside)
      && k (i + 1)
    | Concat rs ->
      let rec seq rs i = match rs with [] -> k i | r :: tl -> go r i (fun j -> seq tl j) in
      seq rs i
    | Alt rs -> List.exists (fun r -> go r i k) rs
    | Opt r -> go r i k || k i
    | Star r -> star r i k
    | Plus r -> go r i (fun j -> star r j k)
    | Repeat (r, lo, hi) -> repeat r lo hi 0 i k
  (* The [j > i] guard stops a nullable body (e.g. [(a?)*]) looping forever. *)
  and star r i k = k i || go r i (fun j -> j > i && star r j k)
  and repeat r lo hi count i k =
    let may_stop = count >= lo in
    let may_continue = match hi with None -> true | Some h -> count < h in
    (may_stop && k i)
    || (may_continue
        && go r i (fun j -> (j > i || count < lo) && repeat r lo hi (count + 1) j k))
  in
  go r 0 (fun i -> i = len)
