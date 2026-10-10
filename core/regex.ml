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
  | Any                                  (* any byte, including newline *)
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

(* Syntax that cannot be recovered from the language AST. Connectors may need
   a narrower target-compatible subset than this byte-oriented parser. *)
type syntax = {
  shorthand_classes : char list;
  named_captures : string list;
  angle_named_captures : int;
  max_group_depth : int;
  expansion_cost : int;
}

exception Unsupported of string

let unsupported fmt = Printf.ksprintf (fun s -> raise (Unsupported s)) fmt

(* A saturating syntax cost, not a target-specific compilation-size estimate.
   Carry it through parsing so groups erased from [t], including their names,
   remain counted inside numeric repetitions. *)
let add_cost a b = if a > max_int - b then max_int else a + b
let multiply_cost a b =
  if a = 0 || b = 0 then 0 else if a > max_int / b then max_int else a * b

let measured_leaf re =
  let cost = match re with
    | Empty | Any -> 1
    | Lit s -> max 1 (String.length s)
    | Class (_, ranges) -> add_cost 1 (multiply_cost 2 (List.length ranges))
    | _ -> unsupported "internal non-leaf regex atom"
  in
  (re, cost)

let measured_sequence constructor values =
  (constructor (List.map fst values),
   List.fold_left (fun total (_, cost) -> add_cost total cost) 1 values)

(* --- parser (recursive descent) --- *)

let parse_exn (input : string) : parsed * syntax =
  (* Strip anchors up front, so the scanner below sees a pure pattern. A leading
     [^] is redundant (the caller already anchors the start) and a trailing
     unescaped [$] becomes the [anchored_end] flag. *)
  let input = if String.length input > 0 && input.[0] = '^'
              then String.sub input 1 (String.length input - 1) else input in
  let ln = String.length input in
  let rec preceding_backslashes i count =
    if i >= 0 && input.[i] = '\\' then preceding_backslashes (i - 1) (count + 1)
    else count
  in
  let src, anchored_end =
    if ln > 0 && input.[ln - 1] = '$'
       && preceding_backslashes (ln - 2) 0 mod 2 = 0
    then (String.sub input 0 (ln - 1), true)
    else (input, false)
  in
  let n = String.length src in
  let pos = ref 0 in
  let peek () = if !pos < n then Some src.[!pos] else None in
  let eat () = let c = src.[!pos] in incr pos; c in
  let accept c = if !pos < n && src.[!pos] = c then (incr pos; true) else false in
  let shorthand_classes = ref [] in
  let named_captures = ref [] in
  let angle_named_captures = ref 0 in
  let depth = ref 0 in
  let max_group_depth = ref 0 in
  let is_digit c = c >= '0' && c <= '9' in
  let is_alpha c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') in

  let shorthand = function
    | 'd' -> Some [ ('0', '9') ]
    | 'w' -> Some [ ('a', 'z'); ('A', 'Z'); ('0', '9'); ('_', '_') ]
    | 's' -> Some [ (' ', ' '); ('\t', '\t'); ('\n', '\n'); ('\011', '\011');
                    ('\012', '\012'); ('\r', '\r') ]
    | _ -> None
  in
  let negated_shorthand c =
    match Char.lowercase_ascii c with
    | ('d' | 'w' | 's') when c >= 'A' && c <= 'Z' -> shorthand (Char.lowercase_ascii c)
    | _ -> None
  in

  let hex_digit = function
    | '0' .. '9' as c -> Some (Char.code c - Char.code '0')
    | 'a' .. 'f' as c -> Some (Char.code c - Char.code 'a' + 10)
    | 'A' .. 'F' as c -> Some (Char.code c - Char.code 'A' + 10)
    | _ -> None
  in
  let parse_hex () =
    let digit () =
      match peek () with
      | Some c -> (match hex_digit c with
          | Some value -> incr pos; value
          | None -> unsupported "expected a hexadecimal digit in \\x escape")
      | None -> unsupported "incomplete \\x escape"
    in
    if accept '{' then begin
      let lo = digit () in
      let value = if accept '}' then lo else begin
        let value = (lo * 16) + digit () in
        if not (accept '}') then
          unsupported "braced \\x escape must contain one or two hex digits (one byte)";
        value
      end in
      Char.chr value
    end else
      let hi = digit () in
      let lo = digit () in
      Char.chr ((hi * 16) + lo)
  in
  let parse_escape () =
    if !pos >= n then unsupported "trailing backslash";
    let c = eat () in
    match shorthand c with
    | Some rs ->
      shorthand_classes := c :: !shorthand_classes;
      Class (false, rs)
    | None -> (
      match negated_shorthand c with
      | Some rs ->
        shorthand_classes := c :: !shorthand_classes;
        Class (true, rs)
      | None -> (match c with
        | 'a' -> Lit "\007"
        | 'f' -> Lit "\012"
        | 'n' -> Lit "\n"
        | 'r' -> Lit "\r"
        | 't' -> Lit "\t"
        | 'x' -> Lit (String.make 1 (parse_hex ()))
        | '1' .. '9' ->
          unsupported "backreference \\%c is not a regular language" c
        | ('b' | 'B' | 'A' | 'z' | 'Z' | 'G' | '<' | '>') ->
          unsupported "zero-width assertion \\%c" c
        | _ when c >= ' ' && c <= '~' && not (is_alpha c || is_digit c) ->
          Lit (String.make 1 c)
        | _ -> unsupported "unsupported escaped byte %C" c))
  in

  let parse_class () =
    let negated = accept '^' in
    let ranges = ref [] in
    let first = ref true in
    let class_item () =
      (* Rust gives these pairs set-operation semantics whereas PCRE does not.
         Likewise '[' introduces nested/POSIX syntax, not a literal here. *)
      if !pos + 1 < n && src.[!pos] = src.[!pos + 1]
         && String.contains "&-~" src.[!pos] then
        unsupported "character-class set operations are unsupported";
      if accept '\\' then
        match parse_escape () with
        | Lit s -> `Char s.[0]
        | Class (false, rs) -> `Ranges rs
        | Class (true, _) -> unsupported "negated shorthand inside a character class"
        | _ -> unsupported "unsupported character-class atom"
      else if accept '[' then
        unsupported "nested and POSIX character classes are unsupported"
      else if !pos >= n then unsupported "unterminated character class"
      else `Char (eat ())
    in
    let range_follows () =
      (* Check BEFORE consuming a range separator: otherwise the first '-' of
         '--' can disappear into a PCRE range, hiding Rust's set difference. *)
      if !pos + 1 < n && src.[!pos] = '-' && src.[!pos + 1] = '-' then
        unsupported "character-class set operations are unsupported";
      !pos + 1 < n && src.[!pos] = '-' && src.[!pos + 1] <> ']'
    in
    let rec go () =
      if !pos >= n then unsupported "unterminated character class";
      if src.[!pos] = ']' && not !first then incr pos
      else begin
        let raw_initial_closing = !first && src.[!pos] = ']' in
        first := false;
        let item = class_item () in
        (match item with
         | `Ranges rs ->
           if range_follows () then
             unsupported "character-class range endpoints must be single characters";
           ranges := List.rev_append rs !ranges
         | `Char lo ->
           if range_follows () then begin
             if raw_initial_closing then
               unsupported "a range starting with ] requires an escaped endpoint \\]";
             incr pos;
             let hi = match class_item () with
               | `Char c -> c
               | `Ranges _ ->
                 unsupported "character-class range endpoints must be single characters"
             in
             if Char.code hi < Char.code lo then
               unsupported "reversed range %C-%C in character class" lo hi;
             ranges := (lo, hi) :: !ranges
           end
           else ranges := (lo, lo) :: !ranges);
        go ()
      end
    in
    go ();
    Class (negated, List.rev !ranges)
  in

  let parse_group_name () =
    let start = !pos in
    while !pos < n && src.[!pos] <> '>' do incr pos done;
    let name = String.sub src start (!pos - start) in
    if not (accept '>') then unsupported "unterminated group name";
    if String.length name = 0 || String.length name > 128
       || not (is_alpha name.[0] || name.[0] = '_')
       || not (String.for_all (fun c -> is_alpha c || is_digit c || c = '_') name)
    then unsupported "capture name must be an ASCII identifier of 1 to 128 characters";
    if List.mem name !named_captures then unsupported "duplicate capture name %S" name;
    named_captures := name :: !named_captures;
    String.length name
  in

  let rec parse_alt ~top_level =
    let branches = ref [ parse_concat () ] in
    while accept '|' do
      if top_level then
        unsupported "top-level alternation requires an explicit enclosing group";
      branches := parse_concat () :: !branches
    done;
    match !branches with
    | [ one ] -> one
    | many -> measured_sequence (fun values -> Alt values) (List.rev many)

  and parse_concat () =
    let items = ref [] in
    let rec go () =
      match peek () with
      | None | Some '|' | Some ')' -> ()
      | Some _ -> items := parse_repeat () :: !items; go ()
    in
    go ();
    match !items with
    | [] -> measured_leaf Empty
    | [ one ] -> one
    | many -> measured_sequence (fun values -> Concat values) (List.rev many)

  and parse_repeat () =
    let atom, cost = parse_atom () in
    let quantified =
      match peek () with
      | Some '*' -> incr pos; Some (Star atom, add_cost 1 cost)
      | Some '+' -> incr pos; Some (Plus atom, add_cost 1 cost)
      | Some '?' -> incr pos; Some (Opt atom, add_cost 1 cost)
      | Some '{' -> Some (parse_brace atom cost)
      | _ -> None
    in
    match quantified with
    | None -> (atom, cost)
    | Some q ->
      (* A following [?] is LAZY: same language, so accept it. A following [+] is
         POSSESSIVE: different language, so refuse. *)
      if accept '?' then q
      else if !pos < n && src.[!pos] = '+' then
        unsupported "possessive quantifier changes the accepted language"
      else q

  and parse_brace atom cost =
    (* PCRE's literal-brace fallback is not shared by other engines. Reject it.
       The 65535 limit is PCRE2's numeric repeat limit, not an OCaml int limit. *)
    incr pos;
    let digits () =
      let start = !pos in
      while !pos < n && is_digit src.[!pos] do
        incr pos
      done;
      if start = !pos then None
      else match int_of_string_opt (String.sub src start (!pos - start)) with
        | Some count when count <= 65535 -> Some count
        | _ -> unsupported "repetition count exceeds the supported maximum of 65535"
    in
    let lo = match digits () with
      | Some count -> count
      | None -> unsupported "repetition requires a decimal lower bound"
    in
    let hi = if accept ',' then digits () else Some lo in
    if not (accept '}') then unsupported "malformed or unterminated repetition";
    (match hi with
     | Some hi when hi < lo -> unsupported "reversed repetition {%d,%d}" lo hi
     | _ -> ());
    let copies = match hi with Some hi -> max 1 hi | None -> lo + 1 in
    (Repeat (atom, lo, hi), add_cost 1 (multiply_cost copies cost))

  and parse_atom () =
    match peek () with
    | None -> measured_leaf Empty
    | Some '(' ->
      incr pos;
      incr depth;
      max_group_depth := max !max_group_depth !depth;
      (* Keep recursion bounded independently of OCaml's available stack. *)
      if !depth > 250 then unsupported "group nesting exceeds the supported maximum of 250";
      let name_cost = ref 0 in
      let read_name () = name_cost := parse_group_name () in
      if accept '?' then begin
        match peek () with
        | Some ':' -> incr pos
        | Some '>' -> unsupported "atomic group (?>...) changes the accepted language"
        | Some '=' -> unsupported "lookahead (?=...)"
        | Some '!' -> unsupported "lookahead (?!...)"
        | Some 'P' -> incr pos;
          if accept '<' then read_name () else unsupported "unsupported (?P group"
        | Some '<' -> incr pos;
          (match peek () with
           | Some '=' -> unsupported "lookbehind (?<=...)"
           | Some '!' -> unsupported "lookbehind (?<!...)"
           | _ -> incr angle_named_captures; read_name ())
        | _ -> unsupported "unsupported group modifier"
      end;
      let inner, cost = parse_alt ~top_level:false in
      if not (accept ')') then unsupported "unbalanced (";
      decr depth;
      (inner, add_cost 1 (add_cost !name_cost cost))
    | Some '[' -> incr pos; measured_leaf (parse_class ())
    | Some '.' -> incr pos; measured_leaf (Class (true, [ ('\n', '\n') ]))
    | Some '\\' -> incr pos; measured_leaf (parse_escape ())
    | Some '^' -> unsupported "^ anchor in the middle of a pattern"
    | Some '$' -> unsupported "$ anchor in the middle of a pattern"
    | Some ')' -> unsupported "unbalanced )"
    | Some ('*' | '+' | '?' | '{') -> unsupported "quantifier with nothing to repeat"
    | Some '}' -> unsupported "unescaped closing repetition brace"
    | Some _ -> measured_leaf (Lit (String.make 1 (eat ())))
  in

  let re, expansion_cost = parse_alt ~top_level:true in
  if !pos <> n then unsupported "unexpected %C" src.[!pos];
  ({ re; anchored_end },
   { shorthand_classes = List.rev !shorthand_classes;
     named_captures = List.rev !named_captures;
     angle_named_captures = !angle_named_captures;
     max_group_depth = !max_group_depth;
     expansion_cost })

let parse_with_syntax src =
  try Ok (parse_exn src) with
  | Unsupported why -> Error why
  | Stack_overflow -> Error "regular expression exceeds parser resource limits"

let parse (src : string) : (parsed, string) result =
  Result.map fst (parse_with_syntax src)

(* --- SMT-LIB2 translation --- *)

let smt_string = Solver_protocol.encode_string

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
