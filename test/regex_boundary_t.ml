(* These expectations come from the pinned PCRE2 10.44 and Rust regex 1.11.1
   syntax/semantics, not from agreement between two readers of our own AST.
   See Regex_boundary for the narrower language shared by Kong's two flavors. *)
open Soundcheck_core
open Soundcheck_kong

let failures = ref 0

let check label condition =
  if not condition then begin
    incr failures;
    Printf.eprintf "[FAIL] %s\n%!" label
  end

let parsed pattern f =
  match Regex.parse pattern with
  | Ok value -> f value
  | Error why -> check (Printf.sprintf "parse %S: %s" pattern why) false
  | exception exn ->
    check (Printf.sprintf "parse %S raised %s" pattern (Printexc.to_string exn)) false

let member pattern subject expected =
  parsed pattern (fun value ->
    check (Printf.sprintf "%S on %S = %b" pattern subject expected)
      (Regex.matches_full value.re subject = expected))

let rejected pattern =
  match Regex.parse pattern with
  | Error _ -> ()
  | Ok _ -> check (Printf.sprintf "reject %S" pattern) false
  | exception exn ->
    check (Printf.sprintf "reject %S raised %s" pattern (Printexc.to_string exn)) false

let common pattern expected =
  match Regex_boundary.parse pattern with
  | Ok _ -> check (Printf.sprintf "common-language acceptance of %S" pattern) expected
  | Error why ->
    check (Printf.sprintf "common-language rejection of %S: %s" pattern why) (not expected)
  | exception exn ->
    check (Printf.sprintf "common-language parse %S raised %s" pattern (Printexc.to_string exn)) false

let solver_cases cases =
  (* Prove each independently supplied truth value, rather than using our concrete
     matcher as the expected answer. One disjunction asks for any disagreement. *)
  let disagreements = List.filter_map
    (fun (pattern, subject, expected) ->
      match Regex.parse pattern with
      | Error why -> check ("solver test pattern: " ^ why) false; None
      | Ok value ->
        Some (Printf.sprintf "(not (= (str.in_re %s %s) %b))"
                (Regex.smt_string subject) (Regex.to_smt value.re) expected)) cases in
  let query = "(set-logic ALL)\n(assert (or " ^ String.concat " " disagreements
              ^ "))\n(check-sat)\n" in
  match Solve.check query with
  | Solve.Proved -> ()
  | result -> check ("real Z3 disagrees with expected regex membership: "
                     ^ Solve.string_of_result result) false

let () =
  List.iter (fun (pattern, subject) -> member pattern subject true)
    [ ("\\a", "\007"); ("\\f", "\012"); ("\\n", "\n");
      ("\\r", "\r"); ("\\t", "\t"); ("\\s", "\011");
      ("\\x41", "A"); ("\\x{41}", "A"); ("\\x{a}", "\n");
      ("\\x5cu0041", "\\u0041"); ("[\\x41-\\x43]", "B");
      ("[\\n-\\r]", "\011"); ("[]a]", "]"); ("[-a]", "-");
      ("[a-]", "-"); ("[\\[\\]\\-]", "["); ("[\\[\\]\\-]", "]");
      ("[\\[\\]\\-]", "-"); ("\\$", "$"); ("\\\\", "\\");
      ("(a|b)c", "bc"); ("(?:ab)+?", "abab");
      ("(?<part_1>a)(?P<other>b)", "ab"); ("a{2,3}", "aaa");
      ("a{0}", ""); ("a{0,}", "aaa"); ("a{0002}", "aa");
      ("[\\d-]", "-"); ("[&\\&]", "&"); ("[~\\~]", "~");
      ("[\\-\\-]", "-"); ("[\\x00-\\x02]", "\001");
      ("[]-]", "]"); ("[]-]", "-"); ("[\\]-a]", "_");
      ("\\xFF", "\255"); ("\\x{ff}", "\255") ];
  List.iter (fun (pattern, subject) -> member pattern subject false)
    [ ("\\n", "n"); ("\\x41", "x41"); ("[\\x41-\\x43]", "D");
      (".", "\n"); ("(a|b)c", "acx"); ("a{2,3}", "aaaa");
      ("[]-]", "_"); ("[\\]-a]", "-") ];
  check "Any still includes LF for unmatched suffixes"
    (Regex.matches_full Regex.Any "\n");
  List.iter rejected
    [ "\\q"; "\\k"; "\\g"; "\\0"; "\\u0041"; "\\v";
      "\\<"; "\\>"; "[\\b]"; "[\\q]"; "\\x"; "\\x4";
      "\\xGG"; "\\x{}"; "\\x{100}"; "\\x{41";
      "[[:digit:]]"; "[a[b]]"; "[a&&b]"; "[a--b]"; "[a~~b]";
      "[!--a]"; "[\\x00--a]"; "[]-a]";
      "[a-\\w]"; "[\\d-a]"; "[z-a]"; "[a-\\x41]";
      "?a"; "{2}a"; "a{foo}"; "a{1"; "a{,2}"; "a{2,1}";
      "a{65536}"; "a{999999999999999999999999999}";
      "a{1,999999999999999999999999999}"; "a*??"; "a++"; "a{1}*";
      "a**"; "a{1}{2}"; "a?+"; "a}"; "[--a]"; "[&&]"; "[~~]";
      "(?<>a)"; "(?<1bad>a)"; "(?<bad-name>a)"; "(?<bad.name>a)";
      "(?<dup>a)(?P<dup>b)"; "(?<unterminated";
      "(?<" ^ String.make 129 'a' ^ ">b)";
      "/a|/b$"; "a|b"; "("; ")"; "["; "\\";
      String.make 251 '(' ^ "a" ^ String.make 251 ')' ];
  for slash_count = 0 to 4 do
    let pattern = "/a" ^ String.make slash_count '\\' ^ "$" in
    parsed pattern (fun value ->
      check (Printf.sprintf "anchor parity %d" slash_count)
        (value.anchored_end = (slash_count mod 2 = 0));
      let subject = "/a" ^ String.make (slash_count / 2) '\\'
                    ^ if slash_count mod 2 = 1 then "$" else "" in
      check (Printf.sprintf "anchor parity language %d" slash_count)
        (Regex.matches_full value.re subject))
  done;
  parsed "a{65535}" (fun _ -> ());
  parsed (String.make 250 '(' ^ "a" ^ String.make 250 ')') (fun _ -> ());
  parsed ("(?<" ^ String.make 128 'a' ^ ">b)") (fun _ -> ());
  (match Regex.parse "\\\255" with
   | Error why ->
     check "invalid escaped byte has an ASCII-safe diagnostic"
       (String.for_all (fun c -> Char.code c < 128) why)
   | Ok _ -> check "invalid escaped byte rejected" false);
  (* The core remains byte-oriented, but Kong's boundary cannot claim these are
     equivalent to Unicode regex::Regex. Rejection does not assume ASCII paths. *)
  List.iter (fun pattern -> common pattern false)
    [ "/a$"; "/a\\\\$"; "/x/."; "/x/[^/]"; "/x/.*";
      "/x/\\d"; "/x/\\D"; "/x/\\w"; "/x/\\W"; "/x/\\s"; "/x/\\S";
      "/x/[\\d]"; "/x/[a\\w]"; "/x/[\\s]"; "/x/[\\D]";
      "/x/\xc3\xa9"; "/x/\xc3\xa9+"; "/x/[\xc3\xa9]";
      "/x/\\x80"; "/x/\\xFF+"; "/x/[\\x7f-\\x80]"; "/x/\\x{e9}";
      "/x/(?<uri_postfix>a)"; "/x/(?P<uri_postfix>a)";
      "/x/\\?<"; "/x/[?<]"; "/x/(?<good>a)[?<]"; "/x/(?:\\?<)";
      "/x/a?<"; "/x/a{1}?<";
      "/a|/b"; "/x/[[:digit:]]"; "/x/[a&&b]"; "/x/\\q";
      "/x/[!--a]"; "/x/[\\x00--a]"; "/x/[]-a]" ];
  List.iter (fun pattern -> common pattern true)
    [ "/x/[0-9]+"; "/x/[a-zA-Z0-9_]+"; "/x/[ \\t\\n\\r\\f\\x0b]";
      "^/x/(foo|bar)/[a-z]{1,3}"; "/x/(?:a|)b??"; "/x/(?<good>a)";
      "/x/(?P<good>a)"; "/x/(?<first>a)(?P<second>b)";
      "/x/\\$"; "/x/[$]"; "/x/\\\\d"; "/x/[\\\\d]";
      "/x/\\x41"; "/x/[\\x41-\\x5a]"; "/x/\\x{7f}";
      "/x/\\x5cu0041"; "/x/\\x3f<"; "/x/[\\x3f<]";
      "/x/\\?\\x3c"; "/x/[?\\x3c]"; "/x/\\.\\*\\+\\?\\{\\}";
      "/x/[]a]"; "/x/[]-]"; "/x/[\\]-a]" ];
  (* These conservative support limits are smaller than either target's resource
     ceilings. In particular Rust counts AST nodes, not just parentheses, and
     PCRE rejects huge compiled repeat expansions despite legal numeric bounds. *)
  let nested depth = "/" ^ String.make depth '(' ^ "a" ^ String.make depth ')' in
  common (nested 32) true;
  common (nested 33) false;
  common (nested 250) false;
  common "/x/(ab){65535}" false;
  common "/x/a{64}" true;
  common "/x/a{65}" false;
  common "/x/a{0,65}" false;
  common "/x/a{65,}" false;
  common "/x/(a{8}){64}" false;
  common ("/" ^ String.make 510 'a') true;
  common ("/" ^ String.make 511 'a') false;
  let padded_atoms = String.concat "" (List.init 341 (fun _ -> "\\x{61}")) in
  common ("/a" ^ padded_atoms) true;  (* exactly 2048 source bytes, modest cost *)
  common ("/aa" ^ padded_atoms) false;
  common ("/x/[" ^ String.make 256 'a' ^ "]") false;
  common ("/x/" ^ String.concat "" (List.init 255 (fun _ -> "(?:a)"))) false;
  let long_capture = "/x/(?<" ^ String.make 128 'a' ^ ">a)" in
  common (long_capture ^ "{3}") true;
  common (long_capture ^ "{4}") false;
  (match Regex.parse_with_syntax "(?<id>ab){3}" with
   | Error why -> check ("expansion metadata: " ^ why) false
   | Ok (_, syntax) ->
     check "groups and capture names are counted inside repetitions"
       (syntax.expansion_cost = 19 && syntax.max_group_depth = 1));
  (match Regex.parse_with_syntax "(((a{65535}){65535}){65535}){65535}" with
   | Error why -> check ("saturating expansion metadata: " ^ why) false
   | Ok (_, syntax) ->
     check "nested repeat cost saturates rather than overflowing"
       (syntax.expansion_cost = max_int));
  (match Regex.parse_with_syntax "(?<first>[\\d])(?P<second>\\w)\\\\s" with
   | Error why -> check ("syntax metadata: " ^ why) false
   | Ok (_, syntax) ->
     check "shorthand syntax survives class lowering"
       (syntax.shorthand_classes = [ 'd'; 'w' ]);
     check "capture syntax order"
       (syntax.named_captures = [ "first"; "second" ]);
     check "only genuine angle-form named openers are counted"
       (syntax.angle_named_captures = 1));
  (match Regex.parse_with_syntax "[?<]\\?<" with
   | Error why -> check ("literal metadata: " ^ why) false
   | Ok (_, syntax) ->
     check "literal ?< is not counted as a named capture"
       (syntax.angle_named_captures = 0));
  (match Regex_boundary.parse "/x/[0-9]+" with
   | Error why -> check ("ASCII prefix with Unicode suffix: " ^ why) false
   | Ok value ->
     let with_suffix = Regex.Concat [ value.re; Regex.Star Regex.Any ] in
     check "accepted ASCII pattern can match a Unicode request suffix"
       (Regex.matches_full with_suffix "/x/7/\xc3\xa9/\xe4\xb8\xad");
     check "unmatched suffix still includes LF"
       (Regex.matches_full with_suffix "/x/7\n"));
  solver_cases
    [ ("\\n", "\n", true); ("\\n", "n", false);
      ("\\s", "\011", true); ("\\s", "\000", false);
      ("\\x41", "A", true); ("\\x41", "x41", false);
      ("\\x{41}", "A", true); ("\\x5cu0041", "\\u0041", true);
      ("[\\x41-\\x43]", "A", true); ("[\\x41-\\x43]", "C", true);
      ("[\\x41-\\x43]", "D", false); ("[\\n-\\r]", "\011", true);
      (".", "\n", false); (".", "\r", true); (".", "a", true);
      ("(a|b)c", "bc", true); ("(a|b)c", "acx", false);
      ("a{2,3}", "aaa", true); ("a{2,3}", "aaaa", false);
      ("[]a]", "]", true); ("[a-]", "-", true); ("\\$", "$", true);
      ("[]-]", "-", true); ("[]-]", "_", false);
      ("[\\]-a]", "_", true); ("[\\]-a]", "-", false);
      ("a{0}", "", true); ("a{0}", "a", false);
      ("\\xFF", "\255", true); ("\\xFF", "\xc3\xbf", false) ];
  (* Malformed inputs must return Error, not escape through a parser exception.
     This deterministic smoke check exercises mixtures of grammar delimiters. *)
  let random = Random.State.make [| 0x534331 |] in
  let alphabet = "abc09()[]{}?*+|^$\\x<>,-&~\000\255" in
  for _ = 1 to 5_000 do
    let length = Random.State.int random 80 in
    let pattern = String.init length (fun _ ->
        alphabet.[Random.State.int random (String.length alphabet)]) in
    (try ignore (Regex.parse pattern); ignore (Regex_boundary.parse pattern)
     with exn -> check (Printf.sprintf "total parser on %S: %s"
                          pattern (Printexc.to_string exn)) false)
  done;
  if !failures <> 0 then begin
    Printf.eprintf "%d regex boundary checks failed\n%!" !failures;
    exit 1
  end;
  print_endline "regex parser and common-language boundary checks passed"
