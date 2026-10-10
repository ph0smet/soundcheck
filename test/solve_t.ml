open Soundcheck_core

let fail format = Printf.ksprintf failwith format

let contains text fragment =
  let rec loop index =
    index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || loop (index + 1))
  in
  loop 0

let values =
  {|((path "/admin") (method "GET") (is_anon true) (src_ip #x0a000001)
     (host "admin.example") (scheme "https") (sni "admin.example"))|}

let string_fields =
  [ ("path", {|"/admin"|}); ("method", {|"GET"|});
    ("host", {|"admin.example"|}); ("scheme", {|"https"|});
    ("sni", {|"admin.example"|}) ]

let string_values field literal =
  let fields =
    string_fields
    |> List.map (fun (name, value) ->
           Printf.sprintf "(%s %s)" name (if name = field then literal else value))
    |> String.concat " "
  in
  Printf.sprintf "(%s (is_anon true) (src_ip #x0a000001))" fields

let unicode_diagnostic = "pr\xc3\xa9fixe \xff suffix\xe2\x82\xac"
let split_diagnostic_prefix = "\xce\xbb" ^ String.make 2045 'a'
let split_diagnostic = split_diagnostic_prefix ^ "\xc3\xa9suffix"

let read_file path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      really_input_string channel (in_channel_length channel))

let mock () =
  let mode = Sys.getenv "SOUNDCHECK_SOLVER_TEST_MODE" in
  if Sys.argv.(1) = "-version" then begin
    (match mode with
     | "version" -> print_endline "Z3 version test - 64 bit"
     | "version-exit" -> print_endline "Z3 version test"; exit 7
     | "version-stderr" -> prerr_endline "version diagnostic"; print_endline "Z3 version test"
     | "version-malformed" -> print_endline "Z3 version test\nextra reply"
     | "version-hang" -> prerr_endline "version stalled"; Unix.sleep 30
     | "version-invalid-utf8" -> print_endline ("Z3 version " ^ unicode_diagnostic)
     | "version-valid-utf8" -> print_endline "Z3 version test-\xc3\xa9"
     | "version-stderr-invalid-utf8" ->
       prerr_endline unicode_diagnostic; print_endline "Z3 version test"
     | "version-exit-invalid-utf8" -> print_endline unicode_diagnostic; exit 7
     | "version-hang-invalid-utf8" -> prerr_endline unicode_diagnostic; Unix.sleep 30
     | "version-split-utf8" -> print_endline split_diagnostic
     | _ -> fail "unexpected version mock %s" mode);
    exit 0
  end;
  if mode = "never-read" then begin Unix.sleep 30; exit 0 end;
  if mode = "early-exit" then exit 0;
  let source = read_file Sys.argv.(2) in
  let observation = contains source "(get-value" in
  let sat model =
    print_endline "sat";
    if observation then print_endline model
  in
  (match mode with
   | "unsat" ->
     print_endline "unsat";
     if observation then begin
       prerr_endline "unexpected command after unsat"; exit 9
     end
   | "sat" -> sat values
   | "string-value" ->
     sat (string_values (Sys.getenv "SOUNDCHECK_SOLVER_TEST_FIELD")
            (Sys.getenv "SOUNDCHECK_SOLVER_TEST_LITERAL"))
   | "unknown" ->
     print_endline "unknown";
     if observation then begin
       prerr_endline "unexpected command after unknown"; exit 9
     end
   | "exit" -> print_endline "unsat"; prerr_endline "intentional failure"; exit 7
   | "signal" -> print_endline "unsat"; Unix.kill (Unix.getpid ()) Sys.sigterm
   | "stderr" ->
     prerr_endline "important diagnostic";
     output_string stderr (String.make 200_000 'e'); flush stderr;
     print_endline "unsat"
   | "stderr-invalid-utf8" -> prerr_endline unicode_diagnostic; print_endline "unsat"
   | "stdout-invalid-utf8" -> print_endline unicode_diagnostic
   | "exit-invalid-utf8" -> print_endline unicode_diagnostic; exit 7
   | "hang-invalid-utf8" -> prerr_endline unicode_diagnostic; Unix.sleep 30
   | "stderr-split-utf8" -> prerr_endline split_diagnostic; print_endline "unsat"
   | "stdout-split-utf8" -> print_endline split_diagnostic
   | "malformed-status" -> print_endline "unsatisfied"
   | "sat-prefix" -> print_endline "satisfiable"
   | "extra-status" -> print_endline "unsat\nsat"
   | "error-after-status" -> print_endline "unsat\n(error \"bad query\")"
   | "error-before-status" -> print_endline "(error \"bad query\")\nunsat"
   | "eof" -> ()
   | "hang" -> prerr_endline "solver stalled"; Unix.sleep 30
   | "hang-after-status" -> print_endline "unsat"; Unix.sleep 30
   | "hang-after-eof" ->
     print_endline "unsat";
     Unix.close Unix.stdin; Unix.close Unix.stdout; Unix.close Unix.stderr;
     Unix.sleep 30
   | "stdout-limit" ->
     print_endline "sat";
     for _ = 1 to 80 do output_string stdout (String.make 65_536 'x'); flush stdout done
   | "stderr-limit" ->
     for _ = 1 to 80 do output_string stderr (String.make 65_536 'e'); flush stderr done
   | "no-model" -> print_endline "sat"
   | "replay-unsat" -> print_endline (if observation then "unsat" else "sat")
   | "replay-unknown" -> print_endline (if observation then "unknown" else "sat")
   | "replay-exit" -> sat values; if observation then exit 7
   | "two-phase-delay" -> Unix.sleepf 0.2; sat values
   | "unterminated-model" -> sat "((path \"unterminated)"
   | "missing-fields" -> sat "((path \"/admin\"))"
   | "duplicate-fields" ->
     sat {|((path "/admin") (path "/admin") (method "GET") (is_anon true)
             (src_ip #x0a000001) (host "admin.example") (scheme "https") (sni ""))|}
   | "bad-bool" ->
     sat {|((path "/admin") (method "GET") (is_anon true-ish) (src_ip #x0a000001)
             (host "admin.example") (scheme "https") (sni ""))|}
   | "bad-bv" ->
     sat {|((path "/admin") (method "GET") (is_anon true) (src_ip #x1)
             (host "admin.example") (scheme "https") (sni ""))|}
   | _ -> fail "unexpected mock %s" mode);
  exit 0

let query = Smt_encode.condition_query ~name:"solver-test" ~description:"test" Ir.True

let mock_binary =
  if Filename.is_relative Sys.executable_name then
    Filename.concat (Sys.getcwd ()) Sys.executable_name
  else Sys.executable_name

let with_mock mode action =
  let previous = Sys.getenv_opt "SOUNDCHECK_SOLVER_TEST_MODE" in
  Unix.putenv "SOUNDCHECK_SOLVER_TEST_MODE" mode;
  Fun.protect
    ~finally:(fun () ->
      Unix.putenv "SOUNDCHECK_SOLVER_TEST_MODE" (Option.value ~default:"" previous))
    action

let check_mock ?(timeout = 2.) ?(query = query) mode =
  with_mock mode (fun () -> Solve.check ~z3:mock_binary ~timeout query)

let unknown ?fragment label = function
  | Solve.Unknown reason ->
    Option.iter
      (fun fragment ->
        if not (contains reason fragment) then
          fail "%s lost diagnostic %S: %s" label fragment reason)
      fragment
  | result -> fail "%s returned %s" label (Solve.string_of_result result)

let expect_proved label = function
  | Solve.Proved -> ()
  | result -> fail "%s returned %s" label (Solve.string_of_result result)

let bounded label action =
  let start = Unix.gettimeofday () in
  let result = action () in
  let elapsed = Unix.gettimeofday () -. start in
  if elapsed > 2. then fail "%s exceeded its deadline (%.3fs)" label elapsed;
  result

let with_env name value action =
  let previous = Sys.getenv_opt name in
  Unix.putenv name value;
  Fun.protect
    ~finally:(fun () -> Unix.putenv name (Option.value ~default:"" previous))
    action

let check_string_mock ?(field = "path") literal =
  with_env "SOUNDCHECK_SOLVER_TEST_FIELD" field (fun () ->
      with_env "SOUNDCHECK_SOLVER_TEST_LITERAL" literal (fun () ->
          check_mock "string-value"))

(* Handwritten SMT literals deliberately bypass Soundcheck's encoder. Expected
   values follow the SMT-LIB Unicode Strings theory and Z3 4.16.0 zstring.cpp:
   https://smt-lib.org/theories-UnicodeStrings.shtml
   https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/util/zstring.cpp
   The current IR/regex and Z3's raw input literals use one codepoint per byte,
   not one per UTF-8 scalar. Escaping does not change that representation. *)
let literal_query literal =
  let fields =
    string_fields
    |> List.map (fun (name, value) ->
           Printf.sprintf "(define-fun %s () String %s)\n" name
             (if name = "path" then literal else value))
    |> String.concat ""
  in
  "(set-logic ALL)\n" ^ fields
  ^ "(define-fun is_anon () Bool true)\n"
  ^ "(define-fun src_ip () (_ BitVec 32) #x0a000001)\n"
  ^ "(check-sat)\n(get-value (path method is_anon src_ip host scheme sni))\n"

let expect_path label expected = function
  | Solve.Violated model when model.path = expected -> ()
  | Solve.Violated model -> fail "%s: expected path %S, got %S" label expected model.path
  | result -> fail "%s: %s" label (Solve.string_of_result result)

let string_protocol_tests () =
  let faithful =
    [ ("empty", {|""|}, "");
      ("doubled quotes", {|"/a""b"|}, "/a\"b");
      ("fixed-width escapes", {|"\u002fadmin\u0041"|}, "/adminA");
      ("braced escapes", {|"\u{2F}admin\u{0002f}x"|}, "/admin/x");
      ("four digits only", {|"\u00411"|}, "A1");
      ("escape is not recursive", {|"\u005cu0041"|}, {|\u0041|});
      ("backslash does not quote backslash", {|"\\u0041"|}, {|\A|});
      ("C escapes are literal", {|"\n|\r|\t|\x41|\123"|}, {|\n|\r|\t|\x41|\123|});
      ("non-escapes are literal", {|"\u{}|\u{GG}|\u{30000}|\u{000041}|\u123"|},
       {|\u{}|\u{GG}|\u{30000}|\u{000041}|\u123|});
      ("escaped control bytes", {|"\u{0}\u000a\u{7f}"|}, "\x00\n\x7f");
      ("UTF-8 encoded as bytes", {|"\u{c3}\u{a9}|\u{f0}\u{9f}\u{92}\u{a9}"|},
       "\xc3\xa9|\xf0\x9f\x92\xa9");
      ("UTF-8 boundary scalars as bytes",
       {|"\u{c2}\u{80}|\u{df}\u{bf}|\u{e0}\u{a0}\u{80}|\u{ed}\u{9f}\u{bf}|\u{f0}\u{90}\u{80}\u{80}|\u{f4}\u{8f}\u{bf}\u{bf}"|},
       "\xc2\x80|\xdf\xbf|\xe0\xa0\x80|\xed\x9f\xbf|\xf0\x90\x80\x80|\xf4\x8f\xbf\xbf");
      ("raw UTF-8 input is bytes", "\"\xc3\xa9\"", "\xc3\xa9");
      ("quote and command-like contents", {|"\u{22}); (check-sat); \u{5c}u0041"|},
       {|"); (check-sat); \u0041|}) ]
  in
  List.iter
    (fun (label, literal, expected) ->
      check_string_mock literal |> expect_path ("mock " ^ label) expected;
      Solve.check (literal_query literal) |> expect_path ("actual Z3 " ^ label) expected)
    faithful;
  let unsupported =
    [ ("non-byte Unicode", {|"\u{100}"|}, "outside the byte request representation");
      ("SMT surrogate", {|"\ud800"|}, "outside the byte request representation");
      ("SMT maximum", {|"\u{2ffff}"|}, "outside the byte request representation");
      ("Latin-1 is not UTF-8", {|"\u{e9}"|}, "not valid UTF-8");
      ("lone continuation byte", {|"\u0080"|}, "not valid UTF-8");
      ("overlong UTF-8", {|"\u{c0}\u{80}"|}, "not valid UTF-8");
      ("truncated UTF-8", {|"\u{e2}\u{82}"|}, "not valid UTF-8");
      ("UTF-8 surrogate", {|"\u{ed}\u{a0}\u{80}"|}, "not valid UTF-8");
      ("UTF-8 above scalar maximum", {|"\u{f4}\u{90}\u{80}\u{80}"|}, "not valid UTF-8") ]
  in
  List.iter
    (fun (label, literal, fragment) ->
      check_string_mock literal |> unknown ~fragment ("mock " ^ label);
      Solve.check (literal_query literal) |> unknown ~fragment ("actual Z3 " ^ label))
    unsupported;
  List.iter
    (fun (field, _) ->
      check_string_mock ~field {|"\u{100}"|}
      |> unknown ~fragment:field ("unrepresentable " ^ field))
    string_fields;
  List.iter
    (fun literal -> check_string_mock literal |> unknown "malformed string value")
    [ {|"unterminated|}; {|not-a-string|}; {|(str.++ "a" "b")|}; {|"a" "b"|} ];
  (match check_string_mock "\"\xff\"" with
   | Solve.Unknown reason when String.is_valid_utf_8 reason -> ()
   | result -> fail "invalid output bytes escaped in diagnostic: %s" (Solve.string_of_result result));
  (* The entire query must still be framed, not semantically decoded: an
     unrepresentable constant in an UNSAT query needs no model conversion. *)
  Solve.check "(set-logic ALL)\n(assert (= \"\\u{100}\" \"a\"))\n(check-sat)\n"
  |> expect_proved "UNSAT is independent of witness representability";
  let original_values =
    [ {|/literal/\u0041|}; {|/literal/\u{2f}|}; {|/literal/\u{5c}u0041|};
      String.init 128 Char.chr; "\xc3\xa9|\xf0\x9f\x92\xa9";
      {|/quote"; (check-sat)\|} ]
  in
  List.iter
    (fun expected ->
      Smt_encode.condition_query ~name:"literal-roundtrip" ~description:"exact bytes"
        (Ir.Path_exact expected)
      |> Solve.check |> expect_path "condition encoder roundtrip" expected;
      Smt_encode.condition_query ~name:"regex-literal-roundtrip" ~description:"exact bytes"
        (Ir.Path_regex (Regex.Lit expected))
      |> Solve.check |> expect_path "regex encoder roundtrip" expected)
    original_values;
  (* A serializer collision is not just a bad witness: it can turn an inhabited
     request class into UNSAT and thereby produce a false proof. *)
  let literal_backslash = {|/literal/\u0041|} in
  List.iter
    (fun literal_match ->
      Smt_encode.condition_query ~name:"distinct-literal-text" ~description:"no escape collision"
        (Ir.And [ literal_match; Ir.Not (Ir.Path_exact "/literal/A") ])
      |> Solve.check |> expect_path "literal backslash must not become a proof" literal_backslash)
    [ Ir.Path_exact literal_backslash; Ir.Path_regex (Regex.Lit literal_backslash) ];
  List.iter
    (fun (name, value) ->
      Smt_encode.condition_query ~name:"invalid-header-bytes" ~description:"invalid UTF-8"
        (Ir.Header_has (name, value))
      |> Solve.check |> unknown ~fragment:"not valid UTF-8" "header model bytes")
    [ ("x-test", "\xff"); ("x-\xff", "valid") ];
  let header = ("x-test", "\xc3\xa9\x00\n") in
  (match Smt_encode.condition_query ~name:"valid-header-bytes" ~description:"exact UTF-8 bytes"
           (Ir.Header_has (fst header, snd header)) |> Solve.check with
   | Solve.Violated model when model.headers = [ header ] -> ()
   | result -> fail "valid header bytes changed: %s" (Solve.string_of_result result))

let diagnostic_tests () =
  let valid_reason label fragments reason =
    if not (String.is_valid_utf_8 reason) then fail "%s diagnostic is not UTF-8" label;
    List.iter
      (fun fragment ->
        if not (contains reason fragment) then
          fail "%s lost diagnostic %S: %s" label fragment reason)
      fragments
  in
  let unknown_reason label fragments = function
    | Solve.Unknown reason -> valid_reason label fragments reason
    | result -> fail "%s: %s" label (Solve.string_of_result result)
  in
  let escaped = [ "pr\xc3\xa9fixe"; {|\xff|}; "suffix\xe2\x82\xac" ] in
  List.iter
    (fun mode -> check_mock mode |> unknown_reason mode escaped)
    [ "stderr-invalid-utf8"; "stdout-invalid-utf8"; "exit-invalid-utf8" ];
  bounded "invalid UTF-8 timeout" (fun () -> check_mock ~timeout:0.5 "hang-invalid-utf8")
  |> unknown_reason "timeout diagnostic" ("timed out" :: escaped);
  let truncated = [ split_diagnostic_prefix ^ " [truncated]" ] in
  List.iter
    (fun mode -> check_mock mode |> unknown_reason mode truncated)
    [ "stderr-split-utf8"; "stdout-split-utf8" ];
  List.iter
    (fun mode ->
      match with_mock mode (fun () -> Solve.version ~z3:mock_binary ~timeout:0.5 ()) with
      | Error reason -> valid_reason mode escaped reason
      | Ok _ -> fail "%s incorrectly accepted a version" mode)
    [ "version-invalid-utf8"; "version-stderr-invalid-utf8";
      "version-exit-invalid-utf8"; "version-hang-invalid-utf8" ];
  (match with_mock "version-split-utf8" (fun () -> Solve.version ~z3:mock_binary ()) with
   | Error reason -> valid_reason "version split UTF-8" truncated reason
   | Ok _ -> fail "truncated malformed output became a version");
  (match with_mock "version-valid-utf8" (fun () -> Solve.version ~z3:mock_binary ()) with
   | Ok "Z3 version test-\xc3\xa9" -> ()
   | _ -> fail "valid Unicode version changed");
  let missing = "/soundcheck-missing-\xff" in
  Solve.check ~z3:missing query |> unknown_reason "invalid executable path" [ {|\xff|} ];
  (match Solve.version ~z3:missing () with
   | Error reason -> valid_reason "invalid version executable path" [ {|\xff|} ] reason
   | Ok _ -> fail "missing executable acquired a version")

let test () =
  (* Unix.fork is unavailable after any OCaml domain has been spawned, even
     once joined. All checks below, including version lookup, run afterward. *)
  Domain.join (Domain.spawn (fun () -> ()));
  diagnostic_tests ();
  string_protocol_tests ();
  check_mock "unsat" |> expect_proved "UNSAT does not request values";
  (match check_mock "sat" with
   | Solve.Violated model
     when model.path = "/admin" && model.method_ = "GET" && model.is_anon
          && model.src_ip = 0x0a000001l -> ()
   | result -> fail "SAT model changed: %s" (Solve.string_of_result result));
  check_mock "unknown" |> unknown ~fragment:"solver returned unknown" "UNKNOWN";
  check_mock "exit" |> unknown ~fragment:"status 7" "nonzero solver";
  check_mock "exit" |> unknown ~fragment:"intentional failure" "failure stderr";
  check_mock "signal" |> unknown ~fragment:"signal" "signalled solver";
  check_mock "stderr" |> unknown ~fragment:"important diagnostic" "large stderr";
  List.iter
    (fun mode -> check_mock mode |> unknown mode)
    [ "early-exit"; "eof"; "malformed-status"; "sat-prefix";
      "extra-status"; "error-before-status"; "error-after-status";
      "no-model"; "unterminated-model"; "missing-fields"; "duplicate-fields";
      "bad-bool"; "bad-bv"; "replay-unsat"; "replay-unknown"; "replay-exit" ];
  List.iter
    (fun mode ->
      bounded mode (fun () -> check_mock ~timeout:0.15 mode)
      |> unknown ~fragment:"timed out" mode)
    [ "hang"; "hang-after-status"; "hang-after-eof" ];
  let large_query = "; " ^ String.make 2_000_000 'x' ^ "\n" ^ query in
  bounded "unread input file" (fun () -> check_mock ~query:large_query ~timeout:0.15 "never-read")
  |> unknown ~fragment:"timed out" "unread input file";
  bounded "shared deadline" (fun () -> check_mock ~timeout:0.3 "two-phase-delay")
  |> unknown ~fragment:"timed out" "shared deadline";
  List.iter
    (fun mode -> check_mock mode |> unknown ~fragment:"4 MiB" mode)
    [ "stdout-limit"; "stderr-limit" ];
  Solve.check ~z3:"/soundcheck-test-no-such-z3" query
  |> unknown "missing executable";
  List.iter
    (fun timeout -> Solve.check ~timeout query |> unknown "invalid timeout")
    [ 0.; -1.; nan; infinity ];
  List.iter
    (fun text -> Solve.check text |> unknown ~fragment:"unsupported SMT query" "invalid query")
    [ query ^ "(assert false)\n"; query ^ "(check-sat)\n";
      "(check-sat)\n" ^ query; "(check-sat)\n(get-value (path path))\n";
      "(assert \"unterminated)\n(check-sat)\n";
      "(|exit|)\n" ^ query; "(|check-sat|)\n" ^ query;
      "(|assert| false)\n(check-sat)\n" ];
  Solve.check "(set-logic ALL)\n(declare-const |quoted name| Bool)\n(assert |quoted name|)\n(assert (not |quoted name|))\n(check-sat)\n"
  |> expect_proved "quoted symbols inside assertions remain supported";
  Solve.check "(set-logic ALL)\n(assert false)\n(check-sat)\n"
  |> expect_proved "proof-only UNSAT";
  Solve.check "(set-logic ALL)\n(assert true)\n(check-sat)\n"
  |> unknown "SAT without requested model";
  let actual_query =
    Smt_encode.condition_query ~name:"actual-z3" ~description:"exact typed request"
      Ir.(And [ Path_exact "/admin\"; (check-sat)"; Method_is "GET";
                Is_anonymous; Scheme_is "https"; Sni_is "admin.example";
                Header_has ("x-team", "review\"; (check-sat)") ])
  in
  (match Solve.check actual_query with
   | Solve.Violated model
     when model.path = "/admin\"; (check-sat)" && model.method_ = "GET"
          && model.is_anon && model.scheme = "https" && model.sni = "admin.example"
          && model.headers = [ ("x-team", "review\"; (check-sat)") ] -> ()
   | result -> fail "actual Z3 SAT/header/string framing: %s" (Solve.string_of_result result));
  let unsat_query =
    Smt_encode.condition_query ~name:"actual-unsat" ~description:"contradiction"
      Ir.(And [ Is_anonymous; Not Is_anonymous; Header_has ("x-team", "review") ])
  in
  let artifact = Filename.temp_file "soundcheck-solver-artifact-" ".smt2" in
  Fun.protect ~finally:(fun () -> Sys.remove artifact) (fun () ->
      Solve.check ~emit_smt:artifact unsat_query |> expect_proved "actual Z3 UNSAT";
      let channel = open_in_bin artifact in
      let saved =
        Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
            really_input_string channel (in_channel_length channel))
      in
      if saved <> unsat_query then fail "saved obligation was rewritten");
  (match Solve.version () with
   | Ok text when String.starts_with ~prefix:"Z3 version " text -> ()
   | _ -> fail "actual Z3 version failed");
  (match with_mock "version" (fun () -> Solve.version ~z3:mock_binary ()) with
   | Ok "Z3 version test - 64 bit" -> ()
   | _ -> fail "mock Z3 version changed");
  List.iter
    (fun mode ->
      match with_mock mode (fun () -> Solve.version ~z3:mock_binary ()) with
      | Error _ -> ()
      | Ok text -> fail "%s incorrectly accepted %s" mode text)
    [ "version-exit"; "version-stderr"; "version-malformed" ];
  (match bounded "version timeout" (fun () ->
       with_mock "version-hang" (fun () -> Solve.version ~z3:mock_binary ~timeout:0.15 ())) with
   | Error reason when contains reason "timed out" && contains reason "version stalled" -> ()
   | _ -> fail "version timeout was not explicit");
  (match Solve.version ~z3:"/soundcheck-test-no-such-z3" () with
   | Error _ -> () | Ok _ -> fail "missing solver acquired a version");
  List.iter
    (fun mask ->
      let pid =
        Unix.create_process mock_binary
          [| mock_binary; "--closed-stdio"; string_of_int mask |]
          Unix.stdin Unix.stdout Unix.stderr
      in
      match snd (Unix.waitpid [] pid) with
      | Unix.WEXITED 0 -> ()
      | _ -> fail "solver could not run with closed standard descriptors (mask %d)" mask)
    [ 1; 2; 3; 4; 5; 6; 7 ];
  print_endline "solver process and protocol checks passed"

let () =
  if Array.length Sys.argv > 1 then
    match Sys.argv.(1) with
    | "-smt2" | "-version" -> mock ()
    | "--closed-stdio" ->
      let mask = int_of_string Sys.argv.(2) in
      let descriptors = [ Unix.stdin; Unix.stdout; Unix.stderr ] in
      List.iteri
        (fun index descriptor -> if mask land (1 lsl index) <> 0 then Unix.close descriptor)
        descriptors;
      Solve.check ~timeout:2. "(set-logic ALL)\n(assert false)\n(check-sat)\n"
      |> expect_proved "closed standard descriptors";
      (match Solve.version ~timeout:2. () with
       | Ok _ -> () | Error reason -> fail "closed stdio version: %s" reason);
      List.iteri
        (fun index descriptor ->
          if mask land (1 lsl index) <> 0 then
            match Unix.fstat descriptor with
            | _ -> fail "solver reopened a caller's standard descriptor"
            | exception Unix.Unix_error (Unix.EBADF, _, _) -> ())
        descriptors
    | argument -> fail "unknown argument %s" argument
  else test ()
