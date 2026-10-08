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

let test () =
  (* Unix.fork is unavailable after any OCaml domain has been spawned, even
     once joined. All checks below, including version lookup, run afterward. *)
  Domain.join (Domain.spawn (fun () -> ()));
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
