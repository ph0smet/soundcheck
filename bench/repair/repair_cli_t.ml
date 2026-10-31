open Soundcheck_core
open Soundcheck_kong

let checks = ref 0
let check name condition = incr checks; if not condition then failwith ("repair CLI: " ^ name)
let read_file path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel)
    (fun () -> really_input_string channel (in_channel_length channel))
let read_all channel =
  let buffer = Buffer.create 1024 in
  (try while true do Buffer.add_string buffer (input_line channel); Buffer.add_char buffer '\n' done
   with End_of_file -> ()); Buffer.contents buffer
let run executable arguments =
  let channels = Unix.open_process_args_full executable
      (Array.of_list (executable :: arguments)) (Unix.environment ()) in
  let stdout, _, stderr = channels in
  let output = read_all stdout and errors = read_all stderr in
  let status = match Unix.close_process_full channels with Unix.WEXITED code -> code | _ -> -1 in
  status, output, errors
let parse source = match Yaml.of_string source with Ok value -> value | Error _ -> failwith "invalid JSON"
let field name = function `O values -> List.assoc name values | _ -> failwith "object expected"
let list = function `A values -> values | _ -> failwith "array expected"
let contains text fragment =
  let rec loop index = index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || loop (index + 1)) in loop 0
let entry ?(task = "frozen-admin") id config =
  Printf.sprintf "  - task: %s\n    id: %s\n    config: %s\n" task id config

let check_coverage evaluator examples =
  let file name = Filename.concat examples name in
  let frozen name = match Contract_spec.read_file (file name) with
    | Ok spec -> spec | Error error -> failwith error in
  let status, output, errors = run evaluator
    [ file "coverage-suite.yaml"; file "coverage-submissions.yaml" ] in
  (* The exact-host task deliberately has no accepted submitted candidate. It
     remains in the denominator even though the other two tasks are solved. *)
  check "coverage retains the unsolved host task" (status = 3 && errors = "");
  let summary = parse output in
  List.iter (fun (name, expected) ->
    check ("coverage " ^ name) (field name summary = `Float (float_of_int expected)))
    [ "scheduled_tasks", 3; "tasks_with_valid_repair", 2;
      "tasks_with_errors", 0; "submitted_attempts", 13 ];
  List.iter (fun (name, expected) ->
    check ("coverage count " ^ name)
      (field name (field "attempt_counts" summary) = `Float (float_of_int expected)))
    [ "valid_repair", 2; "contract_failed", 7; "out_of_scope_regression", 3;
      "unknown", 1; "errors", 0 ];
  let expected =
    [ "trusted-network", "network-before.yaml", "internal-get.yaml", `Float 8.,
      [ "unchanged", "network-before.yaml", "violated", "contract_failed";
        "deny-all", "deny-all.yaml", "violated", "contract_failed";
        "authentication-only", "network-auth-only.yaml", "violated", "contract_failed";
        "cidr-too-narrow", "network-narrow-cidr.yaml", "violated", "contract_failed";
        "cidr-too-wide", "network-wide-cidr.yaml", "violated", "contract_failed";
        "service-wide-restriction", "network-service-wide.yaml", "proved", "out_of_scope_regression";
        "unsupported", "network-unsupported.yaml", "unknown", "unknown";
        "repaired", "network-repaired.yaml", "proved", "valid_repair" ];
      "get-method-only", "method-before.yaml", "admin-get.yaml", `Float 3.,
      [ "unchanged", "method-before.yaml", "violated", "contract_failed";
        "every-method-auth", "method-all-auth.yaml", "proved", "out_of_scope_regression";
        "repaired", "method-repaired.yaml", "proved", "valid_repair" ];
      "exact-host-boundary", "host-before.yaml", "admin-get-host.yaml", `Null,
      [ "unchanged", "host-before.yaml", "violated", "contract_failed";
        "route-host-auth", "host-route-auth.yaml", "proved", "out_of_scope_regression" ] ] in
  let tasks = list (field "tasks" summary) in
  check "coverage schedule not filtered" (List.length tasks = List.length expected);
  List.iter2 (fun (id, baseline, contract, first_valid, candidates) task ->
    check (id ^ " task identity/order") (field "id" task = `String id);
    check (id ^ " provenance") (field "provenance" task = `String "synthetic");
    check (id ^ " first valid attempt") (field "first_valid_attempt" task = first_valid);
    check (id ^ " no input error") (field "failure" task = `Null);
    check (id ^ " original baseline digest") (field "baseline_sha256" task =
      `String (Sha256.string (read_file (file baseline))));
    check (id ^ " frozen contract digest") (field "contract_sha256" task =
      `String (Sha256.string (Contract_spec.canonical_json (frozen contract))));
    let attempts = list (field "attempts" task) in
    check (id ^ " all submitted attempts retained") (List.length attempts = List.length candidates);
    List.iteri (fun index ((attempt_id, candidate, result, repair), attempt) ->
      let label = id ^ "/" ^ attempt_id in
      check (label ^ " attempt identity/order") (field "id" attempt = `String attempt_id
        && field "ordinal" attempt = `Float (float_of_int (index + 1)));
      check (label ^ " contract outcome") (field "contract_result" attempt = `String result);
      check (label ^ " repair outcome") (field "repair_result" attempt = `String repair);
      check (label ^ " exact candidate digest") (field "candidate_sha256" attempt =
        `String (Sha256.string (read_file (file candidate))));
      check (label ^ " no input error") (field "failure" attempt = `Null))
      (List.combine candidates attempts)) expected tasks;

  (* Check semantic witness classes, never one solver-chosen request value. *)
  let compare contract baseline candidate =
    match Compare.run_repair ~contract:(frozen contract)
      (read_file (file baseline)) (read_file (file candidate)) with
    | Ok report -> report | Error error -> failwith error in
  let regression contract baseline candidate =
    let report = compare contract baseline candidate in
    match report.result with
    | Compare.Out_of_scope_regression witness ->
      check (candidate ^ " changes anonymous Allow to Deny")
        (witness.request.is_anon
         && witness.before.decision = Ir.Allow && witness.after.decision = Ir.Deny);
      witness
    | _ -> failwith (candidate ^ ": " ^ Compare.repair_to_human report) in
  let method_witness = regression "admin-get.yaml" "method-before.yaml" "method-all-auth.yaml" in
  check "method regression is inside /admin but outside GET"
    (String.starts_with ~prefix:"/admin" method_witness.request.path
     && method_witness.request.method_ <> "GET");
  let host_witness = regression "admin-get-host.yaml" "host-before.yaml" "host-route-auth.yaml" in
  check "host regression is GET /admin with a port-suffixed modeled Host"
    (String.starts_with ~prefix:"/admin" host_witness.request.path
     && host_witness.request.method_ = "GET"
     && host_witness.request.host <> "api.example"
     && String.starts_with ~prefix:"api.example:" host_witness.request.host);
  List.iter (fun (candidate, clause_name, source_matches) ->
    let report = compare "internal-get.yaml" "network-before.yaml" candidate in
    match report.contract_report.result, report.contract_report.clause with
    | Report.Violated witness, Some clause ->
      check (candidate ^ " fails the independently specified clause") (clause.name = clause_name);
      check (candidate ^ " witness has the required source/principal class")
        (witness.principal = "authenticated" && witness.action = "GET"
         && String.starts_with ~prefix:"/internal" witness.path
         && source_matches witness.source_ip)
    | _ -> failwith (candidate ^ ": " ^ Compare.repair_to_human report))
    [ "network-narrow-cidr.yaml", "trusted-authenticated-access-allowed",
      (fun source -> Int32.shift_right_logical source 24 = 10l
        && Int32.shift_right_logical source 16 <> 0x0a00l);
      "network-wide-cidr.yaml", "untrusted-network-access-denied",
      (fun source -> Int32.shift_right_logical source 24 = 11l) ]

let () =
  if Array.length Sys.argv <> 3 then failwith "expected evaluator and examples";
  let evaluator = Sys.argv.(1) and examples = Sys.argv.(2) in
  let suite = Filename.concat examples "suite.yaml" in
  let submissions = Filename.concat examples "submissions.yaml" in
  let status, output, errors = run evaluator [ suite; submissions ] in
  check "synthetic task has accepted repair" (status = 0 && errors = "");
  let summary = parse output in
  check "one scheduled task" (field "scheduled_tasks" summary = `Float 1.);
  check "one task with valid repair" (field "tasks_with_valid_repair" summary = `Float 1.);
  check "all five attempts evaluated" (field "submitted_attempts" summary = `Float 5.);
  check "no input failures" (field "tasks_with_errors" summary = `Float 0.);
  let task = List.hd (list (field "tasks" summary)) in
  check "first accepted attempt is last" (field "first_valid_attempt" task = `Float 5.);
  check "task provenance synthetic" (field "provenance" task = `String "synthetic");
  check "baseline exact-byte digest" (field "baseline_sha256" task =
    `String (Sha256.string (read_file (Filename.concat examples "before.yaml"))));
  let frozen = match Contract_spec.read_file (Filename.concat examples "admin-get.yaml") with
    | Ok spec -> spec | Error _ -> failwith "fixture contract invalid" in
  check "reviewed contract identity digest" (field "contract_sha256" task =
    `String (Sha256.string (Contract_spec.canonical_json frozen)));
  List.iter2 (fun (file, result, repair) attempt ->
    check (file ^ " contract outcome") (field "contract_result" attempt = `String result);
    check (file ^ " repair outcome") (field "repair_result" attempt = `String repair);
    check (file ^ " candidate-byte digest") (field "candidate_sha256" attempt =
      `String (Sha256.string (read_file (Filename.concat examples file))));
    check (file ^ " not an input error") (field "failure" attempt = `Null))
    [ "before.yaml", "violated", "contract_failed";
      "deny-all.yaml", "violated", "contract_failed";
      "out-of-scope.yaml", "proved", "out_of_scope_regression";
      "unsupported.yaml", "unknown", "unknown";
      "repaired.yaml", "proved", "valid_repair" ]
    (list (field "attempts" task));

  let status, output, errors = run evaluator
    [ Filename.concat examples "public-suite.yaml";
      Filename.concat examples "public-submissions.yaml" ] in
  check "new public-exceptions contract works in the evaluator" (status = 0 && errors = "");
  let summary = parse output in
  check "all four public attempts retained" (field "submitted_attempts" summary = `Float 4.);
  let task = List.hd (list (field "tasks" summary)) in
  check "public contract needs four supplied attempts" (field "first_valid_attempt" task = `Float 4.);
  check "locked health receives no credit despite preserving authentication"
    (list (field "attempts" task) |> List.map (field "repair_result") =
     List.map (fun value -> `String value)
       [ "contract_failed"; "contract_failed"; "contract_failed"; "valid_repair" ]);

  check_coverage evaluator examples;

  let root = Filename.temp_file "soundcheck-repair-cli-" "" in
  Unix.unlink root; Unix.mkdir root 0o700;
  let write name source =
    let channel = open_out_bin (Filename.concat root name) in
    Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel source) in
  let rec remove path =
    if (Unix.lstat path).Unix.st_kind = Unix.S_DIR then begin
      Array.iter (fun name -> remove (Filename.concat path name)) (Sys.readdir path); Unix.rmdir path
    end else Unix.unlink path in
  Fun.protect ~finally:(fun () -> remove root) (fun () ->
    Array.iter (fun name -> write name (read_file (Filename.concat examples name))) (Sys.readdir examples);
    let run_local attempts =
      write "attempts.yaml" ("format_version: 1\nattempts:\n" ^ attempts);
      run evaluator [ Filename.concat root "suite.yaml"; Filename.concat root "attempts.yaml" ] in
    let status, output, errors = run_local (entry "only-deny-all" "deny-all.yaml") in
    check "invalid repair cannot exit zero" (status = 3 && errors = ""
      && field "tasks_with_valid_repair" (parse output) = `Float 0.);
    write "attempts.yaml" "format_version: 1\nattempts: []\n";
    let status, output, errors = run evaluator
      [ Filename.concat root "suite.yaml"; Filename.concat root "attempts.yaml" ] in
    check "missing submission nonzero" (status = 1 && errors = "");
    let task = List.hd (list (field "tasks" (parse output))) in
    check "missing task retained" (field "failure" task = `String "missing_submission"
      && field "first_valid_attempt" task = `Null && field "attempts" task = `A []);
    let secret = "PRIVATE_CANDIDATE_8ae2" in
    write (secret ^ ".yaml") ("services: [{name: " ^ secret ^ ", routes: 17}]\n");
    let status, output, errors = run_local (entry "invalid" (secret ^ ".yaml")
      ^ entry "missing" (secret ^ "-missing.yaml") ^ entry "good" "repaired.yaml") in
    check "input failures remain fatal despite valid later repair" (status = 1 && errors = "");
    check "private input paths/diagnostics not emitted" (not (contains (output ^ errors) secret));
    let summary = parse output in
    check "all failing attempts retained" (field "submitted_attempts" summary = `Float 3.
      && field "errors" (field "attempt_counts" summary) = `Float 2.
      && field "tasks_with_valid_repair" summary = `Float 1.);
    let before = Sys.readdir root |> Array.to_list |> List.sort String.compare in
    let saved = read_file (Filename.concat root "repaired.yaml") in
    ignore (run evaluator [ Filename.concat root "suite.yaml"; Filename.concat root "attempts.yaml" ]);
    check "no automatic artifacts" (before = (Sys.readdir root |> Array.to_list |> List.sort String.compare));
    check "candidate unchanged" (saved = read_file (Filename.concat root "repaired.yaml"));
    Unix.symlink "repaired.yaml" (Filename.concat root "linked.yaml");
    let status, output, errors = run_local (entry "symlink" "linked.yaml") in
    check "candidate symlink rejected" (status = 1 && errors = ""
      && field "errors" (field "attempt_counts" (parse output)) = `Float 1.);
    Unix.symlink "suite.yaml" (Filename.concat root "linked-suite.yaml");
    let status, output, errors = run evaluator
      [ Filename.concat root "linked-suite.yaml"; Filename.concat root "submissions.yaml" ] in
    check "suite symlink rejected" (status = 1 && errors = ""
      && field "failure" (parse output) = `String "suite_read_error");
    let status, output, errors = run_local (entry ~task:"unknown" "bad-task" "repaired.yaml") in
    let summary = parse output in
    check "unknown task cannot be silently dropped" (status = 1 && errors = ""
      && field "failure" (List.hd (list (field "tasks" summary))) = `String "submissions_invalid");
    check "invalid submissions retain known suite denominator" (field "scheduled_tasks" summary = `Float 1.
      && field "tasks_with_errors" summary = `Float 1. && field "submitted_attempts" summary = `Null);
    write "attempts.yaml" "format_version: 1\nattempts: [{task: frozen-admin, id: a, config: repaired.yaml, contract: weaker.yaml}]\n";
    let status, output, errors = run evaluator
      [ Filename.concat root "suite.yaml"; Filename.concat root "attempts.yaml" ] in
    check "contract substitution rejected" (status = 1 && errors = ""
      && field "failure" (List.hd (list (field "tasks" (parse output)))) = `String "submissions_invalid");
    let status, output, errors = run evaluator
      [ Filename.concat root "suite.yaml"; Filename.concat root "missing/attempts.yaml" ] in
    check "unreadable submissions retain known suite" (status = 1 && errors = ""
      && field "scheduled_tasks" (parse output) = `Float 1.
      && field "failure" (List.hd (list (field "tasks" (parse output)))) = `String "submissions_read_error");
    write "before.yaml" (read_file (Filename.concat examples "unsupported.yaml"));
    let status, output, errors = run_local (entry "supported-candidate-unknown-baseline" "repaired.yaml") in
    let task = List.hd (list (field "tasks" (parse output))) in
    let attempt = List.hd (list (field "attempts" task)) in
    check "candidate assurance does not establish baseline preservation"
      (status = 3 && errors = ""
       && field "contract_result" attempt = `String "proved"
       && field "repair_result" attempt = `String "unknown"
       && field "contract_assurance" attempt = `String "within_profile"
       && field "first_valid_attempt" task = `Null);
    write "before.yaml" "services: malformed\n";
    let status, output, errors = run_local (entry "valid-candidate-bad-baseline" "repaired.yaml") in
    check "malformed baseline cannot count as valid repair" (status = 1 && errors = ""
      && field "tasks_with_valid_repair" (parse output) = `Float 0.);
    let status, output, errors = run evaluator [ "--extra"; secret; "argument" ] in
    check "usage does not echo inputs" (status = 2 && output = "" && not (contains errors secret)));
  Printf.printf "All %d submitted-repair CLI checks passed.\n" !checks
