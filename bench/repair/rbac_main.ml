let load path =
  try
    let root = Unix.realpath (Filename.dirname path) in
    match Pilot.read_regular ~root (Filename.basename path) with
    | Error () -> Error () | Ok bytes -> Ok (root, bytes)
  with _ -> Error ()

let fail failure = print_endline (Rbac_repair_bench.fatal_json failure); exit 1
let failed_schedule failure suite =
  print_endline (Rbac_repair_bench.to_json (Rbac_repair_bench.failed_tasks failure suite)); exit 1

let () =
  try match Array.to_list Sys.argv with
  | [_;suite_path;submissions_path] ->
    (match load suite_path with
     | Error () -> fail "suite_read_error"
     | Ok (suite_root, source) ->
       match Pilot.parse_manifest source with
       | Error () -> fail "suite_invalid"
       | Ok tasks ->
         let suite = Rbac_repair_bench.freeze ~suite_root tasks in
         match load submissions_path with
         | Error () -> failed_schedule Rbac_repair_bench.Submissions_read_error suite
         | Ok (submission_root, source) ->
           match Rbac_repair_bench.parse_submissions suite source with
           | Error () -> failed_schedule Rbac_repair_bench.Submissions_invalid suite
           | Ok attempts ->
             let rows = Rbac_repair_bench.run ~submission_root suite attempts in
             print_endline (Rbac_repair_bench.to_json rows);
             exit (Rbac_repair_bench.exit_code rows))
  | _ ->
    prerr_endline "usage: dune exec bench/repair/rbac_main.exe -- SUITE.yaml SUBMISSIONS.yaml";
    exit 2
  with _ -> fail "runner_error"
