let load path =
  try
    let root = Unix.realpath (Filename.dirname path) in
    match Pilot.read_regular ~root (Filename.basename path) with
    | Error () -> Error () | Ok bytes -> Ok (root, bytes)
  with _ -> Error ()

let fail failure = print_endline (Repair_bench.fatal_json failure); exit 1
let failed_schedule failure tasks =
  print_endline (Repair_bench.to_json (Repair_bench.failed_tasks failure tasks)); exit 1

let () =
  try match Array.to_list Sys.argv with
  | [ _; suite_path; submissions_path ] ->
    (match load suite_path with
     | Error () -> fail "suite_read_error"
     | Ok (suite_root, source) ->
       match Pilot.parse_manifest source with
       | Error () -> fail "suite_invalid"
       | Ok tasks ->
         match load submissions_path with
         | Error () -> failed_schedule Repair_bench.Submissions_read_error tasks
         | Ok (submission_root, source) ->
           match Repair_bench.parse_submissions ~tasks source with
           | Error () -> failed_schedule Repair_bench.Submissions_invalid tasks
           | Ok attempts ->
             let rows = Repair_bench.run ~suite_root ~submission_root tasks attempts in
             print_endline (Repair_bench.to_json rows);
             exit (Repair_bench.exit_code rows))
  | _ ->
    prerr_endline "usage: dune exec bench/repair/main.exe -- SUITE.yaml SUBMISSIONS.yaml";
    exit 2
  with _ -> fail "runner_error"
