open Soundcheck_core
open Soundcheck_kong

let fail format = Printf.ksprintf failwith format
let ok = function Ok value -> value | Error reason -> fail "%s" reason

let read_all channel =
  let buffer = Buffer.create 1024 in
  (try
     while true do
       Buffer.add_string buffer (input_line channel);
       Buffer.add_char buffer '\n'
     done
   with End_of_file -> ());
  Buffer.contents buffer

let read_file path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      really_input_string channel (in_channel_length channel))

let write_file path contents =
  let channel = open_out_bin path in
  output_string channel contents;
  close_out channel

let rec cleanup path =
  match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR ->
    Sys.readdir path |> Array.iter (fun name -> cleanup (Filename.concat path name));
    Unix.rmdir path
  | _ -> Unix.unlink path

let temporary_directory () =
  let path = Filename.temp_file "soundcheck-evidence-cli-" "" in
  Unix.unlink path;
  Unix.mkdir path 0o700;
  path

let run executable arguments =
  let arguments = Array.of_list (executable :: arguments) in
  let channels = Unix.open_process_args_full executable arguments (Unix.environment ()) in
  let stdout, _, stderr = channels in
  let output = read_all stdout in
  let errors = read_all stderr in
  (Unix.close_process_full channels, output, errors)

let expect_exit executable arguments expected =
  let status, output, errors = run executable arguments in
  match status with
  | Unix.WEXITED code when code = expected -> output
  | _ -> fail "expected exit %d\nstdout: %s\nstderr: %s" expected output errors

let parse source =
  match Yaml.of_string source with
  | Ok value -> value
  | Error (`Msg reason) -> fail "invalid bundle JSON: %s" reason

let field name = function
  | `O fields ->
    (match List.assoc_opt name fields with
     | Some value -> value
     | None -> fail "missing bundle field %s" name)
  | _ -> fail "expected an object containing %s" name

let string name value =
  match field name value with `String text -> text | _ -> fail "%s is not a string" name

let list name value =
  match field name value with `A entries -> entries | _ -> fail "%s is not an array" name

let artifact directory value =
  let path = Filename.concat directory (string "path" value) in
  let contents = read_file path in
  if Sha256.string contents <> string "sha256" value then
    fail "artifact digest did not bind %s" path;
  contents

let assert_bundle ~soundcheck ~directory ~config ~canonical ~output ~verdict
    ~results =
  let manifest = read_file (Filename.concat directory "manifest.json") |> parse in
  if field "schema_version" manifest <> `Float 1. then fail "unexpected bundle version";
  if string "result" manifest <> verdict then fail "bundle verdict changed";
  let config_metadata = field "config" manifest in
  if string "sha256" config_metadata <> Sha256.string config
     || field "size_bytes" config_metadata <> `Float (float_of_int (String.length config))
  then fail "config digest did not bind the verified input bytes";
  if Sys.file_exists (Filename.concat directory "config.yaml") then
    fail "evidence copied the config unexpectedly";
  if artifact directory (field "contract" manifest) <> canonical ^ "\n" then
    fail "bundle contract changed frozen identity";
  let profile = field "assurance_profile" manifest in
  if string "id" profile <> Assurance.profile.id
     || artifact directory (field "artifact" profile) <> Assurance.profile_json () ^ "\n"
  then fail "bundle omitted the complete assurance profile";
  let report = artifact directory (field "report" manifest) in
  if report <> output then fail "bundle changed the standard JSON report";
  let parsed_report = parse report in
  if string "result" parsed_report <> verdict
     || string "canonical" (field "frozen_spec" parsed_report) <> canonical
  then fail "bundle report lost the verdict or frozen identity";
  let build = field "soundcheck" manifest in
  if string "executable_sha256" build <> ok (Sha256.file soundcheck)
     || string "ocaml_version" build <> Sys.ocaml_version
     || field "report_schema_version" build <> `Float (float_of_int Report.schema_version)
  then fail "bundle build identity did not bind the verifier executable";
  let solver = field "solver" manifest in
  if string "name" solver <> "z3"
     || string "version" solver <> ok (Solve.version ())
     || field "version_error" solver <> `Null
  then fail "bundle did not capture the solver version";
  let obligations = list "obligations" manifest in
  let actual_results =
    List.map
      (fun entry ->
        let query = field "query" entry in
        ignore (artifact directory query);
        match field "solver_result" entry with
        | `Null ->
          if string "execution" entry <> "not_executed"
             || field "model" entry <> `Null || field "reason" entry <> `Null
          then fail "skipped query was recorded as executed";
          None
        | `String result ->
          if string "execution" entry <> "executed" then fail "executed query was skipped";
          let query_path = Filename.concat directory (string "path" query) in
          let _, replay, _ = run "z3" [ "-smt2"; query_path ] in
          let first_line = String.split_on_char '\n' replay |> List.hd |> String.trim in
          if first_line <> result then fail "saved query did not replay as %s" result;
          (match result, field "model" entry with
           | "sat", (`O _ as witness) ->
             if string "method" witness <> "GET"
                || not (String.starts_with ~prefix:"/admin" (string "path" witness))
             then fail "solver witness escaped the frozen request scope"
           | "unsat", `Null -> ()
           | _ -> fail "unexpected solver result or model");
          Some result
        | _ -> fail "invalid solver result")
      obligations
  in
  if actual_results <> results then fail "bundle omitted or reordered obligations";
  let planned = field "obligation_plan" manifest in
  if verdict = "unknown" then begin
    if string "status" planned <> "unavailable" || obligations <> []
       || field "reason" planned <> field "reason" parsed_report
    then fail "unsupported config acquired misleading obligations"
  end else if string "status" planned <> "complete" || field "reason" planned <> `Null then
    fail "valid config did not retain its complete obligation plan";
  let expected_queries =
    List.map (fun entry -> string "id" entry ^ ".smt2") obligations |> List.sort compare
  in
  let actual_queries =
    Sys.readdir (Filename.concat directory "queries") |> Array.to_list |> List.sort compare
  in
  if actual_queries <> expected_queries then fail "query files did not match the manifest";
  let top_level = Sys.readdir directory |> Array.to_list |> List.sort compare in
  if top_level <> [ "assurance-profile.json"; "contract.json"; "manifest.json"; "queries"; "report.json" ]
  then fail "bundle retained temporary or unexpected files"

let () =
  if Array.length Sys.argv <> 7 then
    fail "expected soundcheck, contract, unsafe, repaired, deny-all, and unsupported paths";
  let soundcheck = Sys.argv.(1) and contract_path = Sys.argv.(2) in
  let spec = ok (Contract_spec.read_file contract_path) in
  let canonical = Contract_spec.canonical_json spec in
  let directory = temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
      let verify file contract format extra =
        [ "verify"; file; "--contract"; contract; "--format"; format ] @ extra
      in
      List.iter
        (fun (name, file, verdict, exit, results) ->
          let target = Filename.concat directory name in
          let arguments = verify file contract_path "json" [ "--evidence-dir"; target ] in
          let output = expect_exit soundcheck arguments exit in
          assert_bundle ~soundcheck ~directory:target ~config:(read_file file)
            ~canonical ~output ~verdict ~results)
        [ ("proved bundle", Sys.argv.(4), "proved", 0,
           List.map Option.some [ "sat"; "sat"; "unsat"; "unsat"; "unsat" ]);
          ("violated", Sys.argv.(3), "violated", 3,
           [ Some "sat"; Some "sat"; Some "unsat"; Some "sat"; None ]);
          ("deny-all", Sys.argv.(5), "violated", 3,
           List.map Option.some [ "sat"; "sat"; "unsat"; "unsat"; "sat" ]);
          ("unsupported", Sys.argv.(6), "unknown", 4, []) ];
      let network_path = Filename.concat directory "network.yaml" in
      write_file network_path
        "schema_version: 1\nkind: network-restricted-access\nscope: {path_prefix: /admin, method: GET, trusted_cidr: 0.0.0.0/0}\nassumptions: {source_ip_integrity: externally-enforced}\n";
      let network = ok (Contract_spec.read_file network_path) in
      let target = Filename.concat directory "vacuous" in
      let output =
        expect_exit soundcheck
          (verify Sys.argv.(4) network_path "json" [ "--evidence-dir"; target ]) 5
      in
      assert_bundle ~soundcheck ~directory:target ~config:(read_file Sys.argv.(4))
        ~canonical:(Contract_spec.canonical_json network) ~output ~verdict:"vacuous"
        ~results:[ Some "unsat"; None; None; None; None ];
      List.iter
        (fun format ->
          let arguments = verify Sys.argv.(4) contract_path format [] in
          let baseline = expect_exit soundcheck arguments 0 in
          let target = Filename.concat directory format in
          let output = expect_exit soundcheck (arguments @ [ "--evidence-dir"; target ]) 0 in
          if output <> baseline then fail "evidence changed %s stdout" format)
        [ "human"; "json"; "github" ];
      let existing = Filename.concat directory "proved bundle" in
      let original = read_file (Filename.concat existing "manifest.json") in
      ignore (expect_exit soundcheck
                (verify Sys.argv.(4) contract_path "json" [ "--evidence-dir"; existing ]) 1);
      if read_file (Filename.concat existing "manifest.json") <> original then
        fail "CLI overwrote existing evidence";
      let occupied = Filename.concat directory "occupied" in
      write_file occupied "preserve me";
      ignore (expect_exit soundcheck
                (verify Sys.argv.(4) contract_path "json" [ "--evidence-dir"; occupied ]) 1);
      if read_file occupied <> "preserve me" then fail "CLI overwrote an existing file";
      let unused = Filename.concat directory "unused" in
      List.iter
        (fun arguments -> ignore (expect_exit soundcheck arguments 2))
        [ [ "verify"; Sys.argv.(4); "--evidence-dir"; unused ];
          verify Sys.argv.(4) contract_path "json" [ "--evidence-dir" ];
          verify Sys.argv.(4) contract_path "json" [ "--evidence-dir"; "--format"; "json" ];
          verify Sys.argv.(4) contract_path "json"
            [ "--evidence-dir"; unused; "--evidence-dir"; unused ];
          verify Sys.argv.(4) contract_path "json"
            [ "--evidence-dir"; unused; "--path-prefix"; "/public" ];
          verify Sys.argv.(4) contract_path "json"
            [ "--evidence-dir"; unused; "--emit-smt"; Filename.concat directory "query.smt2" ];
          [ "mcp"; "--contract"; contract_path; "--evidence-dir"; unused ];
          [ "compare"; Sys.argv.(3); Sys.argv.(4); "--contract"; contract_path;
            "--evidence-dir"; unused ] ];
      let malformed = Filename.concat directory "malformed.yaml" in
      write_file malformed "services: [\n";
      ignore (expect_exit soundcheck
                (verify malformed contract_path "json" [ "--evidence-dir"; unused ]) 1);
      let invalid_contract = Filename.concat directory "invalid-contract.yaml" in
      write_file invalid_contract "schema_version: 2\nkind: authenticated-access\nscope: {path_prefix: /admin}\n";
      ignore (expect_exit soundcheck
                (verify Sys.argv.(4) invalid_contract "json" [ "--evidence-dir"; unused ]) 2);
      if Sys.file_exists unused then fail "invalid invocation created evidence")
