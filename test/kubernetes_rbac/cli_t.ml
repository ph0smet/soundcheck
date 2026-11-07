open Soundcheck_kubernetes_rbac

let count = ref 0
let check name value = incr count; if not value then failwith name
let read path =
  let ch = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr ch) (fun () -> really_input_string ch (in_channel_length ch))
let write path text = let ch = open_out_bin path in output_string ch text; close_out ch
let assoc key = function `O fields -> List.assoc key fields | _ -> failwith ("not object: " ^ key)
let contains text fragment =
  let rec search index =
    index + String.length fragment <= String.length text &&
    (String.sub text index (String.length fragment) = fragment || search (index+1)) in
  search 0

let run binary args =
  let output = Filename.temp_file "rbac-cli-" ".out" in
  let error = Filename.temp_file "rbac-cli-" ".err" in
  Fun.protect ~finally:(fun () -> Sys.remove output;Sys.remove error) (fun () ->
    let stdout = Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let stderr = Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid = Unix.create_process binary (Array.of_list (binary::args)) Unix.stdin stdout stderr in
    Unix.close stdout;Unix.close stderr;
    let _,status = Unix.waitpid [] pid in
    let code = match status with Unix.WEXITED n -> n | _ -> failwith "CLI terminated" in
    code,read output,read error)

let () =
  let binary = Sys.argv.(1) and root = Sys.argv.(2) in
  let contract = root ^ "/contracts/frontend-access.json" in
  let original_contract = read contract in
  let spec = match Contract_spec.of_string original_contract with Ok x -> x | Error e -> failwith e in
  let canonical = Contract_spec.canonical spec in
  let fixture name = root ^ "/fixtures/" ^ name ^ ".json" in
  let invoke command expected =
    let code,output,error = run binary ("rbac" :: command @ ["--contract";contract;"--format";"json"]) in
    check ("exit: " ^ String.concat " " command ^ error) (code=expected);
    let result = Input.parse output in
    check "schema10" (assoc "schema_version" result = `Number "10");
    check "frozen canonical unchanged" (assoc "canonical" (assoc "frozen_spec" result) = `String canonical);
    check "profile id" (assoc "profile" (assoc "assurance" result) = `String Assurance.profile_id);
    result in
  let unsafe = invoke ["verify";fixture "01-unsafe"] 3 in
  check "unwanted grant clause" (assoc "kind" (assoc "clause" unsafe) = `String "must_not_grant");
  let witness = assoc "counterexample" unsafe in
  check "named identity" (assoc "principal" witness = `String "system:serviceaccount:frontend:frontend-sa");
  check "object namespace" (assoc "namespace" (assoc "object_request" witness) = `String "payments");
  check "object resource" (assoc "resource_kind" (assoc "object_request" witness) = `String "secrets");
  check "grant evidence" (match assoc "granting_rules" witness with `A (_::_) -> true | _ -> false);
  let removed = invoke ["verify";fixture "02-delete-workload-grants"] 3 in
  check "required access clause" (assoc "kind" (assoc "clause" removed) = `String "must_allow");
  check "no fabricated grant" (assoc "granting_rules" (assoc "counterexample" removed) = `A []);
  let repaired = invoke ["verify";fixture "03-valid-repair"] 0 in
  check "valid repair" (assoc "result" repaired = `String "proved");
  let preserved = invoke ["compare";fixture "01-unsafe";fixture "03-valid-repair"] 0 in
  check "joint repair proof" (assoc "property" preserved = `String "rbac-repair-preservation");
  let regression = invoke ["compare";fixture "01-unsafe";fixture "16-operator-regression"] 3 in
  check "preservation clause" (assoc "kind" (assoc "clause" regression) = `String "must_preserve");
  check "operator witness" (assoc "principal" (assoc "counterexample" regression) = `String "ops-auditor");
  let candidate_failure = invoke ["compare";fixture "01-unsafe";fixture "02-delete-workload-grants"] 3 in
  check "candidate contract checked first" (assoc "kind" (assoc "clause" candidate_failure) = `String "must_allow");
  List.iter (fun name ->
      let result = invoke ["verify";fixture name] 4 in
      check "unsupported is unknown" (assoc "result" result = `String "unknown");
      check "unsupported assurance" (assoc "status" (assoc "assurance" result) = `String "unsupported"))
    ["17-missing-reference";"18-aggregation-boundary";"26-trailing-json-document"];
  let github command expected fragments =
    let code,output,error = run binary ("rbac" :: command @ ["--contract";contract;"--format";"github"]) in
    check ("GitHub exit: " ^ String.concat " " command ^ error) (code=expected);
    check "GitHub report has no stderr" (error="");
    check "one GitHub annotation" (List.length (String.split_on_char '\n' (String.trim output))=1);
    List.iter (fun fragment -> check ("GitHub annotation contains " ^ fragment) (contains output fragment)) fragments;
    output in
  ignore (github ["verify";fixture "01-unsafe"] 3
            ["::error file=";" get secrets/";"in namespace payments";"granting rules [";"must_not_grant"]);
  ignore (github ["verify";fixture "02-delete-workload-grants"] 3
            ["::error file=";"NoOpinion";"granting rules []";"must_allow"]);
  ignore (github ["verify";fixture "03-valid-repair"] 0
            ["::notice file=";"proved";"frozen spec ";Assurance.profile_id]);
  ignore (github ["verify";fixture "18-aggregation-boundary"] 4
            ["::error file=";"unknown";"unsupported"]);
  ignore (github ["compare";fixture "01-unsafe";fixture "03-valid-repair"] 0
            ["::notice file=" ^ fixture "03-valid-repair";"rbac-repair-preservation proved"]);
  ignore (github ["compare";fixture "01-unsafe";fixture "16-operator-regression"] 3
            ["::error file=" ^ fixture "16-operator-regression";"ops-auditor get configmaps/";"Allow to NoOpinion";"must_preserve"]);
  let missing = root ^ "/missing\n::notice::injected.json" in
  let code,output,error = run binary ["rbac";"verify";missing;"--contract";contract;"--format";"github"] in
  check "GitHub I/O errors retain exit 1" (code=1 && error="");
  check "GitHub I/O errors are escaped annotations"
    (String.starts_with ~prefix:"::error file=" output && contains output "%0A::notice::injected.json" &&
     List.length (String.split_on_char '\n' (String.trim output))=1);
  List.iter (fun args ->
      let code,_,_ = run binary args in check "invalid flags cannot replace frozen scope" (code=2))
    [["rbac";"verify";fixture "03-valid-repair"];
     ["rbac";"verify";fixture "03-valid-repair";"--contract";contract;"--subject";"alice"];
     ["rbac";"verify";fixture "03-valid-repair";"--contract";contract;"--contract";contract];
     ["rbac";"verify";fixture "03-valid-repair";"--contract";contract;"--format";"json";"--format";"human"]];
  let temporary = Filename.temp_file "rbac-bad-contract-" ".json" in
  Fun.protect ~finally:(fun () -> Sys.remove temporary) (fun () ->
    write temporary (original_contract ^ "{}");
    let code,output,_ = run binary ["rbac";"verify";fixture "03-valid-repair";"--contract";temporary;"--format";"json"] in
    check "malformed contract blocks proof" (code=4 && assoc "result" (Input.parse output)=`String "unknown");
    let code,output,error = run binary ["rbac";"verify";fixture "03-valid-repair";"--contract";temporary;"--format";"github"] in
    check "GitHub malformed contract blocks proof" (code=4 && error="" && String.starts_with ~prefix:"::error file=" output);
    let code,output,error = run binary ["rbac";"verify";fixture "03-valid-repair";"--contract";contract;
                                     "--format";"github";"--evidence-dir";temporary] in
    check "GitHub evidence error cannot publish a proof verdict"
      (code=1 && error="" && String.starts_with ~prefix:"::error file=" output &&
       contains output "evidence error" && not (contains output "::notice")));
  let code,output,_ = run binary ["profile";"kubernetes-rbac";"--format";"json"] in
  check "profile command" (code=0 && assoc "id" (Input.parse output)=`String Assurance.profile_id);
  check "contract file not changed" (read contract = original_contract);
  Printf.printf "RBAC CLI: %d checks passed\n" !count
