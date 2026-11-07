open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let checks = ref 0
let check label value = incr checks; if not value then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
    really_input_string channel (in_channel_length channel))
let write path contents =
  let channel = open_out_bin path in output_string channel contents; close_out channel
let field name = function
  | `O fields -> (match List.assoc_opt name fields with Some value -> value | None -> failwith ("missing field " ^ name))
  | _ -> failwith ("expected object for " ^ name)
let string name value = K.Input.str name (field name value)
let array name value = K.Input.arr name (field name value)
let strings name value = K.Input.strings name (field name value)
let json = K.Input.parse
let contains text fragment =
  let rec loop i = i + String.length fragment <= String.length text
    && (String.sub text i (String.length fragment) = fragment || loop (i + 1)) in loop 0
let replace key value = function
  | `O fields -> `O (List.map (fun (name,old) -> name,if name=key then value else old) fields)
  | _ -> failwith "replace expected object"

let rec cleanup path =
  match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path
let temporary_directory () =
  let path = Filename.temp_file "soundcheck-rbac-evidence-" "" in
  Unix.unlink path;Unix.mkdir path 0o700;path

(* This executable also supplies intentionally bad solver responses. The SAT
   reply is well-formed and includes every requested typed dimension, but its
   principal is outside the frozen context. This tests witness validation rather
   than accidentally succeeding through a malformed-protocol rejection. *)
let () =
  if Array.length Sys.argv = 3 && Sys.argv.(1) = "-smt2" then begin
    let source = read Sys.argv.(2) in
    let observation = contains source "(get-value" in
    let log = open_out_gen [Open_wronly;Open_creat;Open_append] 0o600 (Sys.getenv "SOUNDCHECK_RBAC_EVIDENCE_LOG") in
    output_string log (if observation then "observation\n" else "check\n");close_out log;
    (match Sys.getenv "SOUNDCHECK_RBAC_EVIDENCE_FAKE" with
     | "unknown" -> print_endline "unknown"
     | "invalid-sat" ->
       print_endline "sat";
       if observation then print_endline
         {|((path "") (method "get") (is_anon false) (src_ip #x00000000) (host "") (scheme "") (sni "") (principal_name "outside-frozen-context") (has_object_request true) (object_namespace "frontend") (object_kind "configmaps") (object_name "settings"))|}
     | _ -> failwith "unknown fake solver mode");
    exit 0
  end

let run binary args =
  let output = Filename.temp_file "rbac-evidence-stdout-" "" in
  let error = Filename.temp_file "rbac-evidence-stderr-" "" in
  Fun.protect ~finally:(fun () -> Sys.remove output;Sys.remove error) (fun () ->
    let out_fd = Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let err_fd = Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid = Unix.create_process binary (Array.of_list (binary::args)) Unix.stdin out_fd err_fd in
    Unix.close out_fd;Unix.close err_fd;
    let _,status = Unix.waitpid [] pid in
    let code = match status with Unix.WEXITED code -> code | _ -> failwith "CLI terminated" in
    code,read output,read error)

let artifact directory metadata =
  let path = string "path" metadata in
  let contents = read (Filename.concat directory path) in
  check ("artifact SHA-256 " ^ path) (string "sha256" metadata = Sha256.string contents);
  contents

let saved_model value : Solve.model =
  let coordinates = field "object_request" value in
  {path=string "path" value;method_=string "method" value;
   is_anon=(string "principal" value = "anonymous");
   principal_name=Some (string "principal_name" value);
   object_request=Some {namespace=string "namespace" coordinates;
     resource_kind=string "resource_kind" coordinates;name=string "name" coordinates};
   src_ip=(ok (Cidr.parse (string "source_ip" value))).base;
   host=string "host" value;scheme=string "scheme" value;sni=string "sni" value;
   headers=List.map (fun header -> string "name" header,string "value" header) (array "headers" value)}

let validate_sat policy (contract : Contract.t) (obligation : Contract_verify.obligation) model =
  let request = Witness.request_of_model model in
  let clauses = List.map (fun name -> List.find (fun clause -> Contract.name clause=name) contract.clauses)
      obligation.clauses in
  let valid =
    if obligation.phase = Contract_verify.Inhabitance then
      Witness.condition ~domain:policy.Ir.request_domain (Contract.request_class (List.hd clauses)) request
    else if obligation.phase = Contract_verify.Consistency then
      Witness.condition ~domain:policy.request_domain
        (Ir.And (List.map Contract.request_class clauses)) request
    else Witness.clause policy (List.hd clauses) request in
  check ("SAT model satisfies " ^ obligation.id) valid

let assert_bundle ~binary ~z3_version ~directory ~source ~spec ~stdout ~outcome ~statuses =
  let manifest = json (read (Filename.concat directory "manifest.json")) in
  let canonical = K.Contract_spec.canonical spec in
  check "manifest schema" (field "schema_version" manifest = `Number (string_of_int Evidence.schema_version));
  check "manifest verdict" (string "result" manifest = outcome);
  let config = field "config" manifest in
  check "digest binds exact original snapshot bytes" (string "sha256" config = Sha256.string source);
  check "size binds exact original snapshot bytes"
    (field "size_bytes" config = `Number (string_of_int (String.length source)));
  check "frozen contract artifact retains exact canonical context/clauses/change scope"
    (artifact directory (field "contract" manifest) = canonical ^ "\n");
  let profile = field "assurance_profile" manifest in
  check "profile identity" (string "id" profile = K.Assurance.profile_id);
  check "complete profile artifact"
    (artifact directory (field "artifact" profile) = K.Assurance.profile_json () ^ "\n");
  let report_text = artifact directory (field "report" manifest) in
  check "report artifact equals normal JSON stdout byte-for-byte" (report_text = stdout);
  let report = json report_text in
  check "report verdict" (string "result" report = outcome);
  check "report frozen identity" (string "canonical" (field "frozen_spec" report) = canonical);
  let provenance = field "soundcheck" manifest in
  check "actual verifier executable digest" (string "executable_sha256" provenance = ok (Sha256.file binary));
  check "actual OCaml version" (string "ocaml_version" provenance = Sys.ocaml_version);
  check "report schema provenance" (field "report_schema_version" provenance = `Number (string_of_int Report.schema_version));
  let solver = field "solver" manifest in
  check "actual Z3 provenance"
    (string "name" solver = "z3" && string "version" solver = z3_version && field "version_error" solver = `Null);
  let entries = array "obligations" manifest in
  let plan_info = field "obligation_plan" manifest in
  let expected_plan,policy = match K.Snapshot.of_string source with
    | Error _ -> [],None
    | Ok snapshot ->
      let policy = K.Lower.policy spec snapshot in
      Contract_verify.plan policy (K.Contract_spec.to_contract spec),Some policy in
  check "every planned obligation is retained" (List.length entries = List.length expected_plan);
  check "independent fixture status vector length" (List.length entries = List.length statuses);
  (match policy with
   | None ->
     check "unsupported plan unavailable" (string "status" plan_info = "unavailable" && entries=[]);
     check "unavailable reason preserved" (field "reason" plan_info = field "reason" report)
   | Some _ -> check "supported plan complete" (string "status" plan_info = "complete" && field "reason" plan_info = `Null));
  List.iter2 (fun ((obligation : Contract_verify.obligation),entry) expected ->
    check "obligation order and identity" (string "id" entry = obligation.id);
    check "obligation related clauses" (strings "clauses" entry = obligation.clauses);
    let phase = if obligation.phase=Contract_verify.Inhabitance then "inhabitance"
      else if obligation.phase=Contract_verify.Consistency then "consistency" else "clause" in
    check "obligation phase" (string "phase" entry = phase);
    let query = artifact directory (field "query" entry) in
    check "query is the actual complete planned formula" (query = obligation.smtlib);
    check "query filename is bound to stable obligation ID"
      (string "path" (field "query" entry) = "queries/" ^ obligation.id ^ ".smt2");
    match expected with
    | None ->
      check "short-circuited query remains unexecuted"
        (string "execution" entry="not_executed" && field "solver_result" entry=`Null
         && field "model" entry=`Null && field "reason" entry=`Null)
    | Some expected ->
      check "executed query status" (string "execution" entry="executed" && string "solver_result" entry=expected);
      check "successful query lacks error reason" (field "reason" entry=`Null);
      let policy = Option.get policy in
      let contract = K.Contract_spec.to_contract spec in
      (match expected,field "model" entry with
       | "sat",(`O _ as model) -> validate_sat policy contract obligation (saved_model model)
       | "unsat",`Null -> ()
       | _ -> failwith "incorrect stored model/status pairing");
      (* Solve.check handles the conditional get-value observation: direct batch
         replay after UNSAT can legitimately report model-unavailable. *)
      (match Solve.check query,expected with
       | Solve.Proved,"unsat" -> ()
       | Solve.Violated model,"sat" -> validate_sat policy contract obligation model
       | _ -> failwith ("saved formula failed replay: " ^ obligation.id)))
    (List.combine expected_plan entries) statuses;
  let actual_queries = Sys.readdir (Filename.concat directory "queries") |> Array.to_list |> List.sort compare in
  let expected_queries = List.map (fun (item : Contract_verify.obligation) -> item.id ^ ".smt2") expected_plan |> List.sort compare in
  check "no missing or unlisted query payloads" (actual_queries=expected_queries);
  let top_level = Sys.readdir directory |> Array.to_list |> List.sort compare in
  check "only declared artifacts; raw snapshot not copied"
    (top_level=["assurance-profile.json";"contract.json";"manifest.json";"queries";"report.json"]);
  if outcome="violated" then begin
    let decisive = List.rev entries |> List.find (fun entry -> field "solver_result" entry=`String "sat") in
    let model = field "model" decisive and witness = field "counterexample" report in
    check "reported named witness is exactly the checked stored witness"
      (field "principal" witness=field "principal_name" model && field "object_request" witness=field "object_request" model);
    let identity = K.Contract_spec.identities spec |> List.find
      (fun (identity : K.Identity.identity) -> identity.username=string "principal" witness) in
    check "reported groups remain frozen" (strings "identity_groups" witness=identity.groups)
  end

let mock_trace ~directory ~spec ~source =
  let binary = if Filename.is_relative Sys.executable_name then Filename.concat (Sys.getcwd ()) Sys.executable_name else Sys.executable_name in
  let log = Filename.concat directory "solver-calls" in
  let variables = ["SOUNDCHECK_RBAC_EVIDENCE_FAKE";"SOUNDCHECK_RBAC_EVIDENCE_LOG"] in
  let previous = List.map (fun key -> key,Sys.getenv_opt key) variables in
  Fun.protect ~finally:(fun () -> List.iter (fun (key,value) -> Unix.putenv key (Option.value ~default:"" value)) previous)
    (fun () -> List.iter (fun (mode,calls) ->
      write log "";
      Unix.putenv "SOUNDCHECK_RBAC_EVIDENCE_FAKE" mode;
      Unix.putenv "SOUNDCHECK_RBAC_EVIDENCE_LOG" log;
      let report,trace = K.Verify.run_with_trace ~z3:binary spec source in
      check (mode ^ " report unknown") (match report.result with Report.Unknown _ -> true | _ -> false);
      check (mode ^ " report has no unchecked witness") (field "counterexample" (json (Report.to_json report))=`Null);
      let entries = Option.get trace in
      let policy = K.Lower.policy spec (ok (K.Snapshot.of_string source)) in
      check (mode ^ " full library plan")
        (List.map (fun entry -> entry.Contract_verify.obligation) entries = Contract_verify.plan policy (K.Contract_spec.to_contract spec));
      let reason = match (List.hd entries).execution with
        | Contract_verify.Executed (Solve.Unknown reason) -> reason
        | _ -> failwith "unknown was replaced by an unchecked SAT result" in
      if mode="invalid-sat" then check "valid protocol reached semantic witness validation" (contains reason "witness validation failed");
      check "remaining solver calls were actually skipped"
        (read log=calls && List.for_all (fun entry -> entry.Contract_verify.execution=Contract_verify.Not_executed) (List.tl entries));
      let profile : Evidence.profile = {id=K.Assurance.profile_id;json=K.Assurance.profile_json ()} in
      let provenance : Evidence.provenance = {executable_sha256=ok (Sha256.file binary);ocaml_version=Sys.ocaml_version;
        z3_version=Error "mock solver has no version"} in
      let bundle = ok (Evidence.create ~config:source ~profile ~provenance ~report ~trace) in
      let manifest = List.assoc "manifest.json" (Evidence.files bundle) |> json in
      check "solver unknown retains complete plan" (string "status" (field "obligation_plan" manifest)="complete");
      let first = List.hd (array "obligations" manifest) in
      check "unknown trace never publishes the forged SAT model"
        (string "solver_result" first="unknown" && field "model" first=`Null && string "reason" first=reason);
      check "unavailable solver version remains explicit"
        (field "version" (field "solver" manifest)=`Null
         && string "version_error" (field "solver" manifest)="mock solver has no version");
      check "bundle construction does not rerun the solver" (read log=calls))
      ["unknown","check\n";"invalid-sat","check\nobservation\n"])

let () =
  if Array.length Sys.argv<>3 then failwith "expected CLI binary and RBAC corpus root";
  let binary = Sys.argv.(1) and root = Sys.argv.(2) in
  let contract_path = root ^ "/contracts/frontend-access.json" in
  let contract_source = read contract_path in
  let spec = ok (K.Contract_spec.of_string contract_source) in
  let fixture name = root ^ "/fixtures/" ^ name ^ ".json" in
  let directory = temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    let z3_version = ok (Solve.version ()) in
    let invoke ~source_path ~contract ~format extra expected =
      let code,stdout,stderr = run binary (["rbac";"verify";source_path;"--contract";contract;"--format";format] @ extra) in
      check ("CLI exit: " ^ stderr) (code=expected);stdout in
    let padded = Filename.concat directory "snapshot with spaces.json" in
    let padded_source = "\n " ^ read (fixture "03-valid-repair") ^ "\n " in
    write padded padded_source;
    let conflict_value = json contract_source in
    let required = List.hd (array "clauses" conflict_value) in
    let conflicting = required |> replace "name" (`String "conflict") |> replace "kind" (`String "must_not_grant") in
    let conflict_source = replace "clauses" (`A [required;conflicting]) conflict_value |> K.Input.json in
    let conflict_spec = ok (K.Contract_spec.of_string conflict_source) in
    let conflict_path = Filename.concat directory "conflicting-contract.json" in write conflict_path conflict_source;
    let scenarios =
      ["proved",padded,contract_path,spec,"proved",0,[Some "sat";Some "sat";Some "unsat";Some "unsat";Some "unsat"];
       "unsafe",fixture "01-unsafe",contract_path,spec,"violated",3,[Some "sat";Some "sat";Some "unsat";Some "unsat";Some "sat"];
       "deny-all",fixture "02-delete-workload-grants",contract_path,spec,"violated",3,[Some "sat";Some "sat";Some "unsat";Some "sat";None];
       "unsupported",fixture "18-aggregation-boundary",contract_path,spec,"unknown",4,[];
       "inconsistent",padded,conflict_path,conflict_spec,"inconsistent",6,[Some "sat";Some "sat";Some "sat";None;None]] in
    List.iter (fun (name,source_path,contract,spec,outcome,exit,statuses) ->
      let target = Filename.concat directory name in
      let stdout = invoke ~source_path ~contract ~format:"json" ["--evidence-dir";target] exit in
      assert_bundle ~binary ~z3_version ~directory:target ~source:(read source_path) ~spec ~stdout ~outcome ~statuses)
      scenarios;
    List.iter (fun format ->
      let plain = invoke ~source_path:padded ~contract:contract_path ~format [] 0 in
      let target = Filename.concat directory ("stdout-" ^ format) in
      let evidenced = invoke ~source_path:padded ~contract:contract_path ~format ["--evidence-dir";target] 0 in
      check (format ^ " stdout unchanged by evidence") (plain=evidenced)) ["json";"human"];
    let unused = Filename.concat directory "unused" in
    let base = ["rbac";"verify";padded;"--contract";contract_path] in
    List.iter (fun args ->
      let code,stdout,_ = run binary args in
      check "invalid invocation is rejected before output/artifacts" (code=2 && stdout="" && not (Sys.file_exists unused)))
      [base @ ["--evidence-dir"];
       base @ ["--evidence-dir";"--format";"json"];
       base @ ["--evidence-dir";unused;"--evidence-dir";unused];
       base @ ["--evidence-dir";unused;"--subject";"alice"];
       ["rbac";"verify";padded;"--evidence-dir";unused];
       ["rbac";"compare";fixture "01-unsafe";padded;"--contract";contract_path;"--evidence-dir";unused]];
    let invalid_contract = Filename.concat directory "invalid-contract.json" in
    write invalid_contract (contract_source ^ "{}");
    let stdout = invoke ~source_path:padded ~contract:invalid_contract ~format:"json" ["--evidence-dir";unused] 4 in
    check "invalid contract produces unknown without pretending to freeze it"
      (string "result" (json stdout)="unknown" && field "frozen_spec" (json stdout)=`Null && not (Sys.file_exists unused));
    let missing = Filename.concat directory "absent.json" in
    let code,stdout,_ = run binary ["rbac";"verify";missing;"--contract";contract_path;"--evidence-dir";unused] in
    check "snapshot I/O failure emits no proof or bundle" (code=1 && stdout="" && not (Sys.file_exists unused));
    let existing = Filename.concat directory "proved" in
    let original_manifest = read (Filename.concat existing "manifest.json") in
    let occupied = Filename.concat directory "occupied" in write occupied "keep me";
    let link = Filename.concat directory "link" in Unix.symlink occupied link;
    let dangling = Filename.concat directory "dangling" in Unix.symlink missing dangling;
    List.iter (fun target ->
      let code,stdout,stderr = run binary (base @ ["--format";"json";"--evidence-dir";target]) in
      check "evidence I/O failure prevents success stdout" (code=1 && stdout="" && contains stderr "evidence error"))
      [existing;occupied;link;dangling;Filename.concat directory "absent-parent/bundle"];
    check "existing manifest unchanged" (read (Filename.concat existing "manifest.json")=original_manifest);
    check "existing file/symlink target unchanged" (read occupied="keep me");
    check "live and dangling symlinks retained" (Unix.readlink link=occupied && Unix.readlink dangling=missing);
    check "failed new destination has no completion manifest" (not (Sys.file_exists (Filename.concat directory "absent-parent/bundle/manifest.json")));
    mock_trace ~directory ~spec ~source:padded_source;
    check "frozen contract source remains unchanged" (read contract_path=contract_source));
  Printf.printf "RBAC verification evidence: %d checks passed\n" !checks
