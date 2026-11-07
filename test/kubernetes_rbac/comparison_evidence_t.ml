open Soundcheck_core
module K = Soundcheck_kubernetes_rbac

let checks = ref 0
let check label value = incr checks;if not value then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
    really_input_string channel (in_channel_length channel))
let write path contents = let channel=open_out_bin path in output_string channel contents;close_out channel
let field key = function
  | `O fields -> (match List.assoc_opt key fields with Some value -> value | None -> failwith ("missing " ^ key))
  | _ -> failwith ("not an object: " ^ key)
let string key value = K.Input.str key (field key value)
let array key value = K.Input.arr key (field key value)
let strings key value = K.Input.strings key (field key value)
let json = K.Input.parse
let find text fragment =
  let rec loop i = if i + String.length fragment > String.length text then None
    else if String.sub text i (String.length fragment)=fragment then Some i else loop (i+1) in loop 0
let contains text fragment = Option.is_some (find text fragment)
let fingerprint query =
  let stop = Option.get (find query "(check-sat)") + String.length "(check-sat)" in
  Sha256.string (String.sub query 0 stop)

(* Logging covers physical solver invocations, including SAT observations.
   Non-preservation obligations go to the real Z3. Bad preservation SAT replies
   are well-formed: one names a real change inside the approved scope; the other
   names an unchanged request outside it. Both must fail semantic validation. *)
let () =
  if Array.length Sys.argv >= 2 && List.mem Sys.argv.(1) ["-smt2";"-version"] then begin
    let real = Sys.getenv "SOUNDCHECK_COMPARISON_REAL_Z3" in
    if Sys.argv.(1)="-version" then Unix.execv real [|real;"-version"|];
    let source = read Sys.argv.(2) in
    let observation = contains source "(get-value" in
    let log = open_out_gen [Open_wronly;Open_creat;Open_append] 0o600 (Sys.getenv "SOUNDCHECK_COMPARISON_LOG") in
    output_string log (fingerprint source ^ (if observation then " model\n" else " check\n"));close_out log;
    let mode = Sys.getenv "SOUNDCHECK_COMPARISON_FAKE" in
    if mode="pass" || not (contains source "; decision equivalence:") then
      Unix.execv real [|real;"-smt2";Sys.argv.(2)|];
    if mode="unknown" then print_endline "unknown"
    else begin
      let subject,namespace,resource = match mode with
        | "inside-scope" -> "system:serviceaccount:frontend:frontend-sa","payments","secrets"
        | "no-difference" -> "ops-auditor","ops","configmaps"
        | _ -> failwith "unexpected fake preservation mode" in
      print_endline "sat";
      if observation then Printf.printf
        "((path \"\") (method \"get\") (is_anon false) (src_ip #x00000000) (host \"\") (scheme \"\") (sni \"\") (principal_name %S) (has_object_request true) (object_namespace %S) (object_kind %S) (object_name \"settings\"))\n"
        subject namespace resource
    end;
    exit 0
  end

let rec cleanup path =
  match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path
let temporary_directory () =
  let path=Filename.temp_file "soundcheck-rbac-comparison-evidence-" "" in
  Unix.unlink path;Unix.mkdir path 0o700;path
let self = if Filename.is_relative Sys.executable_name then Filename.concat (Sys.getcwd ()) Sys.executable_name else Sys.executable_name
let real_z3 =
  String.split_on_char ':' (Sys.getenv "PATH")
  |> List.find_map (fun directory -> let path=Filename.concat directory "z3" in
      if Sys.file_exists path then Some (Unix.realpath path) else None) |> Option.get

let with_solver directory label mode action =
  let bin = Filename.concat directory ("solver-" ^ label) in
  Unix.mkdir bin 0o700;Unix.symlink self (Filename.concat bin "z3");
  let log=Filename.concat bin "calls" in write log "";
  let settings=["PATH",bin ^ ":" ^ Sys.getenv "PATH";
    "SOUNDCHECK_COMPARISON_REAL_Z3",real_z3;"SOUNDCHECK_COMPARISON_LOG",log;
    "SOUNDCHECK_COMPARISON_FAKE",mode] in
  let old=List.map (fun (key,_) -> key,Sys.getenv_opt key) settings in
  Fun.protect ~finally:(fun () -> List.iter (fun (key,value) -> Unix.putenv key (Option.value ~default:"" value)) old)
    (fun () -> List.iter (fun (key,value) -> Unix.putenv key value) settings;action log)

let run binary arguments =
  let output=Filename.temp_file "rbac-comparison-out-" "" and error=Filename.temp_file "rbac-comparison-err-" "" in
  Fun.protect ~finally:(fun () -> Sys.remove output;Sys.remove error) (fun () ->
    let out_fd=Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let err_fd=Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let pid=Unix.create_process binary (Array.of_list (binary::arguments)) Unix.stdin out_fd err_fd in
    Unix.close out_fd;Unix.close err_fd;
    let _,status=Unix.waitpid [] pid in
    let code=match status with Unix.WEXITED code -> code | _ -> failwith "CLI terminated" in
    code,read output,read error)

let artifact directory value =
  let path=string "path" value in
  let contents=read (Filename.concat directory path) in
  check ("payload SHA-256: " ^ path) (string "sha256" value=Sha256.string contents);contents
let model value : Solve.model =
  let object_=field "object_request" value in
  {path=string "path" value;method_=string "method" value;is_anon=string "principal" value="anonymous";
   principal_name=Some (string "principal_name" value);
   object_request=Some {namespace=string "namespace" object_;resource_kind=string "resource_kind" object_;name=string "name" object_};
   src_ip=(ok (Cidr.parse (string "source_ip" value))).base;host=string "host" value;
   scheme=string "scheme" value;sni=string "sni" value;
   headers=List.map (fun item -> string "name" item,string "value" item) (array "headers" value)}
let calls query observed = fingerprint query ^ " check\n" ^ (if observed then fingerprint query ^ " model\n" else "")
let expected_calls queries statuses =
  List.map2 (fun query status -> match status with None -> "" | Some status -> calls query (status="sat")) queries statuses
  |> String.concat ""

let assert_bundle ~binary ~z3_version ~directory ~before ~after ~spec ~stdout ~outcome ~candidate_outcome ~statuses ~solver_calls =
  let manifest=json (read (Filename.concat directory "manifest.json")) in
  check "comparison schema is independently versioned" (Evidence.comparison_schema_version=3 && field "schema_version" manifest=`Number "3");
  check "explicit repair comparison operation" (string "operation" manifest="repair_comparison");
  let inputs=field "inputs" manifest in
  List.iter (fun (role,source) ->
    let metadata=field role inputs in
    check (role ^ " digest binds original bytes") (string "sha256" metadata=Sha256.string source);
    check (role ^ " exact byte length") (field "size_bytes" metadata=`Number (string_of_int (String.length source))))
    ["before",before;"after",after];
  let canonical=K.Contract_spec.canonical spec in
  check "frozen contract and context payload" (artifact directory (field "contract" manifest)=canonical ^ "\n");
  let profile=field "assurance_profile" manifest in
  check "profile ID" (string "id" profile=K.Assurance.profile_id);
  check "full profile payload" (artifact directory (field "artifact" profile)=K.Assurance.profile_json () ^ "\n");
  let report_text=artifact directory (field "report" manifest) in
  check "final report equals normal CLI stdout" (report_text=stdout);
  let report=json report_text in
  check "final verdict" (string "result" manifest=outcome && string "result" report=outcome);
  check "final report frozen identity" (string "canonical" (field "frozen_spec" report)=canonical);
  let provenance=field "soundcheck" manifest in
  check "actual executable provenance" (string "executable_sha256" provenance=ok (Sha256.file binary));
  check "runtime/schema provenance" (string "ocaml_version" provenance=Sys.ocaml_version
    && field "report_schema_version" provenance=`Number (string_of_int Report.schema_version));
  let solver=field "solver" manifest in
  check "actual solver provenance" (string "name" solver="z3" && string "version" solver=z3_version && field "version_error" solver=`Null);
  let entries=array "obligations" manifest in
  let info=field "obligation_plan" manifest in
  let candidate_text=match candidate_outcome with
    | None ->
      check "unsupported comparison has no invented candidate report" (field "candidate_report" manifest=`Null);
      check "unsupported plan unavailable" (string "status" info="unavailable" && field "reason" info=field "reason" report && entries=[]);
      check "unsupported inputs perform no verification queries" (solver_calls="");None
    | Some expected ->
      let text=artifact directory (field "candidate_report" manifest) in
      let candidate=json text in
      check "candidate report status" (string "result" candidate=expected);
      check "candidate contract/profile match final report"
        (field "frozen_spec" candidate=field "frozen_spec" report && field "assurance" candidate=field "assurance" report);
      check "complete comparison plan" (string "status" info="complete" && field "reason" info=`Null);
      Some text in
  let before_policy,after_policy,plan=match candidate_outcome with
    | None -> None,None,[]
    | Some _ ->
      let left=K.Lower.policy spec (ok (K.Snapshot.of_string before)) in
      let right=K.Lower.policy spec (ok (K.Snapshot.of_string after)) in
      let candidate=Contract_verify.plan right (K.Contract_spec.to_contract spec) in
      let when_=Ir.Not (K.Contract_spec.approved_changes spec) in
      let preservation=Smt_encode.decision_equivalence_query ~when_ left right in
      Some left,Some right,
      (List.map (fun (obligation : Contract_verify.obligation) -> obligation.id,obligation.smtlib,Some obligation) candidate
       @ ["preservation-outside-change-scope",preservation,None]) in
  check "complete candidate plus preservation plan" (List.length entries=List.length plan && List.length entries=List.length statuses);
  check "candidate executes once; preservation only after proof; evidence does not rerun queries"
    (solver_calls=expected_calls (List.map (fun (_,query,_) -> query) plan) statuses);
  List.iter2 (fun ((id,query,obligation),entry) expected ->
    check "stable obligation identity/order" (string "id" entry=id);
    check "saved actual planned formula" (artifact directory (field "query" entry)=query);
    check "safe unique query filename" (string "path" (field "query" entry)="queries/" ^ id ^ ".smt2");
    (match obligation with
     | None -> check "explicit preservation phase" (string "phase" entry="preservation" && array "clauses" entry=[])
     | Some (obligation : Contract_verify.obligation) ->
       let phase=if obligation.phase=Contract_verify.Inhabitance then "inhabitance"
         else if obligation.phase=Contract_verify.Consistency then "consistency" else "clause" in
       check "candidate phase/clauses" (string "phase" entry=phase && strings "clauses" entry=obligation.clauses));
    let validate model =
      let request=Witness.request_of_model model in
      let left=Option.get before_policy and right=Option.get after_policy in
      let valid=match obligation with
        | None -> Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) left right request
        | Some (obligation : Contract_verify.obligation) ->
          let clauses=(K.Contract_spec.to_contract spec).clauses in
          let related=List.map (fun name -> List.find (fun clause -> Contract.name clause=name) clauses) obligation.clauses in
          if obligation.phase=Contract_verify.Clause then Witness.clause right (List.hd related) request
          else Witness.condition ~domain:right.request_domain (Ir.And (List.map Contract.request_class related)) request in
      check ("recorded/replayed SAT model satisfies " ^ id) valid in
    match expected with
    | None -> check "unexecuted queries stay explicit" (string "execution" entry="not_executed"
        && field "solver_result" entry=`Null && field "model" entry=`Null && field "reason" entry=`Null)
    | Some expected ->
      check "executed query result" (string "execution" entry="executed" && string "solver_result" entry=expected && field "reason" entry=`Null);
      (match expected,field "model" entry with
       | "sat",(`O _ as value) -> validate (model value)
       | "unsat",`Null -> ()
       | _ -> failwith "invalid recorded model/status pairing");
      (match Solve.check query,expected with
       | Solve.Proved,"unsat" -> ()
       | Solve.Violated model,"sat" -> validate model
       | _ -> failwith ("formula replay failed: " ^ id))) (List.combine plan entries) statuses;
  (match candidate_outcome with
   | Some "violated" -> check "candidate failure keeps its exact report" (candidate_text=Some report_text)
   | Some "proved" when outcome="violated" ->
     let witness=field "counterexample" report in
     check "operator regression is reported as preservation" (string "kind" (field "clause" report)="must_preserve");
     check "exact named operator identity" (string "principal" witness="ops-auditor");
     let coordinates=field "object_request" witness in
     check "typed operator request" (string "namespace" coordinates="ops" && string "resource_kind" coordinates="configmaps");
     let identity=K.Contract_spec.identities spec |> List.find (fun (i : K.Identity.identity) -> i.username="ops-auditor") in
     check "operator groups are frozen" (strings "identity_groups" witness=identity.groups);
     let stored=field "model" (List.hd (List.rev entries)) in
     check "lift uses the checked preservation witness"
       (field "principal" witness=field "principal_name" stored && field "object_request" witness=field "object_request" stored);
     let request=Witness.request_of_model (model stored) in
     check "operator access actually changed from grant to no grant"
       (Ir.possibly_allows (Option.get before_policy) request && not (Ir.possibly_allows (Option.get after_policy) request))
   | _ -> ());
  let names=Sys.readdir directory |> Array.to_list |> List.sort compare in
  let expected_names=["assurance-profile.json";"contract.json";"manifest.json";"queries";"report.json"]
    @ (if candidate_outcome=None then [] else ["candidate-report.json"]) |> List.sort compare in
  check "no raw inputs, temporary manifests, or unlisted payloads" (names=expected_names);
  let query_names=Sys.readdir (Filename.concat directory "queries") |> Array.to_list |> List.sort compare in
  check "all and only planned queries exist" (query_names=(List.map (fun (id,_,_) -> id ^ ".smt2") plan |> List.sort compare))

let library_failures directory spec before after =
  List.iter (fun (mode,preservation_calls) ->
    with_solver directory ("library-" ^ mode) mode (fun log ->
      let result=K.Verify.compare_with_trace ~z3:(Filename.concat directory ("solver-library-" ^ mode ^ "/z3")) spec ~before ~after in
      let candidate=Option.get result.candidate_report in
      check "candidate proved before failing preservation" (candidate.result=Report.Proved);
      check "preservation failure is unknown" (match result.report.result with Report.Unknown _ -> true | _ -> false);
      let trace=Option.get result.trace in
      let reason=match trace.preservation.execution with Contract_verify.Executed (Solve.Unknown reason) -> reason
        | _ -> failwith "unchecked preservation model escaped" in
      if mode<>"unknown" then check "bad SAT passed protocol and failed semantic validation" (contains reason "witness validation failed");
      let candidate_queries=List.map (fun entry -> entry.Contract_verify.obligation.smtlib) trace.candidate in
      let expected=expected_calls candidate_queries [Some "sat";Some "sat";Some "unsat";Some "unsat";Some "unsat"]
        ^ calls trace.preservation.smtlib preservation_calls in
      check "candidate runs once and only the decisive preservation calls run" (read log=expected);
      let profile : Evidence.profile={id=K.Assurance.profile_id;json=K.Assurance.profile_json ()} in
      let provenance : Evidence.provenance={executable_sha256=ok (Sha256.file self);ocaml_version=Sys.ocaml_version;z3_version=Ok "test wrapper"} in
      let bundle=ok (Evidence.create_comparison ~before ~after ~profile ~provenance ~report:result.report
        ~candidate_report:result.candidate_report ~trace:result.trace) in
      let manifest=List.assoc "manifest.json" (Evidence.files bundle) |> json in
      check "unknown preservation keeps complete plan" (string "status" (field "obligation_plan" manifest)="complete");
      let preserved=List.hd (List.rev (array "obligations" manifest)) in
      check "no raw SAT model in failed preservation evidence"
        (string "solver_result" preserved="unknown" && field "model" preserved=`Null && string "reason" preserved=reason);
      check "no counterexample published for unknown comparison"
        (field "counterexample" (List.assoc "report.json" (Evidence.files bundle) |> json)=`Null);
      check "evidence retains successful candidate report"
        (string "result" (List.assoc "candidate-report.json" (Evidence.files bundle) |> json)="proved");
      check "bundle creation never repeats solver execution" (read log=expected)))
    ["inside-scope",true;"no-difference",true;"unknown",false]

let () =
  if Array.length Sys.argv<>3 then failwith "expected CLI binary and RBAC corpus root";
  let binary=Sys.argv.(1) and root=Sys.argv.(2) in
  let contract_path=root ^ "/contracts/frontend-access.json" in
  let contract_source=read contract_path in
  let spec=ok (K.Contract_spec.of_string contract_source) in
  let fixture name=root ^ "/fixtures/" ^ name ^ ".json" in
  let directory=temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    let before_path=Filename.concat directory "before with spaces.json" in
    let after_path=Filename.concat directory "after with spaces.json" in
    let before="\n " ^ read (fixture "01-unsafe") in
    let after=read (fixture "03-valid-repair") ^ "\n\t" in
    write before_path before;write after_path after;
    let z3_version=ok (Solve.version ()) in
    let arguments left right contract format extra=
      ["rbac";"compare";left;right;"--contract";contract;"--format";format] @ extra in
    let safe_stdout=ref "" in
    List.iter (fun (label,left,right,outcome,candidate,code,statuses) ->
      let target=Filename.concat directory label in
      let stdout,solver_calls=with_solver directory label "pass" (fun log ->
        let status,stdout,stderr=run binary (arguments left right contract_path "json" ["--evidence-dir";target]) in
        check ("comparison exit: " ^ label ^ stderr) (status=code);stdout,read log) in
      if label="safe" then safe_stdout:=stdout;
      assert_bundle ~binary ~z3_version ~directory:target ~before:(read left) ~after:(read right) ~spec ~stdout
        ~outcome ~candidate_outcome:candidate ~statuses ~solver_calls)
      ["safe",before_path,after_path,"proved",Some "proved",0,[Some "sat";Some "sat";Some "unsat";Some "unsat";Some "unsat";Some "unsat"];
       "regression",before_path,fixture "16-operator-regression","violated",Some "proved",3,[Some "sat";Some "sat";Some "unsat";Some "unsat";Some "unsat";Some "sat"];
       "candidate-failure",before_path,fixture "02-delete-workload-grants","violated",Some "violated",3,[Some "sat";Some "sat";Some "unsat";Some "sat";None;None];
       "unsupported-before",fixture "18-aggregation-boundary",after_path,"unknown",None,4,[];
       "unsupported-after",before_path,fixture "26-trailing-json-document","unknown",None,4,[]];
    let code,plain,_=run binary (arguments before_path after_path contract_path "json" []) in
    check "JSON report/exit unchanged by evidence" (code=0 && plain= !safe_stdout);
    let code,plain,_=run binary (arguments before_path after_path contract_path "human" []) in
    let status,evidenced,_=run binary (arguments before_path after_path contract_path "human" ["--evidence-dir";Filename.concat directory "human"]) in
    check "human report/exit unchanged by evidence" (code=0 && status=0 && plain=evidenced);
    let unused=Filename.concat directory "unused" in
    let invalid_contract=Filename.concat directory "invalid-contract.json" in write invalid_contract (contract_source ^ "{}");
    let code,stdout,_=run binary (arguments before_path after_path invalid_contract "json" ["--evidence-dir";unused]) in
    check "invalid contract is unknown with no misleading bundle"
      (code=4 && string "result" (json stdout)="unknown" && field "frozen_spec" (json stdout)=`Null && not (Sys.file_exists unused));
    List.iter (fun (left,right) ->
      let code,stdout,_=run binary (arguments left right contract_path "json" ["--evidence-dir";unused]) in
      check "input I/O failure has no report or bundle" (code=1 && stdout="" && not (Sys.file_exists unused)))
      [Filename.concat directory "missing-before",after_path;before_path,Filename.concat directory "missing-after"];
    List.iter (fun extra ->
      let code,stdout,_=run binary (arguments before_path after_path contract_path "json" extra) in
      check "invalid evidence flags rejected before artifacts" (code=2 && stdout="" && not (Sys.file_exists unused)))
      [["--evidence-dir"];["--evidence-dir";unused;"--evidence-dir";unused];["--evidence-dir";unused;"--subject";"alice"]];
    let existing=Filename.concat directory "safe" in
    let original_manifest=read (Filename.concat existing "manifest.json") in
    let occupied=Filename.concat directory "occupied" in write occupied "keep";
    let link=Filename.concat directory "link" in Unix.symlink occupied link;
    List.iter (fun (target,left) ->
      let code,stdout,stderr=run binary (arguments left after_path contract_path "json" ["--evidence-dir";target]) in
      check "evidence I/O error prevents success output" (code=1 && stdout="" && contains stderr "evidence error"))
      [existing,before_path;occupied,fixture "18-aggregation-boundary";link,fixture "18-aggregation-boundary";
       Filename.concat directory "missing-parent/bundle",fixture "18-aggregation-boundary"];
    check "existing complete bundle not overwritten" (read (Filename.concat existing "manifest.json")=original_manifest);
    check "occupied file and symlink unchanged" (read occupied="keep" && Unix.readlink link=occupied);
    check "failed new destination has no completion marker" (not (Sys.file_exists (Filename.concat directory "missing-parent/bundle/manifest.json")));
    library_failures directory spec before after;
    check "contract source unchanged" (read contract_path=contract_source));
  Printf.printf "RBAC comparison evidence: %d checks passed\n" !checks
