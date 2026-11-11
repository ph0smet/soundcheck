open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label condition = incr checks; if not condition then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let field key = function
  | `O fields -> (match List.assoc_opt key fields with Some value -> value | None -> failwith ("missing " ^ key))
  | _ -> failwith ("not an object: " ^ key)
let string key value = I.str key (field key value)
let array key value = I.arr key (field key value)
let strings values = `A (List.map (fun value -> `String value) values)
let contains text fragment =
  let rec loop index = index + String.length fragment <= String.length text
    && (String.sub text index (String.length fragment) = fragment || loop (index + 1)) in loop 0
let read path =
  let channel = open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      really_input_string channel (in_channel_length channel))
let write path value =
  let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel value)
let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun name -> cleanup (Filename.concat path name)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path
let mkdir path = Unix.mkdir path 0o700
let temporary_directory () =
  let path = Filename.temp_file "soundcheck-rbac-write-adapters-" "" in
  Unix.unlink path;mkdir path;Unix.realpath path

let run ?env binary args =
  let output = Filename.temp_file "rbac-write-out-" "" and error = Filename.temp_file "rbac-write-err-" "" in
  Fun.protect ~finally:(fun () -> Sys.remove output;Sys.remove error) (fun () ->
      let out_fd = Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
      let err_fd = Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
      let argv = Array.of_list (binary::args) in
      let pid = match env with
        | None -> Unix.create_process binary argv Unix.stdin out_fd err_fd
        | Some env -> Unix.create_process_env binary argv env Unix.stdin out_fd err_fd in
      Unix.close out_fd;Unix.close err_fd;
      let _,status = Unix.waitpid [] pid in
      let code = match status with Unix.WEXITED value -> value | _ -> failwith "child terminated" in
      code,read output,read error)

(* Keep v3 acceptance separate from the unchanged v1/v2 workflows. *)
let profile_v3 = "kubernetes-rbac-v1.34-read-write-v2"
let profile_v4 = "kubernetes-rbac-v1.34-scoped-read-write-v2"
let profile_for_version = function
  | 1 -> "kubernetes-rbac-v1.34-get-v2" | 2 -> "kubernetes-rbac-v1.34-read-v2"
  | 3 -> profile_v3 | 4 -> profile_v4 | _ -> failwith "unexpected contract version"
let assert_report ~version ~spec outcome report =
  check "report schema remains 10" (field "schema_version" report=`Number "10");
  check "expected verdict" (string "result" report=outcome);
  let frozen=field "frozen_spec" report in
  check "frozen contract version and exact canonical identity"
    (field "schema_version" frozen=`Number (string_of_int version)
     && string "canonical" frozen=K.Contract_spec.canonical spec);
  check "contract-selected profile" (string "profile" (field "assurance" report)=
    profile_for_version version)
let replace key value = function
  | `O fields -> `O (List.map (fun (name,old)->name,if name=key then value else old) fields)
  | _ -> failwith "object expected"
let without_role_verbs source role verbs =
  let value=I.parse source in
  let items=array "items" value |> List.map (fun item ->
    if List.mem (string "kind" item) ["Role";"ClusterRole"] && string "name" (field "metadata" item)=role then
      replace "rules" (`A (array "rules" item |> List.map (fun rule ->
        replace "verbs" (strings (I.strings "verbs" (field "verbs" rule) |> List.filter (fun verb->not (List.mem verb verbs)))) rule))) item
    else item) in
  I.json (replace "items" (`A items) value)
let legacy_contract version source =
  let value=I.parse source in
  let required=List.hd (array "clauses" value) in
  (* The v4 adapter fixture uses singleton includes and unrestricted complements.
     Its downgrade must remain a valid, weaker v1/v2 contract, not just corrupt
     JSON that the frozen adapters would also ignore. *)
  let required=match field "namespace" required with
    | `O ["include",`A [(`String _ as namespace)]] -> replace "namespace" namespace required
    | _ -> required in
  let required=match field "names" required with
    | `O fields when List.assoc_opt "exclude" fields=Some (`A []) -> replace "names" `Null required
    | _ -> required in
  let forbidden=required |> replace "name" (`String "legacy-secret-read-not-granted")
    |> replace "kind" (`String "must_not_grant") |> replace "namespace" (`String "payments")
    |> replace "resource" (`String "secrets") |> replace "names" `Null in
  let clauses=List.map (fun clause->if version=1 then match clause with
    | `O fields -> `O (List.remove_assoc "verb" fields) | _->assert false else clause) [required;forbidden] in
  let source=value |> replace "schema_version" (`Number (string_of_int version))
    |> replace "clauses" (`A clauses) |> replace "change_scope" (`A []) |> I.json in
  check "tampered downgrade remains a valid older contract"
    (K.Contract_spec.version (ok (K.Contract_spec.of_string source))=version);
  source

let witness_request witness : Ir.request =
  let object_ = field "object_request" witness in
  {principal=Authenticated (string "principal" witness);action=string "action" witness;
   resource="";context=[];source=0l;host="";scheme="";sni="";
   object_request=Some {namespace=string "namespace" object_;resource_kind=string "resource_kind" object_;name=string "name" object_}}
let assert_witness spec ?before ~after report =
  if string "result" report="violated" then begin
    let witness = field "counterexample" report in
    let request = witness_request witness in
    let coordinates = Option.get request.object_request in
    check "typed read or named-write action" (List.mem request.action ["get";"list";"watch";"update";"patch";"delete"]);
    check "typed namespace preserves all-namespace empty coordinate"
      (coordinates.namespace="" || I.dns_label coordinates.namespace);
    check "typed name preserves unfiltered empty coordinate"
      (coordinates.name="" || I.dns_subdomain coordinates.name);
    check "get and named writes require a namespace and name"
      (List.mem request.action ["list";"watch"] || (coordinates.namespace<>"" && coordinates.name<>""));
    let username = string "principal" witness in
    let identity = List.find (fun (value : K.Identity.identity) -> value.username=username) (K.Contract_spec.identities spec) in
    check "witness groups remain frozen" (field "identity_groups" witness=strings identity.groups);
    let policy source = K.Lower.policy spec (ok (K.Snapshot.of_string source)) in
    let candidate = policy after in
    let clause = field "clause" report in
    let valid = if string "kind" clause="must_preserve" then
        Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec))
          (policy (Option.get before)) candidate request
      else Witness.clause candidate
          (List.find (fun value -> Contract.name value=string "name" clause) (K.Contract_spec.to_contract spec).clauses) request in
    check "reported access witness satisfies the actual obligation" valid;
    check "grant IDs describe the candidate decision"
      (field "granting_rules" witness=strings (K.Lower.granting_rules candidate request))
  end

let assert_coordinate report ~action ~namespace ~name =
  let witness = field "counterexample" report in
  let object_ = field "object_request" witness in
  check "exact access action" (string "action" witness=action);
  check "exact namespace coordinate" (string "namespace" object_=namespace);
  Option.iter (fun name -> check "exact effective name coordinate" (string "name" object_=name)) name

let saved_model value : Solve.model =
  let object_ = field "object_request" value in
  {path=string "path" value;method_=string "method" value;is_anon=false;
   principal_name=Some (string "principal_name" value);
   object_request=Some {namespace=string "namespace" object_;resource_kind=string "resource_kind" object_;name=string "name" object_};
   src_ip=(ok (Cidr.parse (string "source_ip" value))).base;host=string "host" value;
   scheme=string "scheme" value;sni=string "sni" value;
   headers=List.map (fun item -> string "name" item,string "value" item) (array "headers" value)}
let assert_evidence directory spec ?before ~after stdout =
  let version=K.Contract_spec.version spec in
  let artifact metadata =
    let value = read (Filename.concat directory (string "path" metadata)) in
    check "evidence artifact checksum" (string "sha256" metadata=Sha256.string value);value in
  let manifest = I.parse (read (Filename.concat directory "manifest.json")) in
  check "evidence format does not change for the new profile"
    (field "schema_version" manifest=`Number (if before=None then "2" else "3"));
  let input role source metadata =
    check (role ^ " input digest") (string "sha256" metadata=Sha256.string source);
    check (role ^ " input byte length") (field "size_bytes" metadata=`Number (string_of_int (String.length source))) in
  (match before with
   | None -> input "config" after (field "config" manifest)
   | Some before ->
     check "comparison operation stays explicit" (string "operation" manifest="repair_comparison");
     input "before" before (field "before" (field "inputs" manifest));
     input "after" after (field "after" (field "inputs" manifest));
     let candidate = I.parse (artifact (field "candidate_report" manifest)) in
     assert_report ~version ~spec "proved" candidate);
  check "evidence report is exactly the same invocation's stdout" (artifact (field "report" manifest)=stdout);
  check "canonical contract is retained" (artifact (field "contract" manifest)=K.Contract_spec.canonical spec ^ "\n");
  let profile = field "assurance_profile" manifest in
  check "evidence references the selected read-write profile" (string "id" profile=profile_for_version version);
  check "evidence includes the full selected profile"
    (artifact (field "artifact" profile)=K.Assurance.profile_json ~version () ^ "\n");
  check "supported plan is complete" (string "status" (field "obligation_plan" manifest)="complete");
  let policy source = K.Lower.policy spec (ok (K.Snapshot.of_string source)) in
  let after_policy = policy after in
  let clauses = K.Contract_spec.to_contract spec in
  let plan = Contract_verify.plan after_policy clauses in
  let entries = array "obligations" manifest in
  check "all candidate and preservation queries retained" (List.length entries=List.length plan + if before=None then 0 else 1);
  List.iter (fun entry ->
    let id = string "id" entry in
    let preservation = id="preservation-outside-change-scope" in
    let obligation = if preservation then None else Some (List.find (fun (value : Contract_verify.obligation) -> value.id=id) plan) in
    let expected_query = match obligation with Some value -> value.smtlib | None ->
        Smt_encode.decision_equivalence_query ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) (policy (Option.get before)) after_policy in
    check "saved query includes the actual read/write domain and obligation" (artifact (field "query" entry)=expected_query);
    if field "solver_result" entry=`String "sat" then begin
      let request = Witness.request_of_model (saved_model (field "model" entry)) in
      let valid = match obligation with
        | None -> Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) (policy (Option.get before)) after_policy request
        | Some value ->
          let related = List.map (fun name -> List.find (fun clause -> Contract.name clause=name) clauses.clauses) value.clauses in
          if value.phase=Contract_verify.Clause then Witness.clause after_policy (List.hd related) request
          else Witness.condition ~domain:after_policy.request_domain (Ir.And (List.map Contract.request_class related)) request in
      check "saved access model is valid for its exact obligation" valid
    end) entries;
  let report = I.parse stdout in
  if string "result" report="violated" then begin
    let decisive = List.find (fun entry -> field "solver_result" entry=`String "sat") (List.rev entries) in
    let model = field "model" decisive and witness = field "counterexample" report in
    check "report and evidence agree on the access verb" (field "action" witness=field "method" model);
    check "report and evidence agree on exact typed object coordinates"
      (field "object_request" witness=field "object_request" model && field "principal" witness=field "principal_name" model)
  end

type child = {pid:int;input:out_channel;output:Unix.file_descr;error_path:string;
  mutable pending:string;mutable reaped:bool}
let with_child directory binary args action =
  let input_read,input_write = Unix.pipe ~cloexec:true () and output_read,output_write = Unix.pipe ~cloexec:true () in
  let error_path = Filename.concat directory "mcp.stderr" in
  let error = Unix.openfile error_path [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_TRUNC] 0o600 in
  let pid = Unix.create_process binary (Array.of_list (binary::args)) input_read output_write error in
  List.iter Unix.close [input_read;output_write;error];
  let child = {pid;input=Unix.out_channel_of_descr input_write;output=output_read;error_path;pending="";reaped=false} in
  Fun.protect ~finally:(fun () -> close_out_noerr child.input;
    if not child.reaped then begin (try Unix.kill child.pid Sys.sigkill with Unix.Unix_error (Unix.ESRCH,_,_) -> ());ignore (Unix.waitpid [] child.pid) end;
    Unix.close child.output) (fun () -> action child)
let send child value = output_string child.input (I.json value);output_char child.input '\n';flush child.input
let receive child =
  let deadline = Unix.gettimeofday () +. 45. in
  let rec loop () = match String.index_opt child.pending '\n' with
    | Some index ->
      let line = String.sub child.pending 0 index in
      child.pending <- String.sub child.pending (index+1) (String.length child.pending-index-1);I.parse line
    | None ->
      let timeout = deadline -. Unix.gettimeofday () in
      if timeout<=0. || (let ready,_,_ = Unix.select [child.output] [] [] timeout in ready=[]) then failwith "MCP response timed out";
      let bytes = Bytes.create 4096 in let count = Unix.read child.output bytes 0 (Bytes.length bytes) in
      if count=0 then failwith ("MCP unexpectedly exited: " ^ read child.error_path);
      child.pending <- child.pending ^ Bytes.sub_string bytes 0 count;loop () in loop ()
let rpc id method_ params = `O ["jsonrpc",`String "2.0";"id",`Number (string_of_int id);
  "method",`String method_;"params",params]
let exchange child id method_ params =
  send child (rpc id method_ params);
  let response = receive child in
  check "MCP envelope and ID preserved" (field "jsonrpc" response=`String "2.0" && field "id" response=`Number (string_of_int id));response

let cli_checks directory binary demo =
  let fixture name=read (Filename.concat demo (name ^ ".json")) in
  let contract_source=fixture "contract" in
  let spec=ok (K.Contract_spec.of_string contract_source) in
  let contract_path=Filename.concat demo "contract.json" and baseline_path=Filename.concat demo "unsafe.json" in
  let baseline=fixture "unsafe" and partial=fixture "partial-write-fix" and repaired=fixture "repaired"
  and regression=fixture "operator-regression" in
  let code,stdout,stderr=run binary ["profile";"kubernetes-rbac";"--contract-version";"3";"--format";"json"] in
  check "profile command selects the bounded write model" (code=0 && stderr="");
  let profile=I.parse stdout in
  check "profile document retains envelope2 and explicitly binds contract3"
    (string "id" profile=profile_v3 && field "schema_version" profile=`Number "2"
      && field "contract_schema_version" profile=`Number "3"
      && field "verbs" profile=strings ["get";"list";"watch";"update";"patch";"delete"]);
  let invoke ?before ?evidence name source outcome =
    let path=Filename.concat directory (name ^ ".json") in write path source;
    let args=match before with None->["verify";path] | Some baseline->["compare";baseline;path] in
    let code,stdout,stderr=run binary ("rbac"::args @ ["--contract";contract_path;"--format";"json"]
      @ match evidence with None->[] | Some path->["--evidence-dir";path]) in
    check ("CLI " ^ name ^ ": " ^ stderr)
      (code=(match outcome with "proved"->0 | "unknown"->4 | _->3) && stderr="");
    let report=I.parse stdout in assert_report ~version:3 ~spec outcome report;
    assert_witness spec ?before:(Option.map read before) ~after:source report;
    Option.iter (fun path->assert_evidence path spec ?before:(Option.map read before) ~after:source stdout) evidence;
    report in
  ignore (invoke "unsupported" (repaired ^ "{}") "unknown");
  let deletion=partial |> fun source->without_role_verbs source "app-config" ["patch"]
    |> fun source->without_role_verbs source "app-secrets" ["patch"] in
  List.iter (fun (verb,source) ->
    let report=invoke ?evidence:(if verb="update" then Some (Filename.concat directory "verify-evidence") else None)
        ("app-" ^ verb) source "violated" in
    assert_coordinate report ~action:verb ~namespace:"frontend" ~name:None;
    check "each forbidden named write is reported independently"
      (string "name" (field "clause" report)="app-configmaps-" ^ verb ^ "-not-granted"))
    ["update",baseline;"patch",partial;"delete",deletion];
  List.iter (fun verb ->
    let source=without_role_verbs repaired "config-manager" [verb] in
    let report=invoke ("missing-manager-" ^ verb) source "violated" in
    assert_coordinate report ~action:verb ~namespace:"frontend" ~name:(Some "settings");
    check "required manager write is not replaced by other verbs"
      (string "kind" (field "clause" report)="must_allow"
       && string "principal" (field "counterexample" report)="config-manager")) ["update";"patch";"delete"];
  let denied=invoke "deny-all" (fixture "deny-all") "violated" in
  assert_coordinate denied ~action:"get" ~namespace:"frontend" ~name:(Some "settings");
  ignore (invoke ~before:baseline_path "valid-repair" repaired "proved");
  let changed=invoke ~before:baseline_path ~evidence:(Filename.concat directory "comparison-evidence")
      "rotator-regression" regression "violated" in
  assert_coordinate changed ~action:"update" ~namespace:"payments" ~name:(Some "signing-key");
  check "unrelated write regression is preservation, not a contract violation"
    (string "kind" (field "clause" changed)="must_preserve"
      && string "principal" (field "counterexample" changed)="secret-rotator");
  let lost_watch=invoke ~before:baseline_path "app-watch-regression"
      (without_role_verbs repaired "app-config" ["watch"]) "violated" in
  assert_coordinate lost_watch ~action:"watch" ~namespace:"frontend" ~name:None;
  check "v3 repair still preserves existing application reads" (string "kind" (field "clause" lost_watch)="must_preserve");
  let operator=invoke ~before:baseline_path "operator-watch-regression"
      (without_role_verbs repaired "operator-configmaps" ["watch"]) "violated" in
  check "v3 repair preserves unrelated operator collection access"
    (string "kind" (field "clause" operator)="must_preserve"
      && string "action" (field "counterexample" operator)="watch"
      && string "principal" (field "counterexample" operator)="ops-auditor");
  List.iter (fun version ->
    let old=legacy_contract version contract_source in
    let old_spec=ok (K.Contract_spec.of_string old) in
    let old_path=Filename.concat directory (Printf.sprintf "v%d-contract.json" version) in write old_path old;
    let code,stdout,stderr=run binary ["rbac";"compare";baseline_path;Filename.concat demo "operator-regression.json";
        "--contract";old_path;"--format";"json"] in
    check "older contract preservation domains do not silently gain writes" (code=0 && stderr="");
    assert_report ~version ~spec:old_spec "proved" (I.parse stdout)) [1;2];
  spec,contract_source,baseline,partial,repaired,regression

let mcp_checks directory binary spec source baseline partial repaired regression =
  let version=K.Contract_spec.version spec in
  let contract_path=Filename.concat directory "mcp-contract.json" and baseline_path=Filename.concat directory "mcp-baseline.json" in
  write contract_path source;write baseline_path baseline;
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";contract_path;"--baseline";baseline_path] (fun child ->
    ignore (field "result" (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "write-acceptance";"version",`String "1"]])));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let tools=array "tools" (field "result" (exchange child 2 "tools/list" (`O []))) in
    check "v3 MCP tools remain config-only" (List.map (string "name") tools=["verify";"compare"]);
    List.iter (fun tool->let schema=field "inputSchema" tool in
      check "MCP discovery permits no requirement overrides"
        (field "required" schema=strings ["config"] && field "additionalProperties" schema=`Bool false)) tools;
    check "MCP captures original baseline digest" (contains (string "description" (List.nth tools 1)) (Sha256.string baseline));
    write contract_path (legacy_contract 2 source);write baseline_path regression;
    let call id operation candidate expected =
      let result=field "result" (exchange child id "tools/call" (`O ["name",`String operation;
        "arguments",`O ["config",`String candidate]])) in
      let report=field "structuredContent" result in
      check "MCP text equals structured write report" (I.parse (string "text" (List.hd (array "content" result)))=report);
      assert_report ~version ~spec expected report;
      assert_witness spec ?before:(if operation="compare" then Some baseline else None) ~after:candidate report;report in
    let uncorrected=call 3 "verify" partial "violated" in
    assert_coordinate uncorrected ~action:"patch" ~namespace:"frontend" ~name:None;
    let changed=call 4 "compare" regression "violated" in
    assert_coordinate changed ~action:"update" ~namespace:"payments" ~name:(Some "signing-key");
    Sys.remove contract_path;Sys.remove baseline_path;
    ignore (call 5 "verify" repaired "proved");ignore (call 6 "compare" repaired "proved");
    let rejected=exchange child 7 "tools/call" (`O ["name",`String "verify";
      "arguments",`O ["config",`String repaired;"contract_version",`Number "2";"verb",`String "get"]]) in
    check "MCP cannot downgrade write requirements to read-only" (field "code" (field "error" rejected)=`Number "-32602");
    close_out child.input;check "MCP has no unsolicited stdout" (child.pending="");
    let ready,_,_=Unix.select [child.output] [] [] 10. in
    check "MCP closes protocol stream at EOF" (ready<>[] && Unix.read child.output (Bytes.create 1) 0 1=0);
    let _,status=Unix.waitpid [] child.pid in child.reaped<-true;
    check "MCP write session exits cleanly" (status=Unix.WEXITED 0 && read child.error_path=""))

let gate_checks directory binary helper source baseline partial repaired regression =
  let version=K.Contract_spec.version (ok (K.Contract_spec.of_string source)) in
  let workspace=Filename.concat directory "workspace" and action=Filename.concat directory "trusted-action"
  and runner_temp=Filename.concat directory "runner-temp" in
  List.iter mkdir [workspace;action;runner_temp];
  List.iter (fun path->mkdir (Filename.concat action path)) ["scripts";"_build"];
  mkdir (Filename.concat action "_build/default");mkdir (Filename.concat action "_build/default/cli");
  let script=Filename.concat action "scripts/verify-approved-contract.sh" in write script (read helper);
  Unix.symlink (Unix.realpath binary) (Filename.concat action "_build/default/cli/main.exe");
  let git args=let code,stdout,stderr=run "git" (["-c";"core.hooksPath=/dev/null";"-C";workspace] @ args) in
    check ("local Action git: " ^ stderr) (code=0);String.trim stdout in
  ignore (git ["init";"--quiet"]);
  let config_path=Filename.concat workspace "snapshot.json" and contract_path=Filename.concat workspace "contract.json" in
  write config_path baseline;write contract_path source;
  ignore (git ["add";"--";"snapshot.json";"contract.json"]);
  ignore (git ["-c";"user.name=Soundcheck acceptance";"-c";"user.email=acceptance@example.invalid";
      "-c";"commit.gpgSign=false";"commit";"--quiet";"-m";"Approved named-write contract"]);
  let approved=git ["rev-parse";"HEAD"] in
  let event=Filename.concat directory "event.json" in
  write event (I.json (`O ["repository",`O ["full_name",`String "example/soundcheck"];
    "pull_request",`O ["base",`O ["sha",`String approved;"ref",`String "main";
      "repo",`O ["full_name",`String "example/soundcheck"]]]]));
  let weakened=legacy_contract 2 source in write contract_path weakened;
  let execute mode candidate expected fragments =
    write config_path candidate;
    let settings=["GITHUB_WORKSPACE",workspace;"GITHUB_EVENT_PATH",event;"GITHUB_EVENT_NAME","pull_request";
      "GITHUB_REPOSITORY","example/soundcheck";"GITHUB_BASE_REF","main";"RUNNER_TEMP",runner_temp;
      "SOUNDCHECK_CONFIG_INPUT","snapshot.json";"SOUNDCHECK_CONTRACT_INPUT","contract.json";
      "SOUNDCHECK_CONNECTOR_INPUT","kubernetes-rbac";"SOUNDCHECK_MODE_INPUT",mode] in
    let inherited=Array.to_list (Unix.environment ()) |> List.filter (fun entry->
      not (List.exists (fun (key,_)->String.starts_with ~prefix:(key ^ "=") entry) settings)) in
    let env=Array.of_list (List.map (fun (key,value)->key ^ "=" ^ value) settings @ inherited) in
    let code,stdout,stderr=run ~env "bash" [script] in
    check ("approved-write Action " ^ mode ^ ": " ^ stderr) (code=expected && stderr="");
    List.iter (fun fragment->check ("Action retains " ^ fragment) (contains stdout fragment))
      (["Approved contract: " ^ approved ^ ":contract.json";profile_for_version version;
        "\"schema_version\":" ^ string_of_int version] @ fragments);
    check "Action cleans approved inputs without rewriting candidate contract"
      (Sys.readdir runner_temp=[||] && read contract_path=weakened) in
  execute "verify" partial 3 ["must_not_grant";" patch configmaps/";"in namespace frontend"];
  execute "repair" regression 3 ["Approved baseline: " ^ approved ^ ":snapshot.json";
    "must_preserve";"secret-rotator update secrets/signing-key in namespace payments"];
  execute "repair" repaired 0 ["rbac-repair-preservation proved"]

let benchmark_checks directory binary source baseline partial repaired regression =
  let profile=profile_for_version (K.Contract_spec.version (ok (K.Contract_spec.of_string source))) in
  let root=Filename.concat directory "benchmark" in mkdir root;
  List.iter (fun (name,bytes)->write (Filename.concat root name) bytes)
    ["contract.json",source;"baseline.json",baseline;"partial.json",partial;"regression.json",regression;"valid.json",repaired];
  let suite=Filename.concat root "suite.json" and submissions=Filename.concat root "submissions.json" in
  write suite {|{"format_version":1,"cases":[{"id":"writes","config":"baseline.json","contract":"contract.json","provenance":"synthetic"}]}|};
  write submissions {|{"format_version":1,"attempts":[{"task":"writes","id":"partial","config":"partial.json"},{"task":"writes","id":"regression","config":"regression.json"},{"task":"writes","id":"valid","config":"valid.json"}]}|};
  let code,stdout,stderr=run binary [suite;submissions] in
  check ("write benchmark process: " ^ stderr) (code=0 && stderr="");
  let summary=I.parse stdout in
  check "schema3 benchmark uses existing format2 with write profile"
    (field "experimental_format_version" summary=`Number "2" && string "profile" summary=profile);
  let task=List.hd (array "tasks" summary) in
  check "benchmark binds trusted profile and exact source bytes"
    (string "profile" task=profile && string "baseline_sha256" task=Sha256.string baseline
     && string "contract_sha256" task=Sha256.string source && field "first_valid_attempt" task=`Number "3");
  let attempts=array "attempts" task in
  check "benchmark distinguishes partial fix, preservation loss and valid repair"
    (List.map (string "repair_result") attempts=["contract_failed";"out_of_scope_regression";"valid_repair"]
     && List.map (string "contract_result") attempts=["violated";"proved";"proved"]);
  List.iter2 (fun attempt candidate->check "candidate bytes and successful dispatch retained"
      (string "candidate_sha256" attempt=Sha256.string candidate && field "failure" attempt=`Null)) attempts [partial;regression;repaired];
  check "summary does not expose named write witnesses or canonical contract"
    (not (contains stdout "signing-key") && not (contains stdout "config-manager") && not (contains stdout "change_scope"))

let scoped_contract source =
  let value=I.parse source in
  let convert scope =
    let names=match field "names" scope with
      | `Null -> `O ["exclude",strings [];"include_empty",`Bool (List.mem (string "verb" scope) ["list";"watch"])]
      | value -> value in
    let namespace=match field "namespace" scope with
      | `String value -> `O ["include",strings [value]] | value -> value in
    scope |> replace "namespace" namespace |> replace "names" names in
  value |> replace "schema_version" (`Number "4")
    |> replace "clauses" (`A (List.map convert (array "clauses" value)))
    |> replace "change_scope" (`A (List.map convert (array "change_scope" value))) |> I.json

let scoped_cli_checks directory binary source baseline repaired regression =
  let spec=ok (K.Contract_spec.of_string source) in
  let contract=Filename.concat directory "contract.json" and before=Filename.concat directory "baseline.json" in
  write contract source;write before baseline;
  let code,stdout,stderr=run binary ["profile";"kubernetes-rbac";"--contract-version";"4";"--format";"json"] in
  check "scope profile command binds version4" (code=0 && stderr="" &&
    string "id" (I.parse stdout)=profile_v4 && field "contract_schema_version" (I.parse stdout)=`Number "4");
  List.iter (fun (name,candidate,expected) ->
    let after=Filename.concat directory (name ^ ".json") and evidence=Filename.concat directory (name ^ "-evidence") in
    write after candidate;
    let code,stdout,stderr=run binary ["rbac";"compare";before;after;"--contract";contract;
      "--format";"json";"--evidence-dir";evidence] in
    check ("v4 CLI comparison " ^ name) (code=(if expected="proved" then 0 else 3) && stderr="");
    let report=I.parse stdout in assert_report ~version:4 ~spec expected report;
    assert_witness spec ~before:baseline ~after:candidate report;
    assert_evidence evidence spec ~before:baseline ~after:candidate stdout)
    ["valid",repaired,"proved";"regression",regression,"violated"];
  spec

let () =
  if Array.length Sys.argv<>5 then failwith "expected CLI, benchmark binary, workflow directory and approved-contract helper";
  let binary=Sys.argv.(1) and benchmark=Sys.argv.(2) and demo=Sys.argv.(3) and helper=Sys.argv.(4) in
  let directory=temporary_directory () in
  Fun.protect ~finally:(fun ()->cleanup directory) (fun ()->
    let spec,source,baseline,partial,repaired,regression=cli_checks directory binary demo in
    mcp_checks directory binary spec source baseline partial repaired regression;
    gate_checks directory binary helper source baseline partial repaired regression;
    benchmark_checks directory benchmark source baseline partial repaired regression;
    let scoped=Filename.concat directory "scoped" in mkdir scoped;
    let source=scoped_contract source in
    let spec=scoped_cli_checks scoped binary source baseline repaired regression in
    mcp_checks scoped binary spec source baseline partial repaired regression;
    gate_checks scoped binary helper source baseline partial repaired regression;
    benchmark_checks scoped benchmark source baseline partial repaired regression);
  Printf.printf "RBAC write adapters: %d checks passed\n" !checks
