open Soundcheck_core
module K = Soundcheck_kubernetes_rbac
module I = K.Input

let checks = ref 0
let check label yes = incr checks; if not yes then failwith label
let ok = function Ok value -> value | Error reason -> failwith reason
let strings xs = `A (List.map (fun x -> `String x) xs)
let field key = function `O xs -> List.assoc key xs | _ -> failwith ("object expected: "^key)
let string key value = I.str key (field key value)
let array key value = I.arr key (field key value)
let contains value part =
  let rec loop n = n+String.length part<=String.length value &&
    (String.sub value n (String.length part)=part || loop (n+1)) in loop 0
let read path = let c=open_in_bin path in
  Fun.protect ~finally:(fun () -> close_in_noerr c) (fun () -> really_input_string c (in_channel_length c))
let write path source = let c=open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr c) (fun () -> output_string c source)
let mkdir path = Unix.mkdir path 0o700
let rec cleanup path = match (Unix.lstat path).Unix.st_kind with
  | Unix.S_DIR -> Array.iter (fun x -> cleanup (Filename.concat path x)) (Sys.readdir path);Unix.rmdir path
  | _ -> Unix.unlink path
let temporary_directory () =
  let path=Filename.temp_file "soundcheck-rbac-controller-adapters-" "" in
  Unix.unlink path;mkdir path;Unix.realpath path
let run ?env binary args =
  let output=Filename.temp_file "rbac-controller-out-" "" and error=Filename.temp_file "rbac-controller-err-" "" in
  Fun.protect ~finally:(fun () -> List.iter Sys.remove [output;error]) (fun () ->
    let out=Unix.openfile output [Unix.O_WRONLY;Unix.O_TRUNC] 0o600
    and err=Unix.openfile error [Unix.O_WRONLY;Unix.O_TRUNC] 0o600 in
    let argv=Array.of_list (binary::args) in
    let pid=match env with None -> Unix.create_process binary argv Unix.stdin out err
      | Some env -> Unix.create_process_env binary argv env Unix.stdin out err in
    Unix.close out;Unix.close err;
    let _,status=Unix.waitpid [] pid in
    (match status with Unix.WEXITED code -> code | _ -> failwith "child terminated"),read output,read error)

type child={pid:int;input:out_channel;output:Unix.file_descr;error:string;mutable pending:string;mutable reaped:bool}
let with_child directory binary args action =
  let ir,iw=Unix.pipe ~cloexec:true () and or_,ow=Unix.pipe ~cloexec:true () in
  let error=Filename.concat directory "mcp.stderr" in
  let err=Unix.openfile error [Unix.O_WRONLY;Unix.O_CREAT;Unix.O_TRUNC] 0o600 in
  let pid=Unix.create_process binary (Array.of_list (binary::args)) ir ow err in
  List.iter Unix.close [ir;ow;err];
  let child={pid;input=Unix.out_channel_of_descr iw;output=or_;error;pending="";reaped=false} in
  Fun.protect ~finally:(fun () -> close_out_noerr child.input;
    if not child.reaped then begin (try Unix.kill pid Sys.sigkill with Unix.Unix_error (Unix.ESRCH,_,_) -> ());ignore (Unix.waitpid [] pid) end;
    Unix.close child.output) (fun () -> action child)
let send child value=output_string child.input (I.json value);output_char child.input '\n';flush child.input
let receive child =
  let deadline=Unix.gettimeofday ()+.45. in
  let rec loop ()=match String.index_opt child.pending '\n' with
    | Some n -> let line=String.sub child.pending 0 n in
      child.pending<-String.sub child.pending (n+1) (String.length child.pending-n-1);I.parse line
    | None -> let timeout=deadline-.Unix.gettimeofday () in
      if timeout<=0. || (let ready,_,_=Unix.select [child.output] [] [] timeout in ready=[]) then failwith "MCP timed out";
      let bytes=Bytes.create 4096 in let count=Unix.read child.output bytes 0 (Bytes.length bytes) in
      if count=0 then failwith ("MCP exited: "^read child.error);
      child.pending<-child.pending^Bytes.sub_string bytes 0 count;loop () in loop ()
let exchange child id method_ params =
  send child (`O ["jsonrpc",`String "2.0";"id",`Number (string_of_int id);"method",`String method_;"params",params]);
  let response=receive child in
  check "MCP envelope preserved" (field "jsonrpc" response=`String "2.0" && field "id" response=`Number (string_of_int id));response

let profile="kubernetes-rbac-v1.34-controller-apis-v1"
let fixture = if Array.length Sys.argv=5 then Sys.argv.(4) else failwith "expected CLI, gate helper, evaluator and workflow directory"
let source name=read (Filename.concat fixture (name^".json"))
let baseline=source "unsafe" and repaired=source "repaired" and regression=source "operator-regression"
let denied=source "deny-all" and leftover=source "leftover-group" and named=source "named-review"
let replace key value = function `O fields -> `O ((key,value)::List.remove_assoc key fields) | _ -> assert false
let operator_change=`O ["request_kind",`String "resource";"subject",`String "reviewer";
  "operation",`String "get";"api_group",`String "admissionregistration.k8s.io";
  "resource",`String "validatingwebhookconfigurations";"subresource",`String "";
  "namespace",`Null;"names",`Null]
let contract ?(allow_webhooks=false) ?(drop_reviewer=false) ?(permit_reviewer=false) () =
  let value=I.parse (source "contract") in
  let value=if allow_webhooks then replace "clauses" (`A (List.map (fun clause ->
    if string "kind" clause="must_not_grant" then replace "operation" (`String "get") clause else clause)
    (array "clauses" value))) value else value in
  let value=if drop_reviewer then
    let context=field "context" value in
    replace "context" (replace "identities" (`A (List.filter (fun identity ->
      string "username" identity<>"reviewer") (array "identities" context))) context) value else value in
  let value=if permit_reviewer then replace "change_scope"
      (`A (array "change_scope" value @ [operator_change])) value else value in
  I.json value
let spec=ok (K.Contract_spec.of_string (contract ()))
let policy source=K.Lower.policy spec (ok (K.Snapshot.of_string source))
let request_of_json principal action path coordinates : Ir.request =
  {principal=Authenticated principal;action;resource=path;context=[];source=0l;host="";scheme="";sni="";
   object_request=(match coordinates with `Null->None|value->Some {namespace=string "namespace" value;
     resource_kind=string "resource_kind" value;name=string "name" value})}
let witness value=request_of_json (string "principal" value) (string "action" value)
  (string "path" value) (field "object_request" value)
let assert_report expected report =
  check "report schema stays10" (field "schema_version" report=`Number "10");
  check "requested verdict" (string "result" report=expected);
  check "controller API profile retained" (string "profile" (field "assurance" report)=profile);
  let frozen=field "frozen_spec" report in
  check "schema10 controller catalogue retained in frozen identity"
    (field "schema_version" frozen=`Number "10" && string "canonical" frozen=K.Contract_spec.canonical spec)
let assert_witness ?before after report =
  if string "result" report="violated" then begin
    let ce=field "counterexample" report in let req=witness ce in
    let valid=if string "kind" (field "clause" report)="must_preserve" then
        Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec))
          (policy (Option.get before)) (policy after) req
      else Witness.clause (policy after)
        (List.find (fun clause->Contract.name clause=string "name" (field "clause" report))
          (K.Contract_spec.to_contract spec).clauses) req in
    check "typed resource/URL witness validates" valid;
    check "exact source provenance retained" (field "granting_rules" ce=strings (K.Lower.granting_rules (policy after) req));
    let groups=if string "principal" ce="controller" then ["controller-team"] else [] in
    check "exact trusted identity groups retained" (field "identity_groups" ce=strings groups)
  end
let assert_evidence directory ?before after stdout =
  let manifest=I.parse (read (Filename.concat directory "manifest.json")) in
  let artifact value=let source=read (Filename.concat directory (string "path" value)) in
    check "evidence hashes exact artifact" (Sha256.string source=string "sha256" value);source in
  check "evidence envelope unchanged" (field "schema_version" manifest=`Number (if before=None then "2" else "3"));
  check "evidence exact report" (artifact (field "report" manifest)=stdout);
  check "evidence preserves frozen controller API contract" (artifact (field "contract" manifest)=K.Contract_spec.canonical spec^"\n");
  let selected=field "assurance_profile" manifest in
  check "evidence profile exact" (string "id" selected=profile &&
    artifact (field "artifact" selected)=K.Assurance.profile_json ~version:10 ()^"\n");
  let bind source value=check "input digest exact" (string "sha256" value=Sha256.string source) in
  (match before with None->bind after (field "config" manifest)
   |Some source->bind source (field "before" (field "inputs" manifest));bind after (field "after" (field "inputs" manifest));
     assert_report "proved" (I.parse (artifact (field "candidate_report" manifest))));
  let clauses=K.Contract_spec.to_contract spec in let plan=Contract_verify.plan (policy after) clauses in
  let entries=array "obligations" manifest in
  check "complete obligation plan retained" (List.length entries=List.length plan+(if before=None then 0 else 1));
  List.iter (fun entry->
    let id=string "id" entry in
    let obligation=List.find_opt (fun (o:Contract_verify.obligation)->o.id=id) plan in
    let expected=match obligation with Some o->o.smtlib|None->
      Smt_encode.decision_equivalence_query ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) (policy (Option.get before)) (policy after) in
    check "evidence keeps exact frozen-domain query" (artifact (field "query" entry)=expected);
    if field "solver_result" entry=`String "sat" then begin
      let model=field "model" entry in
      let req=request_of_json (string "principal_name" model) (string "method" model)
        (string "path" model) (field "object_request" model) in
      let valid=match obligation with
        |None->Witness.decision_difference ~when_:(Ir.Not (K.Contract_spec.approved_changes spec)) (policy (Option.get before)) (policy after) req
        |Some o->let related=List.map (fun name->List.find (fun c->Contract.name c=name) clauses.clauses) o.clauses in
          if o.phase=Contract_verify.Clause then Witness.clause (policy after) (List.hd related) req
          else Witness.condition ~domain:(policy after).request_domain (Ir.And (List.map Contract.request_class related)) req in
      check "evidence resource/URL SAT model satisfies saved obligation" valid
    end) entries

let mcp_checks directory binary =
  let cp=Filename.concat directory "mcp-contract.json" and bp=Filename.concat directory "mcp-baseline.json" in
  write cp (contract ());write bp baseline;
  with_child directory binary ["mcp";"--connector";"kubernetes-rbac";"--contract";cp;"--baseline";bp] (fun child ->
    ignore (field "result" (exchange child 1 "initialize" (`O ["protocolVersion",`String "2024-11-05";
      "capabilities",`O [];"clientInfo",`O ["name",`String "controller-acceptance";"version",`String "1"]])));
    send child (`O ["jsonrpc",`String "2.0";"method",`String "notifications/initialized"]);
    let tools=array "tools" (field "result" (exchange child 2 "tools/list" (`O []))) in
    check "MCP exposes candidate-only tools" (List.map (string "name") tools=["verify";"compare"]);
    List.iter (fun tool -> let schema=field "inputSchema" tool in
      check "MCP has no caller or domain override"
        (field "required" schema=strings ["config"] && field "additionalProperties" schema=`Bool false)) tools;
    let call id operation candidate wanted =
      let result=field "result" (exchange child id "tools/call" (`O ["name",`String operation;
        "arguments",`O ["config",`String candidate]])) in
      let report=field "structuredContent" result in
      check "MCP text and structured report agree" (I.parse (string "text" (List.hd (array "content" result)))=report);
      assert_report wanted report;
      assert_witness ?before:(if operation="compare" then Some baseline else None) candidate report in
    write cp (contract ~allow_webhooks:true ());write bp regression;
    call 3 "verify" baseline "violated";
    call 4 "compare" regression "violated";
    write cp (contract ~drop_reviewer:true ());
    call 5 "compare" regression "violated";
    write cp (contract ~permit_reviewer:true ());
    call 6 "compare" regression "violated";
    Sys.remove cp;Sys.remove bp;
    call 7 "compare" repaired "proved";
    call 8 "verify" named "violated";
    let response=exchange child 9 "tools/call" (`O ["name",`String "verify";
      "arguments",`O ["config",`String baseline;"username",`String "reviewer";
        "contract_version",`Number "9";"request_kind",`String "resource"]]) in
    check "MCP rejects identity and profile replacement" (field "code" (field "error" response)=`Number "-32602");
    close_out child.input;
    let ready,_,_=Unix.select [child.output] [] [] 10. in
    check "MCP EOF" (child.pending="" && ready<>[] && Unix.read child.output (Bytes.create 1) 0 1=0);
    let _,status=Unix.waitpid [] child.pid in child.reaped<-true;
    check "MCP clean exit" (status=Unix.WEXITED 0 && read child.error=""))

let gate_checks directory binary helper =
  let workspace=Filename.concat directory "workspace" and action=Filename.concat directory "action"
  and temp=Filename.concat directory "runner-temp" in
  List.iter mkdir [workspace;action;temp];
  List.iter (fun p -> mkdir (Filename.concat action p)) ["scripts";"_build";"_build/default";"_build/default/cli"];
  let script=Filename.concat action "scripts/verify-approved-contract.sh" in write script (read helper);
  Unix.symlink (Unix.realpath binary) (Filename.concat action "_build/default/cli/main.exe");
  let git args=let code,out,err=run "git" (["-c";"core.hooksPath=/dev/null";"-C";workspace]@args) in
    check ("fixture git: "^err) (code=0);String.trim out in
  ignore (git ["init";"--quiet"]);
  let cp=Filename.concat workspace "contract.json" and sp=Filename.concat workspace "snapshot.json" in
  write cp (contract ());write sp baseline;
  ignore (git ["add";"--";"contract.json";"snapshot.json"]);
  ignore (git ["-c";"user.name=Soundcheck acceptance";"-c";"user.email=acceptance@example.invalid";
    "-c";"commit.gpgSign=false";"commit";"--quiet";"-m";"Approved controller requirements"]);
  let approved=git ["rev-parse";"HEAD"] and event=Filename.concat directory "event.json" in
  write event (I.json (`O ["repository",`O ["full_name",`String "example/soundcheck"];
    "pull_request",`O ["base",`O ["sha",`String approved;"ref",`String "main";
      "repo",`O ["full_name",`String "example/soundcheck"]]]]));
  write cp (contract ~allow_webhooks:true ());
  let code,out,err=run binary ["rbac";"verify";sp;"--contract";cp;"--format";"json"] in
  check "candidate forbidden-operation weakening would pass" (code=0 && err="" && string "result" (I.parse out)="proved");
  let execute ?(candidate_contract=contract ~allow_webhooks:true ()) mode candidate expected fragments =
    write sp candidate;write cp candidate_contract;
    let settings=["GITHUB_WORKSPACE",workspace;"GITHUB_EVENT_PATH",event;"GITHUB_EVENT_NAME","pull_request";
      "GITHUB_REPOSITORY","example/soundcheck";"GITHUB_BASE_REF","main";"RUNNER_TEMP",temp;
      "SOUNDCHECK_CONFIG_INPUT","snapshot.json";"SOUNDCHECK_CONTRACT_INPUT","contract.json";
      "SOUNDCHECK_CONNECTOR_INPUT","kubernetes-rbac";"SOUNDCHECK_MODE_INPUT",mode] in
    let inherited=Array.to_list (Unix.environment ()) |> List.filter (fun value ->
      not (List.exists (fun (key,_) -> String.starts_with ~prefix:(key^"=") value) settings)) in
    let env=Array.of_list (List.map (fun (key,value) -> key^"="^value) settings@inherited) in
    let code,out,err=run ~env "bash" [script] in
    check ("schema10 trusted gate: "^err) (code=expected && err="");
    List.iter (fun part -> check ("gate retains "^part) (contains out part))
      (["Approved contract: "^approved^":contract.json";profile;"\"schema_version\":10"]@fragments);
    check "gate leaves candidate and cleans temporary sources" (Sys.readdir temp=[||] && read cp=candidate_contract) in
  execute "verify" baseline 3 ["no-validating-webhook-patch";"validatingwebhookconfigurations"];
  execute "verify" named 3 ["submit-access-review";"subjectaccessreviews"];
  execute "repair" regression 3 ["must_preserve";"reviewer"];
  execute "repair" repaired 0 ["rbac-repair-preservation proved"];
  let original=Filename.concat directory "approved-baseline.json" in write original baseline;
  List.iter (fun weakened ->
    write cp weakened;write sp regression;
    let code,out,err=run binary ["rbac";"compare";original;sp;"--contract";cp;"--format";"json"] in
    check "candidate identity/scope tampering could hide unrelated regression"
      (code=0 && err="" && string "result" (I.parse out)="proved");
    execute ~candidate_contract:weakened "repair" regression 3 ["must_preserve";"reviewer"])
    [contract ~drop_reviewer:true ();contract ~permit_reviewer:true ()]

let evaluator_checks directory evaluator =
  let root=Filename.concat directory "submitted" in mkdir root;let local name=Filename.concat root name in
  write (local "baseline.json") baseline;write (local "contract.json") (contract ());
  write (local "suite.yaml") "format_version: 1\ncases:\n  - id: controller\n    config: baseline.json\n    contract: contract.json\n    provenance: synthetic\n";
  let cases=["valid",repaired,"valid_repair";"unchanged",baseline,"contract_failed";
    "deny-all",denied,"contract_failed";"leftover-group",leftover,"contract_failed";
    "named-review",named,"contract_failed";"operator-regression",regression,"out_of_scope_regression"] in
  List.iter (fun (name,source,_) -> write (local (name^".json")) source) cases;
  write (local "submissions.yaml") ("format_version: 1\nattempts:\n"^
    String.concat "" (List.map (fun (name,_,_) -> "  - {task: controller, id: "^name^", config: "^name^".json}\n") cases));
  let code,out,err=run evaluator [local "suite.yaml";local "submissions.yaml"] in
  check "submitted evaluator accepts schema10 task" (code=0 && err="");
  let summary=I.parse out in
  check "submitted schema/profile retained" (field "experimental_format_version" summary=`Number "2" && string "profile" summary=profile);
  let task=List.hd (array "tasks" summary) in
  check "submitted frozen digest retained" (string "frozen_contract_sha256" task=Sha256.string (K.Contract_spec.canonical spec));
  let attempts=array "attempts" task in
  check "all attempts accounted" (List.length attempts=List.length cases);
  List.iter (fun (name,_,wanted) -> let row=List.find (fun row -> string "id" row=name) attempts in
    check ("submitted result "^name) (string "repair_result" row=wanted)) cases;
  write (local "submissions.yaml") "format_version: 1\nattempts:\n  - {task: controller, id: bad, config: valid.json, contract_version: 9}\n";
  let code,out,err=run evaluator [local "suite.yaml";local "submissions.yaml"] in
  check "submission cannot choose smaller schema" (code=1 && err="" && string "failure" (List.hd (array "tasks" (I.parse out)))="submissions_invalid")

let () =
  let binary=Sys.argv.(1) and helper=Sys.argv.(2) and evaluator=Sys.argv.(3) in
  let directory=temporary_directory () in
  Fun.protect ~finally:(fun () -> cleanup directory) (fun () ->
    let code,out,err=run binary ["profile";"kubernetes-rbac";"--contract-version";"10";"--format";"json"] in
    check "CLI selects schema10" (code=0 && err="");
    let selected=I.parse out in
    check "CLI profile versions" (string "id" selected=profile && field "schema_version" selected=`Number "6" && field "contract_schema_version" selected=`Number "10");
    let cp=Filename.concat directory "contract.json" and bp=Filename.concat directory "baseline.json" in
    write cp (contract ());write bp baseline;
    let code,out,err=run binary ["rbac";"check-contract";cp] in
    check "contract review distinguishes initial caller from body result"
      (code=0 && err="" && contains out "Contract schema: 10" && contains out "structure only" &&
       contains out "Review APIs allow only initial create" && contains out "returned decisions are not the caller");
    let invoke ?before ?(evidence=false) tag candidate wanted =
      let path=Filename.concat directory (tag^".json") and evidence_path=Filename.concat directory (tag^"-evidence") in
      write path candidate;
      let operation=match before with None -> ["verify";path] | Some _ -> ["compare";bp;path] in
      let code,out,err=run binary ("rbac"::operation@["--contract";cp;"--format";"json"]@
        if evidence then ["--evidence-dir";evidence_path] else []) in
      check ("CLI "^tag^": "^err) (code=(if wanted="proved" then 0 else 3) && err="");
      let report=I.parse out in assert_report wanted report;assert_witness ?before candidate report;
      if evidence then assert_evidence evidence_path ?before candidate out;report in
    let r=invoke ~evidence:true "unsafe" baseline "violated" in
    check "webhook witness retains exact group and empty namespace"
      (string "resource_kind" (field "object_request" (field "counterexample" r))="validatingwebhookconfigurations.admissionregistration.k8s.io" &&
       string "namespace" (field "object_request" (field "counterexample" r))="");
    let r=invoke ~evidence:true "named-review" named "violated" in
    check "review witness is caller create with empty name"
      (string "action" (field "counterexample" r)="create" && string "principal" (field "counterexample" r)="controller" &&
       string "name" (field "object_request" (field "counterexample" r))="");
    ignore (invoke "leftover-group" leftover "violated");
    ignore (invoke "deny-all" denied "violated");
    ignore (invoke ~before:baseline ~evidence:true "valid" repaired "proved");
    let r=invoke ~before:baseline ~evidence:true "operator-regression" regression "violated" in
    check "unmentioned reviewer preserved" (string "principal" (field "counterexample" r)="reviewer");
    mcp_checks directory binary;gate_checks directory binary helper;evaluator_checks directory evaluator);
  Printf.printf "controller API adapters: %d checks passed\n" !checks
